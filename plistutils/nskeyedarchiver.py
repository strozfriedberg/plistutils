import logging
from uuid import UUID


from biplist import Data, Uid


from plistutils.utils import parse_mac_absolute_time


logger = logging.getLogger(__name__)


class NSKeyedArchiveException(Exception):
    pass


class NSKeyedArchiveParser(object):
    # https://developer.apple.com/documentation/foundation/nskeyedarchiver
    KNOWN_VERSIONS = [100000]

    def __init__(self, fullpath):
        self.fullpath = fullpath

    @staticmethod
    def is_known_nskeyedarchive(plist_data, fullpath):
        if plist_data:
            archiver = plist_data.get('$archiver')
            version = plist_data.get('$version')
            # NR -> iOS NanoRegistry KeyedArchiver (inherits from NSKeyedArchiver)
            if archiver in ['NRKeyedArchiver', 'NSKeyedArchiver']:
                if version in NSKeyedArchiveParser.KNOWN_VERSIONS:
                    return True
                else:
                    logger.error("Unknown NSKeyedArchiver version '{}' in file {}, please report.", version, fullpath)
        return False

    def parse_archive(self, plist_data):
        """
        :param plist_data: pre-parsed plist data
        :return: parsed dict
        """
        ret = {}
        objects_list = plist_data.get('$objects')
        if objects_list:
            for name, val in plist_data.get('$top', {}).items():
                if isinstance(val, Uid):
                    top = objects_list[val.integer]
                    try:
                        ret[name] = self.process_obj(top, objects_list)
                    except RecursionError:
                        # failsafe
                        logger.error(
                            "Could not parse NSKeyedArchive '{}' in top key '{}' due to infinite recursion",
                            self.fullpath, name)
                else:
                    ret[name] = val
        return ret

    def process_obj(self, obj, objects_list, parents=None):
        if parents is None:
            parents = set()
        obj_id = id(obj)
        if obj_id in parents:
            raise NSKeyedArchiveException("Infinite loop detected while parsing NSKeyedArchive data in '{}'".format(self.fullpath))
        else:
            parents.add(obj_id)

        ret = obj
        if isinstance(obj, dict):
            ret = self.convert_dict(obj, objects_list, parents)
        elif isinstance(obj, list):
            ret = [self.process_obj(x, objects_list, parents) for x in obj]
        elif isinstance(obj, Uid):
            ret = self.process_obj(objects_list[obj.integer], objects_list, parents)
        elif isinstance(obj, (bool, bytes, int, float)) or obj is None:
            ret = obj
        elif isinstance(obj, str):
            ret = self.convert_string(obj)
        elif isinstance(obj, Data):
            ret = bytes(obj)
        else:
            logger.warning("Unexpected data type '{}' in '{}', please report.", type(obj).__name__, self.fullpath)

        parents.remove(obj_id)
        return ret

    def _process_ns_dictionary(self, _class_name, d, objects_list, parents):
        if 'NS.keys' in d and 'NS.objects' in d:
            assembled_dict = {}
            for idx, k in enumerate(d['NS.keys']):
                assembled_dict[self.process_obj(k, objects_list, parents)] = self.process_obj(d['NS.objects'][idx],
                                                                                              objects_list, parents)
            return assembled_dict
        return d

    def _process_ns_url(self, _class_name, d, objects_list, parents):
        base = self.process_obj(d.get('NS.base', ''), objects_list, parents)
        relative = self.process_obj(d.get('NS.relative', ''), objects_list, parents)
        return '/'.join([x for x in [base, relative] if x])

    def _process_ns_uuid(self, _class_name, d, _objects_list, _parents):
        uuid_bytes = d.get('NS.uuidbytes', '')
        if len(uuid_bytes) == 16:
            return str(UUID(bytes=uuid_bytes))
        return uuid_bytes

    def _process_ns_sequence(self, _class_name, d, objects_list, parents):
        array_members = d.get('NS.objects')
        return [self.process_obj(member, objects_list, parents) for member in array_members]

    def _process_ns_data(self, _class_name, d, _objects_list, _parents):
        data = d.get('NS.data', None)
        if isinstance(data, dict) and self.is_known_nskeyedarchive(data, ''):
            return self.parse_archive(data)
        return data

    def _process_ns_null(self, _class_name, d, _objects_list, _parents):
        return None

    def _process_ns_string(self, _class_name, d, _objects_list, _parents):
        return d.get('NS.string', None)

    def _process_ns_attributed_string(self, class_name, d, objects_list, parents):
        # Sample:
        # {'NSAttributeInfo': Uid(74), '$class': Uid(51), 'NSString': Uid(68), 'NSAttributes': Uid(69)}
        # TODO if demand - process NSAttributes, NSAttributeInfo (font, color, style, etc)
        return self.process_obj(d.get('NSString'), objects_list, parents)

    def _process_ns_range(self, _class_name, d, objects_list, parents):
        # length: The number of items in the range (can be 0). LONG_MAX is the maximum value you should use for length.
        # location: The start index (0 is the first). LONG_MAX is the maximum value you should use for location.
        #
        return {
            'length': self.process_obj(d.get('NS.rangeval.length'), objects_list, parents),
            'location': self.process_obj(d.get('NS.rangeval.location'), objects_list, parents)
        }

    def _process_ns_value(self, class_name, d, objects_list, parents):
        # An NSValue object can hold any of the scalar types such as int, float, and char,
        # as well as pointers, structures, and object id references.
        #
        # NS.special: 1 : NSPoint, 2 : NSSize, 3 : NSRect, 4 : NSRange, 12 : NSEdgeInsets
        #
        # NSConcreteValue varies based on type, which is typically provided by the @encode compiler directive
        # https://developer.apple.com/library/content/documentation/Cocoa/Conceptual/ObjCRuntimeGuide/Articles/ocrtTypeEncodings.html#//apple_ref/doc/uid/TP40008048-CH100
        # These types are voluminous, and we need samples to support them.

        # https://github.com/apple/swift-corelibs-foundation/blob/master/Foundation/NSSpecialValue.swift
        ns_value_special_types = {
            # 1: 'NSPoint'
            # 2: 'NSSize'
            # 3: 'NSRect' https://github.com/apple/swift-corelibs-foundation/blob/master/TestFoundation/Resources/NSKeyedUnarchiver-RectTest.plist
            4: NSKeyedArchiveParser._process_ns_range,
            # 12: 'NSEdgeInsets' https://github.com/apple/swift-corelibs-foundation/blob/master/TestFoundation/Resources/NSKeyedUnarchiver-EdgeInsetsTest.plist
        }
        special_type = d.get('NS.special')
        if special_type:  # NSSpecialValue
            if special_type in ns_value_special_types:
                return ns_value_special_types[special_type](self, class_name, d, objects_list, parents)
            else:
                logger.error("Unsupported NSValue special type {} in NSKeyedArchiver data, please report.", special_type)
        else:  # NSConcreteValue
            logger.error("Unsupported NSConcreteValue type in NSKeyedArchiver data, please report.", special_type)
        return None

    def _process_ns_list_item(self, _class_name, d, objects_list, parents):
        # TODO 'properties' is an NSDictionary
        return {
            'url': self.process_obj(d.get('URL', None), objects_list, parents),
            'bookmark': self.process_obj(d.get('bookmark', None), objects_list, parents),
            'name': self.process_obj(d.get('name', None), objects_list, parents),
            'order': self.process_obj(d.get('order', None), objects_list, parents),
            'uuid': self.process_obj(d.get('uniqueIdentifier', None), objects_list, parents)
        }

    def _process_ns_date(self, _class_name, d, _objects_list, _parents):
        return parse_mac_absolute_time(d.get('NS.time'))

    def _process_default(self, class_name, d, _objects_list, _parents):
        logger.warning(
            "Unknown NSKeyedArchiver class name {} with data ({}) in '{}', please report.", class_name, d, self.fullpath)

    @classmethod
    def get_processors(cls):
        return {
            'NSArray': cls._process_ns_sequence,
            'NSAttributedString': cls._process_ns_attributed_string,
            # 'NSCache'
            # 'NSColor' simple sample: {'NSColorSpace': 3, 'NSWhite': b'0\x00'},
            # 'NSCompoundPredicate'
            'NSData': cls._process_ns_data,
            'NSDate': cls._process_ns_date,
            'NSDictionary': cls._process_ns_dictionary,
            # 'NSError'
            # 'NSFont' sample: {'NSName': 'Helvetica', 'NSSize': 12.0, 'NSfFlags': 16},
            # 'NSGeometry'
            # 'NSLocale'
            'NSMutableArray': cls._process_ns_sequence,
            'NSMutableAttributedString': cls._process_ns_attributed_string,
            'NSMutableData': cls._process_ns_data,
            'NSMutableDictionary': cls._process_ns_dictionary,
            'NSMutableSet': cls._process_ns_sequence,
            'NSMutableString': cls._process_ns_string,
            # 'NSNotification' https://github.com/apple/swift-corelibs-foundation/blob/master/TestFoundation/Resources/NSKeyedUnarchiver-NotificationTest.plist
            'NSNull': cls._process_ns_null,
            # 'NSNumber'
            # 'NSOrderedSet' https://github.com/apple/swift-corelibs-foundation/blob/master/TestFoundation/Resources/NSKeyedUnarchiver-OrderedSetTest.plist
            # 'NSParagraphStyle' sample: {'NSAlignment': 4, 'NSTabStops': '$null'},
            # 'NSPredicate'
            # 'NSProgressFraction'
            # 'NSRange'
            # 'NSRegularExpression'
            'NSSet': cls._process_ns_sequence,
            'NSString': cls._process_ns_string,
            'NSURL': cls._process_ns_url,
            'NSUUID': cls._process_ns_uuid,
            'NSValue': cls._process_ns_value,
            'SFLListItem': cls._process_ns_list_item
        }

    def convert_dict(self, d, objects_list, parents):
        if '$class' in d:
            try:
                class_name = self.process_obj(d['$class'], objects_list, parents).get('$classname')
                return self.get_processors().get(class_name, NSKeyedArchiveParser._process_default)(self, class_name, d, objects_list, parents)
            except (AttributeError, KeyError, ValueError):
                pass
        return d

    def convert_string(self, obj):
        if obj == '$null':
            return None
        return obj
