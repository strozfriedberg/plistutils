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
        objects_list = plist_data.get('$objects')
        root_id = plist_data.get('$top', {}).get('root')
        if objects_list and root_id:
            root = objects_list[root_id.integer]
            try:
                return self.process_obj(root, objects_list)
            except RecursionError:
                # failsafe
                logger.error("Could not parse NSKeyedArchive '{}' due to infinite recursion", self.fullpath)
        return None

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
        elif isinstance(obj, (bool, int, float)) or obj is None:
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
        else:
            return d

    def _process_ns_url(self, _class_name, d, objects_list, parents):
        base = self.process_obj(d.get('NS.base', ''), objects_list, parents)
        relative = self.process_obj(d.get('NS.relative', ''), objects_list, parents)
        return '/'.join([x for x in [base, relative] if x])

    def _process_ns_uuid(self, _class_name, d, _objects_list, _parents):
        uuid_bytes = d.get('NS.uuidbytes', '')
        if len(uuid_bytes) == 16:
            return str(UUID(bytes=uuid_bytes))
        else:
            return uuid_bytes

    def _process_ns_sequence(self, _class_name, d, objects_list, parents):
        array_members = d.get('NS.objects')
        return [self.process_obj(member, objects_list, parents) for member in array_members]

    def _process_ns_data(self, _class_name, d, _objects_list, _parents):
        return d.get('NS.data', None)

    def _process_ns_string(self, _class_name, d, _objects_list, _parents):
        return d.get('NS.string', None)

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
            'NSDictionary': cls._process_ns_dictionary,
            'NSMutableDictionary': cls._process_ns_dictionary,
            'NSURL': cls._process_ns_url,
            'NSUUID': cls._process_ns_uuid,
            'NSArray': cls._process_ns_sequence,
            'NSMutableArray': cls._process_ns_sequence,
            'NSMutableSet': cls._process_ns_sequence,
            'NSSet': cls._process_ns_sequence,
            'NSData': cls._process_ns_data,
            'NSMutableData': cls._process_ns_data,
            'NSMutableString': cls._process_ns_string,
            'NSString': cls._process_ns_string,
            'SFLListItem': cls._process_ns_list_item,
            'NSDate': cls._process_ns_date,
        }

    def convert_dict(self, d, objects_list, parents):
        if '$class' in d:
            try:
                class_name = self.process_obj(d['$class'], objects_list, parents).get('$classname')
                return self.get_processors().get(class_name, self._process_default)(self, class_name, d, objects_list, parents)
            except (AttributeError, KeyError, ValueError):
                pass
        return d

    def convert_string(self, obj):
        if obj == '$null':
            return None
        else:
            return obj
