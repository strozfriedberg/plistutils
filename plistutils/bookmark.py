import logging
import struct
from urllib.parse import urljoin


from plistutils.utils import guid_str_from_bytes, interpret_flags, parse_mac_absolute_time


logger = logging.getLogger(__name__)


class BookmarkParser(object):
    """
    References
    http://michaellynn.github.io/2015/10/24/apples-bookmarkdata-exposed/
    """
    HEADER = struct.Struct('< 4s 3I')
    TOC_HEADER = struct.Struct('< I 2H 3I')
    TOC_DATA_HEADER = struct.Struct('< 3I')
    RECORD_HEADER = struct.Struct('< 2I')

    EXPECTED_TYPE_MASK = 0xffffff00
    STRING_TYPE = 0x100
    BYTES_TYPE = 0x200
    NUMBER_TYPE = 0x300
    DATE_TYPE = 0x400
    BOOL_TYPE = 0x500
    ARRAY_TYPE = 0x600
    DICT_TYPE = 0x700  # haven't seen one of these in the wild, yet
    UUID_TYPE = 0x800
    URL_TYPE = 0x900
    NULL_TYPE = 0xA00

    # field_id: ([expected data types], field_name)
    # fields with field_name of None will not be parsed
    FIELDS = {
        0x1004: ([ARRAY_TYPE], 'path'),  # array of path components
        0x1005: ([ARRAY_TYPE], 'inode_path'),  # array of file IDs
        0x1010: ([BYTES_TYPE], 'resource_props'),  # byte array of props - three 8-byte ints: [0] target flags, [1] flag validity, [2] unknown (always 0)
        0x1020: ([STRING_TYPE, URL_TYPE], 'target_filename'),  # string
        0x1030: ([NUMBER_TYPE], 'target_inode'),  # int
        0x1040: ([DATE_TYPE], 'creation_date'),  # date
        0x2000: ([ARRAY_TYPE], 'volume_info_depths'),  # array of depths
        0x2002: ([STRING_TYPE, URL_TYPE], 'volume_path'),  # string
        0x2005: ([STRING_TYPE, URL_TYPE], 'volume_url'),  # CFURL
        0x2010: ([STRING_TYPE], 'volume_name'),  # string
        0x2011: ([STRING_TYPE, UUID_TYPE], 'volume_uuid'),  # string
        0x2012: ([NUMBER_TYPE], 'volume_size'),  # int
        0x2013: ([DATE_TYPE], 'volume_creation_date'),  # date
        0x2020: ([BYTES_TYPE], 'volume_props'),  # byte array of props - three 8-byte ints: [0] target flags, [1] flag validity, [2] unknown (always 0)
        0x2030: ([BOOL_TYPE], 'volume_was_boot'),  # bool (existence indicates True)
        0x2040: ([NUMBER_TYPE], 'disk_image_depth'),  # 32-bit int
        0x2050: ([STRING_TYPE, URL_TYPE], 'volume_mount_point'),  # CFURL
        0xc001: ([NUMBER_TYPE], None),  # 'volume_home_dir_relative_path_component_count' - index of parent in path components
        0xc011: ([STRING_TYPE], 'user_name'),  # string
        0xc012: ([NUMBER_TYPE], 'user_uid'),  # int
        0xd001: ([BOOL_TYPE], None),  # 'wasFileIDFormat' bool
        0xd010: ([NUMBER_TYPE], None),  # 'creation_options' flags for CFURLCreateBookmarkData
        0xe003: ([ARRAY_TYPE], None),   # 'url_length' - array
        0xf017: ([STRING_TYPE], 'display_name'),
        0xf021: ([BYTES_TYPE], None),  # 'effective_flattened_icon_ref' - byte array - Img file?
        0xf030: ([NUMBER_TYPE], 'bookmark_creation_time'),  # 'bookmark_creation_time' exp 64-bit float seconds since 1/1/2001 (e.g. b'68CB95EB545DB841')
        0xf080: ([BYTES_TYPE], 'sandbox_rw_extension'),  # semi-colon separated values string (from byte-array)
        0xf081: ([BYTES_TYPE], 'sandbox_ro_extension'),  # semi-colon separated values string (from byte-array)
        0xfe00: ([BYTES_TYPE], None),  # 'alias_data'
        0x800001ac: ([NUMBER_TYPE], None),  # 'nsurl_document_identifier_key' https://developer.apple.com/reference/foundation/nsurldocumentidentifierkey
        0x800001d8: ([NUMBER_TYPE], None),  # 'nsurl_document_identifier_key' https://developer.apple.com/reference/foundation/nsurldocumentidentifierkey
    }

    # https://opensource.apple.com/source/CF/CF-1153.18/CFURLPriv.h.auto.html
    RESOURCE_PROPERTY_FLAGS = [
        (0x00000001, 'IsRegularFile'),
        (0x00000002, 'IsDirectory'),
        (0x00000004, 'IsSymbolicLink'),
        (0x00000008, 'IsVolume'),
        (0x00000010, 'IsPackage'),
        (0x00000020, 'IsSystemImmutable'),
        (0x00000040, 'IsUserImmutable'),
        (0x00000080, 'IsHidden'),
        (0x00000100, 'HasHiddenExtension'),
        (0x00000200, 'IsApplication'),
        (0x00000400, 'IsCompressed'),
        (0x00000800, 'CanSetHiddenExtension'),
        (0x00001000, 'IsReadable'),
        (0x00002000, 'IsWriteable'),
        (0x00004000, 'IsExecutable'),  # execute files or search directories
        (0x00008000, 'IsAliasFile'),
        (0x00010000, 'IsMountTrigger'),
    ]

    # https://opensource.apple.com/source/CF/CF-1153.18/CFURLPriv.h.auto.html
    VOLUME_PROPERTY_FLAGS = [
        (0x1, 'IsLocal'),         # Local device (vs. network device)
        (0x2, 'IsAutomount'),     # Mounted by the automounter
        (0x4, 'DontBrowse'),      # Hidden from user browsing
        (0x8, 'IsReadOnly'),      # Mounted read-only
        (0x10, 'IsQuarantined'),  # Mounted with quarantine bit
        (0x20, 'IsEjectable'),
        (0x40, 'IsRemovable'),
        (0x80, 'IsInternal'),
        (0x100, 'IsExternal'),
        (0x200, 'IsDiskImage'),
        (0x400, 'IsFileVault'),
        (0x800, 'IsLocaliDiskMirror'),
        (0x1000, 'IsiPod'),
        (0x2000, 'IsiDisk'),
        (0x4000, 'IsCD'),
        (0x8000, 'IsDVD'),
        (0x10000, 'IsDeviceFileSystem'),
        (0x100000000, 'SupportsPersistentIDs'),
        (0x200000000, 'SupportsSearchFS'),
        (0x400000000, 'SupportsExchange'),
        (0x1000000000, 'SupportsSymbolicLinks'),
        (0x2000000000, 'SupportsDenyModes'),
        (0x4000000000, 'SupportsCopyFile'),
        (0x8000000000, 'SupportsReadDirAttr'),
        (0x10000000000, 'SupportsJournaling'),
        (0x20000000000, 'SupportsRename'),
        (0x40000000000, 'SupportsFastStatFS'),
        (0x80000000000, 'SupportsCaseSensitiveNames'),
        (0x100000000000, 'SupportsCasePreservedNames'),
        (0x200000000000, 'SupportsFLock'),
        (0x400000000000, 'HasNoRootDirectoryTimes'),
        (0x800000000000, 'SupportsExtendedSecurity'),
        (0x1000000000000, 'Supports2TBFileSize'),
        (0x2000000000000, 'SupportsHardLinks'),
        (0x4000000000000, 'SupportsMandatoryByteRangeLocks'),
        (0x8000000000000, 'SupportsPathFromID'),
        (0x20000000000000, 'IsJournaling'),
        (0x40000000000000, 'SupportsSparseFiles'),
        (0x80000000000000, 'SupportsZeroRuns'),
        (0x100000000000000, 'SupportsVolumeSizes'),
        (0x200000000000000, 'SupportsRemoteEvents'),
        (0x400000000000000, 'SupportsHiddenFiles'),
        (0x800000000000000, 'SupportsDecmpFSCompression'),
        (0x1000000000000000, 'Has64BitObjectIDs')
    ]

    @classmethod
    def get_toc(cls, buf, data_offset):
        toc_offset, = struct.unpack_from('<I', buf, data_offset)
        table_of_contents = []

        toc_count = 0
        while toc_offset > 0:
            toc_info, toc_offset = cls.parse_toc(buf, data_offset + toc_offset, data_offset, toc_count)
            table_of_contents.extend(toc_info)
            toc_count += 1
        return table_of_contents, toc_count

    @classmethod
    def parse_bookmark(cls, fullpath, idx, item_name, buf):
        if buf is None or len(buf) < cls.HEADER.size:
            return []
        magic, _size, _version, data_offset = cls.HEADER.unpack_from(buf)
        if magic != b'book' and magic != b'alis':
            return []
        table_of_contents, toc_count = cls.get_toc(buf, data_offset)

        all_data = [{'bookmark_index': idx} for _i in range(toc_count)]
        for toc_entry in table_of_contents:
            cur_toc_entry = all_data[toc_entry['index']]
            if 'toc_depth' not in cur_toc_entry:
                cur_toc_entry['toc_depth'] = toc_entry['depth']
            record_offset = toc_entry['record_offset']
            record_length, record_data_type = cls.RECORD_HEADER.unpack_from(buf, record_offset)
            cls.process_field(fullpath, buf, item_name, data_offset, cur_toc_entry,
                              toc_entry['record_type'], record_offset, record_length, record_data_type)
        return all_data

    @classmethod
    def process_field(cls, fullpath, buf, item_name, data_offset, cur_toc_entry,
                      rec_type, record_offset, record_length, record_data_type):
        if rec_type in cls.FIELDS:
            expected_data_types, field_name = cls.FIELDS[rec_type]
            if field_name is None:  # we know what it is, we just don't want to process it
                return
            general_type = record_data_type & cls.EXPECTED_TYPE_MASK
            if general_type not in expected_data_types + [cls.NULL_TYPE]:  # anything could be NULL
                logger.error(
                    "Unexpected data type {:#x} for record type {:#x} ({}) in file '{}', please report.", record_data_type, rec_type, field_name, fullpath)
                return
            record_data_offset = record_offset + cls.RECORD_HEADER.size
            data = buf[record_data_offset: record_data_offset + record_length]
            field_dict = cls.decode_value(field_name, buf, data_offset, rec_type, record_length, record_data_type, data)
            cls.update_record(cur_toc_entry, field_dict)
        else:
            logger.warning(
                "Unknown bookmark record/data type ({}/{}) in item {} from file {}, please report.", rec_type, record_data_type, item_name, fullpath)

    @staticmethod
    def update_record(record, field_dict):
        for k, v in field_dict.items():
            if k in record:
                logger.error(
                    "Could not update record due to duplicate key in level. Initial value: {}/{}. Attempted update: {}/{}.", k, record[k], k, field_dict[k])
            else:
                record[k] = v

    @classmethod
    def _parse_record_data_601(cls, data, record_length, buf, data_offset):
        pointer_ct = record_length // 4
        pointers = struct.unpack('<{}I'.format(pointer_ct), data)
        parsed_values = []
        for p in pointers:
            component_offset = p + data_offset
            component_length, component_data_type = cls.RECORD_HEADER.unpack_from(buf, component_offset)
            component_data_offset = component_offset + cls.RECORD_HEADER.size
            component_data = buf[component_data_offset:component_data_offset + component_length]
            parsed_values.append(
                cls.parse_record_data(buf, data_offset, component_length,
                                      component_data_type, component_data))
        return parsed_values

    @classmethod
    def _parse_record_data_902(cls, data, record_length, buf, data_offset):
        parsed = cls._parse_record_data_601(data, record_length, buf, data_offset)
        rec_count = len(parsed)
        if rec_count == 2:
            return urljoin(parsed[0], parsed[1])
        else:
            joined = '/'.join(parsed)
            logger.warning("Unexpected record count {} in URL array (expected 2): '{}', please report.", rec_count, joined)
            return joined

    @classmethod
    def _parse_record_data_a01(cls, _data, record_length, *args):
        if record_length != 0:
            logger.warning("Unexpected data length {} in bookmark data type 0xA01, please report.", record_length)
        return None

    @classmethod
    def parse_record_data(cls, buf, data_offset, record_length, data_type, data):
        identity = lambda x, *args: x
        parsers = {
            0x101: lambda x, *args: x.decode('utf-8'),             # UTF-8 String
            0x201: identity,                                       # byte array, up to caller to handle
            # 0x300 CFNumberType https://developer.apple.com/reference/corefoundation/cfnumbertype
            0x301: lambda x, *args: struct.unpack('<b', data)[0],  # sInt8Type: Eight-bit, signed integer. The SInt8 data type is defined in MacTypes.h
            0x302: lambda x, *args: struct.unpack('<h', data)[0],  # sInt16Type: Sixteen-bit, signed integer. The SInt16 data type is defined in MacTypes.h
            0x303: lambda x, *args: struct.unpack('<i', data)[0],  # sInt32Type: Thirty-two-bit, signed integer. The SInt32 data type is defined in MacTypes.h
            0x304: lambda x, *args: struct.unpack('<q', data)[0],  # sInt64Type: Sixty-four-bit, signed integer. The SInt64 data type is defined in MacTypes.h
            0x305: lambda x, *args: struct.unpack('<f', data)[0],  # float32Type: Thirty-two-bit real. The Float32 data type is defined in MacTypes.h
            0x306: lambda x, *args: struct.unpack('<d', data)[0],  # float64Type: Sixty-four-bit real. The Float64 data type is defined in MacTypes.h and conforms to the 64-bit IEEE 754 standard
            0x307: lambda x, *args: struct.unpack('<B', data)[0],  # charType: Basic C char type
            0x308: lambda x, *args: struct.unpack('<H', data)[0],  # shortType: Basic C short type
            0x309: lambda x, *args: struct.unpack('<I', data)[0],  # intType: Basic C int type
            0x30A: lambda x, *args: struct.unpack('<L', data)[0],  # longType: Basic C long type
            0x30B: lambda x, *args: struct.unpack('<Q', data)[0],  # longLongType: Basic C long long type
            0x30C: lambda x, *args: struct.unpack('<f', data)[0],  # floatType: Basic C float type
            0x30D: lambda x, *args: struct.unpack('<d', data)[0],  # doubleType: Basic C double type
            0x30E: lambda x, *args: struct.unpack('<I', data)[0],  # cfIndexType: CFIndex value, see https://developer.apple.com/reference/corefoundation/cfindex
            0x30F: lambda x, *args: struct.unpack('<I', data)[0],  # nsIntegerType: NSInteger value, see https://developer.apple.com/reference/objectivec/nsinteger
            # 0x310 cgFloatType: Apparently this can be either 32-bit or 64-bit float,
            # dependent on target build architecture; CGFloat value, see https://developer.apple.com/reference/coregraphics/cgfloat
            0x400: lambda x, *args: parse_mac_absolute_time(struct.unpack_from('>d', data)[0]),  # Timestamp
            0x500: lambda x, *args: False,                                          # bool False if exists
            0x501: lambda x, *args: True,                                           # bool True if exists
            0x601: cls._parse_record_data_601,                     # array of pointers to data within bookmark (32-bit int + data_offset)
            0x801: lambda x, * args: guid_str_from_bytes(data, 'be'),  # UUID raw bytes
            0x901: lambda x, *args: x.decode('utf-8'),             # CFURL (UTF-8 String)
            0x902: cls._parse_record_data_902,                     # CFURL via array of pointers (multi-part URL)
            0xA01: cls._parse_record_data_a01,                     # CFNull
        }

        return parsers.get(data_type, identity)(data, record_length, buf, data_offset)

    @classmethod
    def _decode_sandbox_value(cls, parsed):
        parts = parsed.split(b';')
        return {
            'sandbox_uuid': parts[0].decode('utf-8'),
            'sandbox_path': parts[-1].rstrip(b'\x00').decode('utf-8'),
        }

    @classmethod
    def decode_value(cls, field_name, buf, data_offset, item_type, record_length, data_type, data):
        if field_name is None:
            return {}
        parsed = cls.parse_record_data(buf, data_offset, record_length, data_type, data)

        decoders = {
            0x1004: lambda x: {field_name: cls.join_path(x)},
            0x1005: lambda x: {field_name: cls.join_path(x)},
            0x1010: lambda x: {field_name: interpret_flags(struct.unpack_from('<Q', x[:8])[0], cls.RESOURCE_PROPERTY_FLAGS)},
            0x2000: lambda x: {field_name: ', '.join([str(y) for y in x])},
            0x2020: lambda x: {field_name: interpret_flags(struct.unpack_from('<Q', x[:8])[0], cls.VOLUME_PROPERTY_FLAGS)},
            0xf030: lambda x: {field_name: parse_mac_absolute_time(x)},
            0xf080: cls._decode_sandbox_value,
            0xf081: cls._decode_sandbox_value,
        }
        return decoders.get(item_type, lambda x: {field_name: x})(parsed)

    @classmethod
    def join_path(cls, array):
        return '/' + '/'.join([str(x) for x in array if x])

    @classmethod
    def parse_toc(cls, buf, offset, data_offset, toc_index):
        contents = []
        _data_length, record_type, flags, depth, next_toc, count = cls.TOC_HEADER.unpack_from(buf, offset)
        for i in range(count):
            (record_type,
             record_offset,
             flags) = cls.TOC_DATA_HEADER.unpack_from(buf,
                                                      offset + cls.TOC_HEADER.size + i * cls.TOC_DATA_HEADER.size)

            contents.append({'record_type': record_type,
                             'record_type_hex': hex(record_type),
                             'flags': flags,
                             'record_offset': record_offset + data_offset,
                             'hex_offset': hex(record_offset + data_offset),
                             'index': toc_index,
                             'depth': depth})

        return contents, next_toc
