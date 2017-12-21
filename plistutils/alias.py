import binascii
import logging
import struct


from plistutils.utils import HFS_EPOCH_FROM_UNIX_SHIFT, interpret_flags, NamedStruct, parse_timestamp


logger = logging.getLogger(__name__)


class AliasParser(object):
    """
    Note that for...
        v2: volume_creation_date, creation_date, and volume_name are present in both the main struct and named fields.
        v3: volume_creation_date and creation_date are present in both the main struct and named fields.
        The named fields value is higher resolution in all cases, and will overwrite the main struct value, if present.

    References
    https://opensource.apple.com/source/CarbonHeaders/CarbonHeaders-8A428/Aliases.h
    http://dubeyko.com/development/FileSystems/HFSPLUS/hexdumps/hfsplus_volume_header.html
    """

    HEADER = struct.Struct('> 4sHH')

    ALIASV3 = NamedStruct('AliasV3', '>', [
        ('is_directory', 'H'),
        ('volume_creation_date', '8s'),
        ('signature_fsid', '4s'),
        ('_unknown_x16', '2x'),  # Maybe disk type - See comments above DISK_TYPES
        ('parent_inode', 'I'),  # 0xFFFFFFFF for none (e.g. alias points to volume - see BLAH sample)
        ('target_inode', 'I'),  # 0xFFFFFFFF for none (e.g. alias points to volume - see BLAH sample)
        ('creation_date', '8s'),
        ('volume_flags', 'I'),
        ('_unknown_x2c', '14x'),
    ])

    ALIASV2 = NamedStruct('AliasV2', '>', [
        ('is_directory', 'H'),
        ('_volume_name_length', 'x'),
        ('volume_name', '27s'),  # first octet is volume length
        ('volume_creation_date', 'I'),
        ('signature', '2s'),
        ('disk_type', 'H'),
        ('parent_inode', 'I'),  # 0xFFFFFFFF for none (e.g. alias points to volume - see BLAH sample)
        ('_filename_len', 'x'),
        ('target_filename', '63s'),
        ('target_inode', 'I'),  # 0xFFFFFFFF for none (e.g. alias points to volume - see BLAH sample)
        ('creation_date', 'I'),
        ('application', '4s'),  # creator code (4CC)
        ('target_type', '4s'),
        ('alias_to_root_depth', 'H'),
        ('root_to_target_depth', 'H'),
        ('volume_flags', 'I'),
        ('filesystem_id', '2s'),
        ('_unknown_x2c', '10x'),
    ])

    # getattrlist and statfs specify signature as 32-bit when on 64-bit systems
    SIGNATURE_FSID = {
        b'BDcu': 'UDF (CD/DVD)',
        b'BDIS': 'FAT32',
        b'BDxF': 'exFAT',
        b'HX\x00\x00': 'HFSX',
        b'H+\x00\x00': 'HFS+',
        b'KG\x00\x00': 'FTP',
        b'NTcu': 'NTFS'
    }

    # Disk Types are known good for Alias v2.
    #
    # These don't seem quite right for Alias v3, though:
    # - 0 samples look correct ('Fixed')
    # - we have one sample for 1 which is a USB thumb drive
    # - we have one sample for 5 which is a DMG
    DISK_TYPES = {
        0: 'Fixed',
        1: 'Network',
        2: '400KB Floppy',
        3: '800KB Floppy',
        4: '1.44MB Floppy',
        5: 'Ejectable'
    }

    ALIAS_FLAGS = [
        (0x0002, 'IsEjectable'),
        (0x0020, 'IsBootVolume'),
        (0x0080, 'IsAutomounted'),
        (0x0100, 'HasPersistentFileIds')
    ]

    @classmethod
    def named_fields(cls):
        # Named fields appear to be the same between v2 and v3.
        # Fields with a decoder of None are ignored.
        return {
            0x0000: ('folder_name', cls.decode_utf8),
            0x0001: ('cnid_path', cls.decode_cnid_path),
            0x0002: ('hfs_path', cls.decode_utf8),
            0x0003: ('appleshare_zone', None),
            0x0004: ('appleshare_server_name', None),
            0x0005: ('appleshare_username', None),
            0x0006: ('driver_name', cls.decode_utf8),
            # 0x0007: ?
            # 0x0008: ?
            0x0009: ('network_mount_info', None),
            0x000A: ('dialup_info', None),
            # 0x000B: ?
            # 0x000C: ?
            # 0x000D: ?
            0x000E: ('target_filename', cls.decode_hfs_unicode_str),
            0x000F: ('volume_name', cls.decode_hfs_unicode_str),
            0x0010: ('volume_creation_date', cls.decode_hfs_epoch_date),
            0x0011: ('creation_date', cls.decode_hfs_epoch_date),
            0x0012: ('path', cls.decode_utf8),
            0x0013: ('volume_mount_point', cls.decode_utf8),
            0x0014: ('alias_data', lambda buf, offset, length: buf[offset:offset + length]),
            0x0015: ('user_home_prefix_length', None)  # does anyone care about this? struct.unpack('>H')
        }

    @classmethod
    def parse(cls, fullpath, idx, buf):
        """
        :param fullpath: Full path to file, used for logging only
        :param idx: Index enumerated from original plist structure, used for reference only
        :param buf: Alias binary blob
        :return: dictionary containing parsed data
        """
        supported_versions = {
            2: cls.ALIASV2,
            3: cls.ALIASV3
        }

        if buf is None or len(buf) < cls.HEADER.size:
            return
        app_info, record_length, version = cls.HEADER.unpack_from(buf)
        if app_info != b'\x00\x00\x00\x00':
            logger.warning("Alias data unexpected app info '{}', please report.", app_info)
        if record_length != len(buf):
            logger.warning("Alias data unexpected size in '{}': expected {:,} bytes, got {:,} bytes.", fullpath, record_length, len(buf))
        if version not in supported_versions:
            logger.error("Unsupported Alias version ({}) in '{}', please report.", version, fullpath)
            return

        yield from cls.parse_version(fullpath, idx, buf, cls.HEADER.size, supported_versions[version])

    @classmethod
    def parse_version(cls, fullpath, idx, buf, offset, version_struct):
        buf_len = len(buf)
        try:
            record = version_struct.parse_as_dict(buf, offset)
        except struct.error:
            logger.debug("Could not decode alias data in file '{}'.", fullpath)
            return {}
        cur_offset = offset + version_struct.size

        loop_ct = 0
        # Iterate field list with a hard cap on iterations.
        # We only know of 22 fields (and we don't know what all of those are),
        # but maybe there are more we don't know about.
        while cur_offset < buf_len and loop_ct < 50:
            cur_offset = cls.decode_field(fullpath, buf, cur_offset, record)
            loop_ct += 1

        cls.decode_ascii_fields(record)
        cls.decode_dates(record)
        cls.filter_cnids(record)
        cls.filter_levels(record)
        cls.join_path_mount(record)
        record['is_directory'] = bool(record['is_directory'])
        if record.get('signature_fsid') is None:
            record['signature_fsid'] = record.pop('signature') + record.pop('filesystem_id')
        record['filesystem_description'] = cls.SIGNATURE_FSID.get(record['signature_fsid'], 'Unknown')
        if 'disk_type' in record:
            record['disk_type_description'] = cls.DISK_TYPES.get(record['disk_type'], 'Unknown')
        record['signature_fsid'] = cls.decode_utf8(record['signature_fsid'], 0, None)
        record['volume_flags'] = interpret_flags(record.pop('volume_flags', None), cls.ALIAS_FLAGS)
        record['bookmark_index'] = idx
        alias_data = record.pop('alias_data', None)
        yield record
        if alias_data:
            try:
                yield from AliasParser.parse(fullpath, idx, alias_data)
            except RecursionError:
                logger.error("Could not fully parse embedded alias data due to depth, please report.")

    @classmethod
    def decode_field(cls, fullpath, buf, offset, record):
        """
        2-byte field ID, followed by 2-byte length
        length must be padded to a multiple of 2 to find next offset
        e.g. b'\x00\x13\x00\x01\x2F\x00' denotes:
            - field 0x13 ('volume_mount_point')
            - data length of 1 byte
            - decoded value of '/'
            - total length of 2 bytes
        """
        cur_offset = offset
        field_id, length = struct.unpack_from('>HH', buf, cur_offset)
        cur_offset += 4
        if field_id != 0xFFFF and length > 0:
            field_name, decoder = cls.named_fields().get(field_id, (None, None))
            if decoder:
                try:
                    record[field_name] = decoder(buf, cur_offset, length)
                except Exception as e:
                    logger.debug("Could not decode field '{}' in file '{}': {}.", field_name, fullpath, e)
            elif field_name is None:
                logger.warning("Unexpected field tag {} in Alias data for {}, please report.", field_id, fullpath)
            cur_offset += length + length % 2
        return cur_offset

    @classmethod
    def decode_utf8(cls, buf, offset, length):
        """
        In Alias v2 data, some path strings contain ':\x00' as a separator. Other tools
        include the \x00 in output, which seems useless/careless.
        """
        if length:
            raw = buf[offset:offset + length]
        else:
            raw = buf[offset:]
        try:
            return raw.decode('utf-8').replace('\x00', '')
        except UnicodeDecodeError:
            return binascii.hexlify(raw).decode('ascii')

    @classmethod
    def decode_ascii_fields(cls, record):
        fields = ['application', 'target_type']
        for f in fields:
            if f in record and isinstance(record[f], bytes):
                val = record[f]
                try:
                    record[f] = val.decode('ascii')
                except UnicodeDecodeError:
                    record[f] = binascii.hexlify(val).decode('ascii')

    @classmethod
    def decode_hfs_unicode_str(cls, buf, offset, _length):
        # HFSUniStr255 - a string of up to 255 16-bit Unicode characters,
        # with a preceding 16-bit length (number of characters)
        cur_offset = offset
        uni_str_len = struct.Struct('>H')
        char_count = uni_str_len.unpack_from(buf, cur_offset)[0]
        cur_offset += uni_str_len.size
        hfs_unicode_str = buf[cur_offset:cur_offset + (char_count * 2)].decode('utf-16-be')
        return hfs_unicode_str

    @classmethod
    def decode_cnid_path(cls, buf, offset, length):
        path = None
        if length % 4 != 0:
            logger.warning(
                "Unable to parse CNIDs from alias data. Expected multiple of 4 bytes, but got {}. Please report.", length)
        elif length:
            path = '/'.join([str(x) for x in struct.unpack('>{}I'.format(length // 4), buf[offset:offset + length])])
        return path

    @classmethod
    def decode_hfs_epoch_date(cls, buf, offset, length=8, struct_endian='>'):
        """

        Args:
            buf: bytes object containing the HFS timestamp
            offset: int offset within the buf
            length: number of bytes to read
            struct_endian: endianness to use when reading values (MS Office 2011 Access Date is LE)

        Returns: datetime.datetime

        """
        timestamp = buf[offset:offset + length]
        high = struct.unpack('{}H'.format(struct_endian), timestamp[0:2])[0]
        low = struct.unpack('{}I'.format(struct_endian), timestamp[2:6])[0]
        fraction = struct.unpack('{}H'.format(struct_endian), timestamp[6:8])[0]
        return cls.combine_hfs_datetime(high, low, fraction)

    @classmethod
    def combine_hfs_datetime(cls, high_seconds, low_seconds, fraction):
        seconds = ((high_seconds << 32) + low_seconds) * 65535 + fraction
        try:
            return parse_timestamp(seconds, 65535, HFS_EPOCH_FROM_UNIX_SHIFT) if seconds else None
        except Exception:
            return None

    @classmethod
    def decode_dates(cls, record):
        for field_name in ['creation_date', 'volume_creation_date']:
            if field_name in record and isinstance(record[field_name], bytes):
                record[field_name] = cls.decode_hfs_epoch_date(record.pop(field_name), 0, 8)

    @classmethod
    def filter_cnids(cls, record):
        for cnid in ['parent_inode', 'target_inode']:
            if cnid in record:
                record[cnid] = None if record[cnid] == 0xFFFFFFFF else record[cnid]

    @classmethod
    def filter_levels(cls, record):
        for level in ['alias_to_root_depth', 'root_to_target_depth']:
            if record.get(level) == 0xFFFF:
                record[level] = None

    @classmethod
    def join_path_mount(cls, record):
        mount = record.get('volume_mount_point')
        if mount:
            path = record.get('path') or ''
            if not mount.endswith('/') and path:
                mount += '/'
            record['path'] = mount + path
