from collections import namedtuple
from datetime import datetime
import decimal
import struct
from uuid import UUID


UNIX_EPOCH = datetime(1970, 1, 1)
HFS_EPOCH = datetime(1904, 1, 1)
HFS_EPOCH_FROM_UNIX_SHIFT = (UNIX_EPOCH - HFS_EPOCH).total_seconds()
MAC_ABSOLUTE_TIME_EPOCH = datetime(2001, 1, 1)
MAC_ABSOLUTE_TIME_EPOCH_FROM_UNIX_SHIFT = (UNIX_EPOCH - MAC_ABSOLUTE_TIME_EPOCH).total_seconds()


class NamedStruct(struct.Struct):
    def __init__(self, struct_name='NamedStruct', endianness='<', pairs=None):
        if pairs is None:
            pairs = []
        struct_args = [x[1] for x in pairs]
        super().__init__(endianness + ' '.join(struct_args))
        self.structured_data = namedtuple(struct_name, [x[0] for x in pairs if 'x' not in x[1]])

    def parse(self, buf, offset):
        return self.structured_data._make(self.unpack(buf[offset:self.size + offset]))

    def parse_as_dict(self, buf, offset):
        return dict(self.parse(buf, offset)._asdict())


def guid_str_from_bytes(guid_bytes, endian='le'):
    if endian.lower() == 'le':
        return str(UUID(bytes_le=guid_bytes))
    else:
        return str(UUID(bytes=guid_bytes))


def interpret_flags(bitmask, values):
    """
    Args:
        bitmask: flags to check
        values: array of tuples containing (value, description) pairs

    Returns: string containing descriptions of flags

    """
    return ', '.join(desc for num, desc in values if num & bitmask) if bitmask else None


def parse_mac_absolute_time(seconds, resolution=1):
    try:
        return parse_timestamp(seconds, resolution, MAC_ABSOLUTE_TIME_EPOCH_FROM_UNIX_SHIFT) if seconds else None
    except Exception:
        return None


def parse_timestamp(qword, resolution, epoch_shift, mode=decimal.ROUND_HALF_EVEN):
    """
    Generalized function for parsing timestamps

    :param qword: number of time units since the epoch
    :param resolution: number of time units per second
    :param epoch_shift: difference in seconds between UNIX epoch (1970-1-1)
                        and epoch of qword
    :param mode: decimal rounding mode
    :return: datetime.datetime
    """
    # convert qword from given epoch to UNIX epoch
    shifted = qword - epoch_shift * resolution
    # python's datetime.datetime supports microsecond precision
    datetime_resolution = int(1e6)

    # total number of microseconds since UNIX epoch
    # python 3 round() returns int, python 2 round() returns float
    total_microseconds = (decimal.Decimal(shifted * datetime_resolution) / decimal.Decimal(resolution)).quantize(1, mode)

    # convert to datetime
    return datetime.utcfromtimestamp(total_microseconds // datetime_resolution).replace(microsecond=total_microseconds % datetime_resolution)


def case_insensitive_dict_get(d, key, default=None):
    """
    Searches a dict for the first key matching case insensitively. If there is
    an exact match by case for the key, that match is given preference.

    Args:
        d: dict to search
        key: key name to retrieve case-insensitively

    Returns: value or default

    """
    if not key:
        return default
    if key in d:
        return d[key]
    if isinstance(key, str):
        key_lower = key.lower()
        for k in d:
            if k.lower() == key_lower:
                return d[k]
    return default
