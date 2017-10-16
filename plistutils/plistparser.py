from io import BytesIO
import json
import logging
import plistlib


import biplist


logger = logging.getLogger(__name__)


class InvalidPlistException(Exception):
    pass


class PlistParser(object):
    class PlistTypes(object):
        not_plist_type = 0
        binary_type = 1
        xml_type = 2
        json_type = 3

    _binary_magic = b'bplist00'
    _xml_magic = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n"
    _xml2_magic = _xml_magic.replace(b'\n', b'\r\n')
    _xml_str = _xml_magic.decode('utf-8')
    _xml2_str = _xml_magic.decode('utf-8')
    _json_magic_1 = b'['
    _json_magic_2 = b'{'

    @classmethod
    def _get_plist_type(cls, file_obj):
        class NestedScope(object):
            buf = b''
            size = 0

        # Ensures len(NestedScope.buf) >= length of target and compares
        def read_and_check(magic):
            # Already read the required number of bytes
            if len(NestedScope.buf) >= len(magic):
                return NestedScope.buf.startswith(magic)
            # Impossible to satisfy the requirement
            if len(NestedScope.buf) + len(magic) > NestedScope.size:
                return False
            NestedScope.buf += file_obj.read(len(magic) - len(NestedScope.buf))
            return NestedScope.buf.startswith(magic)

        file_obj.seek(0, 2)
        NestedScope.size = file_obj.tell()
        file_obj.seek(0)

        if read_and_check(cls._binary_magic):
            return cls.PlistTypes.binary_type
        if read_and_check(cls._xml_magic) or read_and_check(cls._xml2_magic):
            return cls.PlistTypes.xml_type
        if read_and_check(cls._json_magic_1) or read_and_check(cls._json_magic_2):
            return cls.PlistTypes.json_type
        return cls.PlistTypes.not_plist_type

    @classmethod
    def parse(cls, file_obj):
        file_obj.seek(0)
        return cls._parse(BytesIO(file_obj.read()))

    @classmethod
    def _parse(cls, file_obj, plist_type=None):
        def visit(plist):
            if isinstance(plist, bytes) or isinstance(plist, str):
                if isinstance(plist, str):
                    if plist.startswith(cls._xml_str) or plist.startswith(cls._xml2_str):
                        plist = plist.encode('utf-8')
                    else:
                        return None

                try:
                    value_flo = BytesIO(plist)
                    value_type = cls._get_plist_type(value_flo)
                    if value_type != cls.PlistTypes.not_plist_type:
                        return cls._parse(value_flo, plist_type=value_type)
                except Exception:
                    # It wasn't a plist
                    return None
            iterators = {list: lambda x: iter(enumerate(x)),
                         dict: lambda x: iter(x.items())}
            for base_type, value in iterators.items():
                if isinstance(plist, base_type):
                    it = value
                    break
            else:
                it = lambda x: []

            for k, v in it(plist):
                visited = visit(v)
                if visited:
                    plist[k] = visited
            return None

        data = cls._read_plist(file_obj, plist_type=plist_type)
        visit(data)
        return data

    @classmethod
    def _read_plist(cls, file_obj, plist_type=None):
        # TODO: Old-Style ASCII property Lists
        # https://developer.apple.com/library/mac/documentation/Cocoa/Conceptual/PropertyLists/OldStylePlists/OldStylePLists.html
        # They're like JSON, except not.
        if plist_type is None:
            plist_type = cls._get_plist_type(file_obj)
        try:
            file_obj.seek(0)
            return ({cls.PlistTypes.binary_type: cls._read_binary_plist,
                     cls.PlistTypes.xml_type: cls._read_xml_plist,
                     cls.PlistTypes.json_type: cls._read_json_plist}
                    [plist_type](file_obj))
        except Exception:
            raise

    @classmethod
    def _read_binary_plist(cls, file_obj):
        try:
            return biplist.readPlist(file_obj)
        except biplist.InvalidPlistException as e:
            raise InvalidPlistException(e)

    @classmethod
    def _read_xml_plist(cls, file_obj):
        rtn = plistlib.load(file_obj)
        return rtn

    @classmethod
    def _read_json_plist(cls, file_obj):
        rtn = json.load(file_obj)
        return rtn
