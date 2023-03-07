# plistutils

## About

The `plistutils` library provides a number of convenience functions for dealing with Apple Property List files.
Our goal is to provide a single, comprehensive Python library for dealing with all aspects of Plist parsing.

plistutils is copyright (c) 2017, Stroz Friedberg, an Aon company.

## Components and Usage

### General Plist Parsing

The `PlistParser` class in `plistparser.py` supports automatic, recursive parsing of binary, XML, and JSON plists.
If an embedded plist is located within the structure of a plist file, calling `PlistParser.parse()` will return
the Python data structure representation of that file and all embedded plists.

#### Sample Usage
```
from plistutils.plistparser import InvalidPlistException, PlistParser

fullpath = 'target.plist'
with open(fullpath, rb) as plist_file:
    try:
        data = PlistParser.parse(plist_file)
    except InvalidPlistException:
        logger.warning(f"Error parsing plist '{fullpath}'")
    ...
```

### Alias structure parsing

Beginning in macOS System 7, users could create an "alias" file, which was a dynamically updated link to a
target file, similar in nature to LNK files in Windows. macOS would automatically resolve the location of
the file based on a number of stored attributes. Mac OS X made embedding Alias data structures within plists
regular behavior, also for the purpose of dynamically linking to a target. The Alias structure has undergone
several revisions; the most commonly seen at the time of this publishing are versions 2 and 3, depending on
the application and macOS versions.

Alias data structures have been deprecated, but you will often still find them on machines that have been
upgraded or that are using older versions of application software. For example, if you install Microsoft
Office 2011 on macOS 10.13 High Sierra, the plists created by Office will contain Alias version 2 structures,
while Office 2016 plists will contain a mixture of Alias version 3 and Bookmark structures. Additionally,
Alias data is generally not updated in macOS system plists to newer versions or to Bookmark data unless
the target is updated in the plist (by moving or deleting the plist item, such as in
`com.apple.sidebarlists.plist`).

Both versions 2 and 3 begin with a fixed header structure (containing different fields depending on version),
followed by a table of fields. Fields are noted by a numerical identifier, and not all fields need be
present in the table. The table fields are identical in versions 2 and 3.

The `AliasParser` class in `alias.py` provides parsing for Alias versions 2 and 3. `AliasParser.parse()` is
a generator, and yields Python `dict`s containing the parsed fields. Usually this function will only yield
a single record, but Alias data can contain an embedded Alias record (which could, theoretically, contain
another embedded Alias record), in which case it will yield multiple records.

#### Sample Usage
```
from plistutils.alias import AliasParser
from plistutils.plistparser import PlistParser

fullpath = 'target.plist'
with open(fullpath, rb) as plist_file:
    data = PlistParser.parse(plist_file)
    # Iterate parsed plist and pass index/Alias data to parse_bookmark()
    for alias_record in AliasParser.parse(fullpath, idx, data['Alias']):
        print(alias_record)
```

### Bookmark structure parsing

Bookmark structures are the successor to Alias data. Again, they operate similarly to Windows LNK files, in that
they store attributes about a target, and allow the system to resolve that target. The Bookmark format is a much
more extensible structure allowing the creator to use standard data types or to write arbitrary binary data that
the caller is responsible for storing and interpreting. The detail captured in Bookmarks is often much greater
than that in Alias data.

The `BookmarkParser` class in `bookmark.py` parses Bookmark data. Note that `BookmarkParser.parse_bookmark()` is
a generator which yields multiple parsed records, as a single Bookmark can have multiple entries (usually in the
case of a Bookmark referencing a file within a DMG or similar circumstance) and also contain embedded Alias
data (which could, in turn, contain embedded Alias data).

#### Sample Usage
```
from plistutils.bookmark import BookmarkParser
from plistutils.plistparser import PlistParser

fullpath = 'target.plist'
with open(fullpath, rb) as plist_file:
    data = PlistParser.parse(plist_file)
    # Iterate parsed plist and pass index/name/Bookmark data to parse_bookmark()
    for bookmark_record in BookmarkParser.parse_bookmark(fullpath, idx, name, data['Bookmark']):
        print(bookmark_record)
```

### NSKeyedArchiver parsing

Apple occasionally uses the `NSKeyedArchiver` format to store data within a plist. This "encoder" format has existed
since macOS 10.2, and an example can be seen in the typical iChat plist as well as in SFL recent items plists. This
format is meant to be somewhat space-efficient, as multiple objects can point to the same children values.

The `NSKeyedArchiveParser` in `nskeyedarchiver.py` parses most standard data types, and we intend to improve support
for complex types in future releases.

#### Sample Usage
```
from plistutils.nskeyedarchiver import NSKeyedArchiveParser, NSKeyedArchiveException
from plistutils.plistparser import PlistParser

fullpath = 'target.plist'
with open(fullpath, rb) as plist_file:
    data = PlistParser.parse(plist_file)
    if NSKeyedArchiveParser.is_known_nskeyedarchive(data, fullpath):
        nska_parser = NSKeyedArchiveParser(fullpath)
        try:
            unarchived_data = nska_parser.parse_archive(data).get('root', {})
        except NSKeyedArchiveException:
            return
        print(unarchived_data)
```

### utils.py

`utils.py` contains general utility functions, mostly focused on correct parsing and rounding of timestamps.

## Requirements

`plistutils` depends on the biplist library (https://pypi.python.org/pypi/biplist) and is tested on CPython 3.5 64-bit.

## Acknowledgements

Michael Lynn provided fantastic research illuminating data stored in Bookmarks, without which we could not have
created the Bookmark parser (http://michaellynn.github.io/2015/10/24/apples-bookmarkdata-exposed/).

Patrick Olsen wrote a blog post (http://sysforensics.org/2016/08/mac-alias-data-objects/) which spurred us to take a
look at the Alias v3 structure and produce a fully functional parser.

## Other Plist Utility Libraries

Alastair Houghton maintains a Python library which parses and creates Alias version 2 and Bookmark structures
(https://github.com/al45tair/mac_alias). We came across the `mac_alias` repository after the majority of work was
completed on Alias version 3 and Bookmark parsing.

CCL Group publishes a binary plist parser which supports extracting NSKeyedArchive data when it contains common object
types (https://github.com/cclgroupltd/ccl-bplist).
