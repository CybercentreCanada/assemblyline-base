import os
import platform
import re
import struct
import subprocess
import sys
import threading
import uuid
import zipfile
import msoffcrypto
from binascii import hexlify
from collections import defaultdict
from typing import Tuple, Union, Dict

import magic
import ssdeep
from cart import get_metadata_only

from assemblyline.common.digests import get_digests_for_file
from assemblyline.common.forge import get_constants
from assemblyline.common.str_utils import dotdump, safe_str

constants = get_constants()

STRONG_INDICATORS = {
    'code/vbs': [
        re.compile(rb'(^|\n)On Error Resume Next'),
        re.compile(rb'(^|\n)(?:Private)?[ \t]*Sub[ \t]+\w+\(*'),
        re.compile(rb'(^|\n)End Module'),
        re.compile(rb'(^|\n)ExecuteGlobal'),
    ],
    'code/javascript': [
        re.compile(rb'function([ \t]*|[ \t]+[\w]+[ \t]*)\([\w \t,]*\)[ \t]*{'),
        re.compile(rb'\beval[ \t]*\('),
        re.compile(rb'new[ \t]+ActiveXObject\('),
        re.compile(rb'xfa\.((resolve|create)Node|datasets|form)'),
        re.compile(rb'\.oneOfChild'),
        re.compile(rb'unescape\('),
        re.compile(rb'\.createElement\('),
    ],
    'code/csharp': [
        re.compile(rb'(^|\n)[ \t]*namespace[ \t]+[\w.]+'),
        re.compile(rb'(^|\n)[ \t]*using[ \t]+[\w.]+;'),
        re.compile(rb'(^|\n)[ \t]*internal class '),
    ],
    'code/php': [
        re.compile(rb'(^|\n)<\?php'),
        re.compile(rb'namespace[ \t]+[\w.]+'),
        re.compile(rb'function[ \t]*\w+[ \t]*\(\$[^)]+\)[ \t]*{'),
        re.compile(rb'\beval[ \t]*\('),
    ],
    'code/c': [
        re.compile(rb'(^|\n)(static|typedef)?[ \t]*struct '),
        re.compile(rb'(^|\n)#include[ \t]*([<"])[\w./]+([>"])'),
        re.compile(rb'(^|\n)#(ifndef |define |endif |pragma )'),
    ],
    'code/python': [
        re.compile(rb'(^|\n)[ \t]*if __name__[ \t]*==[ \t]*[\'\"]__main__[\'\"][ \t]*:'),
        re.compile(rb'(^|\n)[ \t]*from[ \t]+[\w.]+[ \t]+import[ \t]+[\w.*]+([ \t]+as \w+)?'),
        re.compile(rb'(^|\n)[ \t]*def[ \t]*\w+[ \t]*\([^)]*\)[ \t]*:'),
    ],
    'code/rust': [
        re.compile(rb'(^|\n)(pub|priv)[ \t]*(struct |enum |impl |const )'),
        re.compile(rb'(^|\n)[ \t]*fn[ \t]*\w+[ \t]*\(&self'),
        re.compile(rb'(println!|panic!)'),
    ],
    'code/lisp': [
        re.compile(rb'(^|\n)[ \t]*\((defmacro|defun|eval-when|in-package|list|export|defvar) '),
    ],
    'code/java': [
        re.compile(rb'(^|\n)[ \t]*public[ \t]+class[ \t]+\w+[ \t]+(extends[ \t]+\w+[ \t]+)?{'),
        re.compile(rb'(^|\n)[\w \t]+\([^)]+\)[ \t]+throws[ \t]+[\w, \t]+[ \t]+{'),
    ],
    'code/perl': [
        re.compile(rb'(^|\n)[ \t]*my[ \t]*\$\w+[ \t]*='),
        re.compile(rb'(^|\n)[ \t]*sub[ \t]*\w+[ \t]*{'),
    ],
    'code/ruby': [
        re.compile(rb'(^|\n)[ \t]*require(_all)?[ \t]*\'[\w/]+\''),
        re.compile(rb'rescue[ \t]+\w+[ \t]+=>'),
    ],
    'code/go': [
        re.compile(rb'(^|\n)[ \t]*import[ \t]+\('),
        re.compile(rb'(^|\n)[ \t]*func[ \t]+\w+\('),
    ],
    'code/css': [
        re.compile(rb'(^|\n|\})(html|body|footer|span\.|img\.|a\.|\.[a-zA-Z\-.]+)[^{]+{'
                   rb'[ \t]*(padding|color|width|margin|background|font|text)[^}]+\}'),
    ],
    'text/markdown': [
        re.compile(rb'\*[ \t]*`[^`]+`[ \t]*-[ \t]*\w+'),
    ],
    'document/email': [
        re.compile(rb'^Content-Type: ', re.MULTILINE),
        re.compile(rb'^Subject: ', re.MULTILINE),
        re.compile(rb'^MIME-Version: ', re.MULTILINE),
        re.compile(rb'^Message-ID: ', re.MULTILINE),
        re.compile(rb'^To: ', re.MULTILINE),
        re.compile(rb'^From: ', re.MULTILINE),
    ],
    'metadata/sysmon': [
        re.compile(rb'<Events>*'),
        re.compile(rb'<Event>*'),
        re.compile(rb'<\/Event>'),
        re.compile(rb'<\/Events>'),
    ],
    'code/xml': [
        # Check if it has an xml declaration header
        re.compile(rb'^\s*<\?xml[^>]+\?>', re.DOTALL | re.MULTILINE),
        # Check if it begins and ends with <tag ... and </tag ...> (for informal xml usages)
        re.compile(rb'^\s*<(?P<open>[\w:]+) .+</(?P=open)[^>]+>\s*$', re.DOTALL),
        # Check if a tag has an xmlns attribute
        re.compile(rb'<[^>]+xmlns[:=][^>]+>', re.MULTILINE),
    ],
    'code/ps1': [
        # Match one of the common Cmdlets
        re.compile(rb'(^|\n)(Get-ExecutionPolicy|Get-Service|Where-Object|ConvertTo-HTML|Select-Object|Get-Process|'
                   rb'Clear-History|ForEach-Object|Clear-Content|Compare-Object|New-ItemProperty|New-Object|'
                   rb'New-WebServiceProxy|Set-Alias|Wait-Job|Get-Counter|Test-Path|Get-WinEvent|Start-Sleep|'
                   rb'Set-Location|Get-ChildItem|Rename-Item|Stop-Process|Add-Type)'),
        # Match one of the common Classes
        re.compile(rb'(-memberDefinition|-Name|-namespace|-passthru)'),
    ]
}
STRONG_SCORE = 15
MINIMUM_GUESS_SCORE = 20

WEAK_INDICATORS = {
    'code/javascript': [rb'var ',
                        rb'document\.write\(',
                        rb'String\.(fromCharCode|raw)\(',
                        rb'Math\.(round|pow|sin|cos)\(',
                        rb'(isNaN|isFinite|parseInt|parseFloat)\(',
                        b'WSH',
                        ],
    'code/jscript': [rb'new[ \t]+ActiveXObject\(', rb'Scripting\.Dictionary'],
    'code/pdfjs': [rb'xfa\.((resolve|create)Node|datasets|form)', rb'\.oneOfChild'],
    'code/vbs': [
        rb'(^|\n)*[ ]{0,1000}[\t]*(Dim |Sub |Loop |Attribute |End Sub|Function |End Function )',
        b'CreateObject',
        b'WScript',
        b'window_onload',
        b'.SpawnInstance_',
        b'.Security_',
        b'WSH',
    ],
    'code/csharp': [rb'(^|\n)(protected)?[ \t]*override'],
    'code/sql': [rb'(^|\n)(create |drop |select |returns |declare )'],
    'code/php': [rb'\$this\->'],
    'code/c': [rb'(^|\n)(const char \w+;|extern |uint(8|16|32)_t )'],
    'code/python': [b'try:', b'except:', b'else:'],
    'code/java': [rb'(^|\n)[ \t]*package[ \t]+[\w\.]+;'],
    'code/perl': [rb'(^|\n)[ \t]*package[ \t]+[\w\.]+;', b'@_'],
    'text/markdown': [rb'\[[\w]+\]:[ \t]*http:'],
    'code/ps1': [
        # Check for PowerShell Parameters ex.  -Online -FeatureName
        rb'\s-([A-Z][a-z0-9]+)+',
        # Check for cmdlet names ex. Disable-WindowsOptionalFeature
        rb'([A-Z][a-z0-9]+)+-([A-Z][a-z0-9]+)+',
    ]
}
WEAK_SCORE = 1

WEAK_INDICATORS = {k: re.compile(b'|'.join(v)) for k, v in WEAK_INDICATORS.items()}

SHEBANG = re.compile(rb'^#![\w./]+/(?:env[ \t]*)?(\w+)[ \t]*\n')

EXECUTABLES = {
    'escript': 'erlang',
    'nush': 'nu',
    'macruby': 'ruby',
    'jruby': 'ruby',
    'rbx': 'ruby',
}

OLE_CLSID_GUIDs = {
    # GUID v0 (0)
    "00020803-0000-0000-C000-000000000046": "document/office/word",  # "MS Graph Chart"
    "00020900-0000-0000-C000-000000000046": "document/office/word",  # "MS Word95"
    "00020901-0000-0000-C000-000000000046": "document/office/word",  # "MS Word 6.0 - 7.0 Picture"
    "00020906-0000-0000-C000-000000000046": "document/office/word",  # "MS Word97"
    "00020907-0000-0000-C000-000000000046": "document/office/word",  # "MS Word"

    "00020C01-0000-0000-C000-000000000046": "document/office/excel",  # "Excel"
    "00020821-0000-0000-C000-000000000046": "document/office/excel",  # "Excel"
    "00020820-0000-0000-C000-000000000046": "document/office/excel",  # "Excel97"
    "00020810-0000-0000-C000-000000000046": "document/office/excel",  # "Excel95"

    "00021a14-0000-0000-C000-000000000046": "document/office/visio",  # "Visio"

    "0002CE02-0000-0000-C000-000000000046": "document/office/equation",  # "MS Equation 3.0"
    "0003000A-0000-0000-C000-000000000046": "document/office/paintbrush",  # "Paintbrush Picture",
    "0003000C-0000-0000-C000-000000000046": "document/office/package",  # "Package"
    "000C1084-0000-0000-C000-000000000046": "document/installer/windows",  # "Installer Package (MSI)"
    "00020D0B-0000-0000-C000-000000000046": "document/email",  # "MailMessage"

    # GUID v1 (Timestamp & MAC-48)
    "29130400-2EED-1069-BF5D-00DD011186B7": "document/office/wordpro",  # "Lotus WordPro"
    "46E31370-3F7A-11CE-BED6-00AA00611080": "document/office/word",  # "MS Forms 2.0 MultiPage"
    "5512D110-5CC6-11CF-8D67-00AA00BDCE1D": "document/office/word",  # "MS Forms 2.0 HTML SUBMIT"
    "5512D11A-5CC6-11CF-8D67-00AA00BDCE1D": "document/office/word",  # "MS Forms 2.0 HTML TEXT"
    "5512D11C-5CC6-11CF-8D67-00AA00BDCE1D": "document/office/word",  # "MS Forms 2.0 HTML Hidden"
    "64818D10-4F9B-11CF-86EA-00AA00B929E8": "document/office/powerpoint",  # "MS PowerPoint Presentation"
    "64818D11-4F9B-11CF-86EA-00AA00B929E8": "document/office/powerpoint",  # "MS PowerPoint Presentation"
    "11943940-36DE-11CF-953E-00C0A84029E9": "document/office/word",  # "MS Photo Editor 3.0 Photo"
    "B801CA65-A1FC-11D0-85AD-444553540000": "document/pdf",  # "Adobe Acrobat Document"
    "A25250C4-50C1-11D3-8EA3-0090271BECDD": "document/office/wordperfect",  # "WordPerfect Office"
    "C62A69F0-16DC-11CE-9E98-00AA00574A4F": "document/office/word",  # "Microsoft Forms 2.0 Form"
    "F4754C9B-64F5-4B40-8AF4-679732AC0607": "document/office/word",  # Word.Document.12
    "BDD1F04B-858B-11D1-B16A-00C0F0283628": "document/office/word",  # Doc (see CVE2012-0158)
}

recognized = constants.RECOGNIZED_TYPES

tag_to_extension = {
    'archive/chm': '.chm',
    'audiovisual/flash': '.swf',
    'code/batch': '.bat',
    'code/c': '.c',
    'code/csharp': '.cs',
    'code/hta': '.hta',
    'code/html': '.html',
    'code/java': '.java',
    'code/javascript': '.js',
    'code/jscript': '.js',
    'code/pdfjs': '.js',
    'code/perl': '.pl',
    'code/php': '.php',
    'code/ps1': '.ps1',
    'code/python': '.py',
    'code/ruby': '.rb',
    'code/vbs': '.vbs',
    'code/wsf': '.wsf',
    'document/installer/windows': '.msi',
    'document/office/excel': '.xls',
    'document/office/mhtml': '.mhtml',
    'document/office/ole': '.doc',
    'document/office/powerpoint': '.ppt',
    'document/office/rtf': '.doc',
    'document/office/unknown': '.doc',
    'document/office/visio': '.vsd',
    'document/office/word': '.doc',
    'document/office/wordperfect': 'wp',
    'document/office/wordpro': 'lwp',
    'document/pdf': '.pdf',
    'document/email': '.eml',
    'executable/windows/pe32': '.exe',
    'executable/windows/pe64': '.exe',
    'executable/windows/dll32': '.dll',
    'executable/windows/dll64': '.dll',
    'executable/windows/dos': '.exe',
    'executable/windows/com': '.exe',
    'executable/linux/elf32': '.elf',
    'executable/linux/elf64': '.elf',
    'executable/linux/so32': '.so',
    'executable/linux/so64': '.so',
    'java/jar': '.jar',
    'silverlight/xap': '.xap',
    'meta/shortcut/windows': '.lnk',
}

sl_patterns = [
    ['tnef', r'Transport Neutral Encapsulation Format'],
    ['chm', r'MS Windows HtmlHelp Data'],
    ['windows/dll64', r'^pe32\+ .*dll.*x86\-64'],
    ['windows/pe64', r'^pe32\+ .*x86\-64.*windows'],
    ['windows/dll32', r'^pe32 .*dll'],
    ['windows/pe32', r'^pe32 .*windows'],
    ['windows/pe', r'^pe unknown.*windows'],
    ['windows/dos', r'^(ms-)?dos executable'],
    ['windows/com', r'^com executable'],
    ['windows/dos', r'^8086 relocatable'],
    ['linux/elf32', r'^elf 32-bit lsb +executable'],
    ['linux/elf64', r'^elf 64-bit lsb +executable'],
    ['linux/so32', r'^elf 32-bit lsb +shared object'],
    ['linux/so64', r'^elf 64-bit lsb +shared object'],
    ['mach-o', r'^Mach-O'],
    ['7-zip', r'^7-zip archive data'],
    ['ace', r'^ACE archive data'],
    ['bzip2', r'^bzip2 compressed data'],
    ['cabinet', r'^installshield cab'],
    ['cabinet', r'^microsoft cabinet archive data'],
    ['cpio', r'cpio archive'],
    ['gzip', r'^gzip compressed data'],
    ['iso', r'ISO 9660'],
    ['lzma', r'^LZMA compressed data'],
    ['rar', r'^rar archive data'],
    ['tar', r'^(GNU|POSIX) tar archive'],
    ['ar', r'ar archive'],
    ['xz', r'^XZ compressed data'],
    ['zip', r'^zip archive data'],
    ['tcpdump', r'^tcpdump'],
    ['pdf', r'^pdf document'],
    ['bmp', r'^pc bitmap'],
    ['gif', r'^gif image data'],
    ['jpg', r'^jpeg image data'],
    ['png', r'^png image data'],
    ['installer/windows', r'(Installation Database|Windows Installer)'],
    ['office/excel', r'Microsoft.*Excel'],
    ['office/powerpoint', r'Microsoft.*PowerPoint'],
    ['office/word', r'Microsoft.*Word'],
    ['office/rtf', r'Rich Text Format'],
    ['office/ole', r'OLE 2'],
    ['office/unknown', r'Composite Document File|CDFV2'],
    ['office/unknown', r'Microsoft.*(OOXML|Document)'],
    ['office/unknown', r'Number of (Characters|Pages|Words)'],
    ['flash', r'Macromedia Flash'],
    ['autorun', r'microsoft windows autorun'],
    ['batch', r'dos batch file'],
    ['jar', r'[ (]Jar[) ]'],
    ['java', r'java program'],
    ['class', r'java class data'],
    ['perl', r'perl .*script'],
    ['php', r'php script'],
    ['python', r'python .*(script|byte)'],
    ['shell', r'(shell|sh) script'],
    ['xml', r'OpenGIS KML'],
    ['html', r'html'],
    ['sgml', r'sgml'],
    ['xml', r'xml'],
    ['sff', r'Frame Format'],
    ['shortcut/windows', r'^MS Windows shortcut'],
    ['email', r'Mime entity text'],
    ['sysmon', r'MS Windows Vista Event Log'],
]

sl_patterns = [[x[0], re.compile(x[1], re.IGNORECASE)] for x in sl_patterns]

sl_to_tl = {
    'windows/com': 'executable',
    'windows/dos': 'executable',
    'windows/pe32': 'executable',
    'windows/pe64': 'executable',
    'windows/dll32': 'executable',
    'windows/dll64': 'executable',
    'linux/elf32': 'executable',
    'linux/elf64': 'executable',
    'linux/so32': 'executable',
    'linux/so64': 'executable',
    'mach-o': 'executable',
    '7-zip': 'archive',
    'bzip2': 'archive',
    'cabinet': 'archive',
    'gzip': 'archive',
    'iso': 'archive',
    'rar': 'archive',
    'tar': 'archive',
    'zip': 'archive',
    'tcpdump': 'network',
    'pdf': 'document',
    'bmp': 'image',
    'gif': 'image',
    'jpg': 'image',
    'png': 'image',
    'shortcut/windows': 'meta',
}

# pylint:disable=C0301
tl_patterns = [
    ['document',
     r'Composite Document File|CDFV2|Corel|OLE 2|OpenDocument |Rich Text Format|Microsoft.*'
     r'(Document|Excel|PowerPoint|Word|OOXML)|Number of (Characters|Pages|Words)'],
    ['document', r'PostScript|pdf|MIME entity text'],
    ['java', r'jar |java'],
    ['code',
     r'Autorun|HTML |KML |LLVM |SGML |Visual C|XML |awk|batch |bytecode|perl|php|program|python'
     r'|ruby|scheme|script text exe|shell script|tcl'],
    ['network', r'capture'],
    ['unknown', r'CoreFoundation|Dreamcast|KEYBoard|OSF/Rose|Zope|quota|uImage'],
    ['unknown', r'disk|file[ ]*system|floppy|tape'],
    ['audiovisual',
     r'Macromedia Flash|Matroska|MIDI data|MPEG|MP4|MPG|MP3|QuickTime|RIFF|WebM|animation|audio|movie|music|ogg'
     r'|sound|tracker|video|voice data'],
    ['executable', r'803?86|COFF|ELF|Mach-O|ia32|executable|kernel|library|libtool|object'],
    ['unknown', r'Emulator'],
    ['image', r'DjVu|Surface|XCursor|bitmap|cursor|color|font|graphics|icon|image|jpeg'],
    ['archive',
     r'BinHex|InstallShield CAB|Transport Neutral Encapsulation Format|archive data|compress|mcrypt'
     r'|MS Windows HtmlHelp Data|current ar archive|cpio archive|ISO 9660'],
    ['meta', r'^MS Windows shortcut'],
    ['metadata', r'MS Windows Vista Event Log'],
    ['unknown', r'.*'],
]

trusted_mimes = {
    'application/x-bittorrent': 'meta/torrent',
    'application/x-tar': 'archive/tar',
    'message/rfc822': 'document/email',
    'text/calendar': 'text/calendar',
    'image/svg+xml': 'image/svg',
    'application/x-mach-binary': 'executable/mach-o',
    'application/vnd.ms-outlook': 'document/office/email'
}

tl_patterns = [[x[0], re.compile(x[1], re.IGNORECASE)] for x in tl_patterns]

custom = re.compile(r'^custom: ', re.IGNORECASE)

ssdeep_from_file = None

magic_lock = None
file_type = None
mime_type = None

if platform.system() != 'Windows':
    magic_lock = threading.Lock()

    file_type = magic.magic_open(magic.MAGIC_CONTINUE + magic.MAGIC_RAW)
    magic.magic_load(file_type, constants.RULE_PATH)

    mime_type = magic.magic_open(magic.MAGIC_CONTINUE + magic.MAGIC_RAW + magic.MAGIC_MIME)
    magic.magic_load(mime_type, constants.RULE_PATH)
    ssdeep_from_file = ssdeep.hash_from_file


# Translate the match object into a sub-type label.
def subtype(label: str) -> str:
    for entry in sl_patterns:
        if entry[1].search(label):  # pylint: disable=E1101
            return entry[0]

    return 'unknown'


def ident(buf, length: int, path) -> Dict:
    data = {'ascii': None, 'hex': None, 'magic': None, 'mime': None, 'type': 'unknown'}

    if length <= 0:
        return data

    header = buf[:min(64, length)]
    data['ascii'] = dotdump(header)
    data['hex'] = safe_str(hexlify(header))

    # noinspection PyBroadException
    try:
        # Loop over the labels returned by libmagic, ...
        labels = []
        if file_type:
            with magic_lock:
                labels = magic.magic_file(file_type, path).split(b'\n')
                labels = [label[2:].strip() if label.startswith(b'- ') else label.strip() for label in labels]

        mimes = []
        if mime_type:
            with magic_lock:
                mimes = magic.magic_file(mime_type, path).split(b'\n')
                mimes = [mime[2:].strip() if mime.startswith(b'- ') else mime.strip() for mime in mimes]

        # For user feedback set the mime and magic meta data to always be the primary
        # libmagic responses
        if len(labels) > 0:
            data['magic'] = safe_str(labels[0])

        if len(mimes) > 0 and mimes[0] != b'':
            data['mime'] = safe_str(mimes[0])

        # Highest priority is given to mime type matching something
        tagged = False

        for label in labels:
            label = dotdump(label)

            if custom.match(label):
                data['type'] = label.split('custom: ')[1].strip()
                tagged = True
                break

        # Second priority is mime times marked as trusted
        if not tagged:
            for mime in mimes:
                mime = dotdump(mime)

                if mime in trusted_mimes:
                    data['type'] = trusted_mimes[mime]
                    tagged = True
                    break

        # As a third priority try matching the tl_patterns
        if not tagged:
            minimum = len(tl_patterns)
            sl_tag = None

            # Try each label and see how far down the tl_patterns list we go
            # before we hit a match, the closer to the beginning of the list we are the better
            # the tag match is. The final line of tl_patterns matches anything and sets
            # tag to 'unknown', so this loop should never finish with sl_tag as None
            # Unless the tl_patters table has been changed inappropriately
            for label in labels:
                label = dotdump(label)

                # ... match against our patterns and, ...
                index = 0
                for entry in tl_patterns:
                    if index >= minimum:
                        break

                    if entry[1].search(label):  # pylint:disable=E1101
                        break

                    index += 1

                # ... keep highest precedence (lowest index) match.
                if index < minimum:
                    minimum = index
                    sl_tag = subtype(label)

                    # If a label does match, take the best from that label
                    # Further labels from magic are probably terrible
                    break

            assert sl_tag is not None, "tl_patterns seems to be missing a match all => unknown rule at the end"

            # Based on the sub tag we found, figure out the top level tag to use
            tl_tag = sl_to_tl.get(sl_tag, tl_patterns[minimum][0])
            data['type'] = '/'.join((tl_tag, sl_tag))

    except Exception as e:
        print(str(e))
        pass

    if not recognized.get(data['type'], False):
        data['type'] = 'unknown'

    if data['type'] == 'document/office/unknown':
        # noinspection PyBroadException
        try:
            root_entry_property_offset = buf.find(u"Root Entry".encode("utf-16-le"))
            if -1 != root_entry_property_offset:
                # Get root entry's GUID and try to guess document type
                clsid_offset = root_entry_property_offset + 0x50
                if len(buf) >= clsid_offset + 16:
                    clsid = buf[clsid_offset:clsid_offset + 16]
                    if len(clsid) == 16 and clsid != b"\0" * len(clsid):
                        clsid_str = uuid.UUID(bytes_le=clsid)
                        clsid_str = clsid_str.urn.rsplit(':', 1)[-1].upper()
                        if clsid_str in OLE_CLSID_GUIDs:
                            data['type'] = OLE_CLSID_GUIDs[clsid_str]
                    else:
                        bup_details_offset = buf[:root_entry_property_offset+0x100].find(u"Details".encode("utf-16-le"))
                        if -1 != bup_details_offset:
                            data['type'] = 'quarantine/mcafee'
        except Exception:
            pass

    return data


def _confidence(score: Union[int, float]) -> str:
    conf = float(score) / float(STRONG_SCORE * 5)
    conf = min(1.0, conf) * 100
    return str(int(conf)) + r'%'


def _differentiate(lang: str, scores_map: Dict) -> str:
    if lang == 'code/javascript':
        jscript_score = scores_map['code/jscript']
        pdfjs_score = scores_map['code/pdfjs']
        if pdfjs_score > 0 and pdfjs_score > jscript_score:
            return 'code/pdfjs'
        elif jscript_score > 0:
            return 'code/jscript'

    return lang


# Pass a filepath and this will return the guessed language in the AL tag format.
def guess_language(path: str) -> Tuple[str, Union[str, int]]:
    file_length = os.path.getsize(path)
    with open(path, 'rb') as fh:
        if file_length > 131070:
            buf = fh.read(65535)
            fh.seek(file_length - 65535)
            buf += fh.read(65535)
        else:
            buf = fh.read()

    scores = defaultdict(int)
    shebang_lang = re.match(SHEBANG, buf)
    if shebang_lang:
        lang = shebang_lang.group(1)
        lang = 'code/' + EXECUTABLES.get(safe_str(lang), safe_str(lang))
        scores[lang] = STRONG_SCORE * 3

    for lang, patterns in STRONG_INDICATORS.items():
        for pattern in patterns:
            for _ in re.findall(pattern, buf):
                scores[lang] += STRONG_SCORE

    for lang, pattern in WEAK_INDICATORS.items():
        for _ in re.findall(pattern, buf):
            scores[lang] += WEAK_SCORE

    for lang in list(scores.keys()):
        if scores[lang] < MINIMUM_GUESS_SCORE:
            scores.pop(lang)

    max_v = 0
    if len(scores) > 0:
        max_v = max(list(scores.values()))
    high_scores = [(k, v) for k, v in scores.items() if v == max_v]
    high_scores = [(_differentiate(k, scores), v) for k, v in high_scores]

    if len(high_scores) != 1:
        return 'unknown', 0
    else:
        confidences = [(k, _confidence(v)) for k, v in high_scores]
        return confidences[0]


# noinspection PyBroadException
def zip_ident(path: str, fallback: str = None) -> str:
    file_list = []

    try:
        with zipfile.ZipFile(path, "r") as zf:
            file_list = [zfname for zfname in zf.namelist()]
    except Exception:
        try:
            stdout, _ = subprocess.Popen(["unzip", "-l", path],
                                         stderr=subprocess.PIPE,
                                         stdout=subprocess.PIPE).communicate()
            lines = stdout.splitlines()
            index = lines[1].index(b"Name")
            for file_name in lines[3:-2]:
                file_list.append(safe_str(file_name[index:]))
        except Exception:
            if fallback is not None:
                return fallback

    tot_files = 0
    tot_class = 0
    tot_jar = 0

    is_ipa = False
    is_jar = False
    is_word = False
    is_excel = False
    is_ppt = False
    doc_props = False
    doc_rels = False
    doc_types = False
    android_manifest = False
    android_dex = False

    for file_name in file_list:
        if file_name[:8] == 'META-INF' and file_name[9:] == 'MANIFEST.MF':
            is_jar = True
        elif file_name == 'AndroidManifest.xml':
            android_manifest = True
        elif file_name == 'classes.dex':
            android_dex = True
        elif file_name.startswith('Payload/') and file_name.endswith(".app/Info.plist"):
            is_ipa = True
        elif file_name.endswith(".class"):
            tot_class += 1
        elif file_name.endswith(".jar"):
            tot_jar += 1
        elif file_name.startswith('word/'):
            is_word = True
        elif file_name.startswith('xl/'):
            is_excel = True
        elif file_name.startswith('ppt/'):
            is_ppt = True
        elif file_name.startswith('docProps/'):
            doc_props = True
        elif file_name.startswith('_rels/'):
            doc_rels = True
        elif file_name == '[Content_Types].xml':
            doc_types = True

        tot_files += 1

    if 0 < tot_files < (tot_class + tot_jar) * 2:
        is_jar = True

    if is_jar and android_manifest and android_dex:
        return 'android/apk'
    elif is_ipa:
        return 'ios/ipa'
    elif is_jar:
        return 'java/jar'
    elif (doc_props or doc_rels) and doc_types:
        if is_word:
            return 'document/office/word'
        elif is_excel:
            return 'document/office/excel'
        elif is_ppt:
            return 'document/office/powerpoint'
        else:
            return 'document/office/unknown'
    else:
        return 'archive/zip'


# noinspection PyBroadException
def cart_ident(path: str) -> str:
    try:
        metadata = get_metadata_only(path)
    except Exception:
        return 'corrupted/cart'
    return metadata.get('al', {}).get('type', 'archive/cart')


def dos_ident(path: str) -> str:
    # noinspection PyBroadException
    try:
        with open(path, "rb") as fh:
            file_header = fh.read(0x40)
            if file_header[0:2] != "MZ":
                raise ValueError()

            header_pos, = struct.unpack("<I", file_header[-4:])
            fh.seek(header_pos)
            if fh.read(4) != "PE\x00\x00":
                raise ValueError()
            machine_id, = struct.unpack("<H", fh.read(2))
            if machine_id == 0x014c:
                width = 32
            elif machine_id == 0x8664:
                width = 64
            else:
                raise ValueError()
            characteristics, = struct.unpack("<H", fh.read(18)[-2:])
            if characteristics & 0x2000:
                pe_type = "dll"
            elif characteristics & 0x0002:
                pe_type = "pe"
            else:
                raise ValueError()
            return "executable/windows/%s%i" % (pe_type, width)
    except Exception:
        pass
    return "executable/windows/dos"


def fileinfo(path: str) -> Dict:
    path = safe_str(path)

    data = get_digests_for_file(path, on_first_block=ident)

    # This is a special case, we know if the mime is set to one of these values
    # then the input file is almost certainly an office file, but based on only the first
    # block magic can't figure out any more than that. To handle that case we will read the
    # entire file, and identify again.
    if data['mime'] is not None and data['mime'].lower() in ['application/cdfv2-corrupt', 'application/cdfv2-unknown']:
        with open(path, 'rb') as fh:
            buf = fh.read()
            buflen = len(buf)
            data.update(ident(buf, buflen))
    data['ssdeep'] = ssdeep_from_file(path) if ssdeep_from_file else ''

    # When data is parsed from a cart file we trust its metatdata and can skip the recognition test later
    cart_metadata_set = False

    if not int(data.get('size', -1)):
        data['type'] = 'empty'
    elif data['type'] in ['archive/zip', 'java/jar']:
        # In addition to explicit zip files, we also want to run zip_ident when
        # a file is a jar as there is a high rate of false positive (magic
        # matching eclipse and other java related files as jars)
        data['type'] = zip_ident(path)
    elif data['type'] == 'document/office/unknown':
        # For unknown document files try identifying them by unziping,
        # but don't commit to it being a zip if it can't be extracted
        data['type'] = zip_ident(path, data['type'])
    elif data['type'] == 'unknown':
        data['type'], _ = guess_language(path)
    elif data['type'] == 'archive/cart':
        data['type'] = cart_ident(path)
        cart_metadata_set = True
    elif data['type'] == 'executable/windows/dos':
        # The default magic file misidentifies PE files with a munged DOS header
        data['type'] = dos_ident(path)
    elif data['type'] == 'code/html':
        # Magic detects .hta files as .html, guess_language detects .hta files as .js/.vbs
        # If both conditions are met, it's fair to say that the file is an .hta
        lang, _ = guess_language(path)
        if lang in ["code/javascript", "code/vbs"]:
            data['type'] = 'code/hta'

    if data['type'] in ['document/office/word', 'document/office/excel',
                        'document/office/powerpoint', 'document/office/unknown']:
        try:
            msoffcrypto_obj = msoffcrypto.OfficeFile(open(path, "rb"))
            if msoffcrypto_obj and msoffcrypto_obj.is_encrypted():
                data['type'] = 'document/office/passwordprotected'
        except Exception:
            # If msoffcrypto can't handle the file to confirm that it is/isn't password protected,
            # then it's not meant to be. Moving on!
            pass

    if not recognized.get(data['type'], False) and not cart_metadata_set:
        data['type'] = 'unknown'

    return data


if __name__ == '__main__':
    from pprint import pprint

    # noinspection PyBroadException
    if len(sys.argv) > 1:
        pprint(fileinfo(sys.argv[1]))
    else:
        name = sys.stdin.readline().strip()
        while name:
            a = fileinfo(name)
            print('\t'.join(dotdump(str(a[k])) for k in ('type', 'ascii',
                                                         'entropy', 'hex', 'magic',
                                                         'mime', 'md5', 'sha1', 'sha256',
                                                         'ssdeep', 'size')))
            name = sys.stdin.readline().strip()
