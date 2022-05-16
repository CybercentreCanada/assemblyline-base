import logging
import magic
import msoffcrypto
import platform
import re
import ssdeep
import struct
import subprocess
import sys
import threading
import uuid
import yara
import zipfile

from binascii import hexlify
from cart import get_metadata_only
from typing import Tuple, Union, Dict

from assemblyline.common.digests import get_digests_for_file
from assemblyline.common.forge import get_constants, get_identify_paths
from assemblyline.common.str_utils import dotdump, safe_str

constants = get_constants()
LOGGER = logging.getLogger('assemblyline.identify')

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
    "00020D0B-0000-0000-C000-000000000046": "document/office/email",  # "MailMessage"
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

tag_to_extension = {
    "archive/chm": ".chm",
    "audiovisual/flash": ".swf",
    "code/batch": ".bat",
    "code/c": ".c",
    "code/csharp": ".cs",
    "code/hta": ".hta",
    "code/html": ".html",
    "code/java": ".java",
    "code/javascript": ".js",
    "code/jscript": ".js",
    "code/pdfjs": ".js",
    "code/perl": ".pl",
    "code/php": ".php",
    "code/ps1": ".ps1",
    "code/python": ".py",
    "code/ruby": ".rb",
    "code/vbs": ".vbs",
    "code/wsf": ".wsf",
    "document/installer/windows": ".msi",
    "document/office/excel": ".xls",
    "document/office/mhtml": ".mhtml",
    "document/office/ole": ".doc",
    "document/office/powerpoint": ".ppt",
    "document/office/rtf": ".doc",
    "document/office/unknown": ".doc",
    "document/office/visio": ".vsd",
    "document/office/word": ".doc",
    "document/office/wordperfect": "wp",
    "document/office/wordpro": "lwp",
    "document/office/onenote": ".one",
    "document/pdf": ".pdf",
    "document/email": ".eml",
    "executable/windows/pe32": ".exe",
    "executable/windows/pe64": ".exe",
    "executable/windows/dll32": ".dll",
    "executable/windows/dll64": ".dll",
    "executable/windows/dos": ".exe",
    "executable/windows/com": ".exe",
    "executable/linux/elf32": ".elf",
    "executable/linux/elf64": ".elf",
    "executable/linux/so32": ".so",
    "executable/linux/so64": ".so",
    "java/jar": ".jar",
    "silverlight/xap": ".xap",
    "shortcut/windows": ".lnk",
}

magic_patterns = [
    ["network/tnef", r"Transport Neutral Encapsulation Format"],
    ["archive/chm", r"MS Windows HtmlHelp Data"],
    ["executable/windows/dll64", r"pe32\+[^\|]+dll[^\|]+x86\-64"],
    ["executable/windows/pe64", r"pe32\+[^\|]+x86\-64[^\|]+windows"],
    ["executable/windows/ia/dll64", r"pe32\+?[^\|]+dll[^\|]+Intel Itanium[^\|]+windows"],
    ["executable/windows/ia/pe64", r"pe32\+?[^\|]+Intel Itanium[^\|]+windows"],
    ["executable/windows/arm/dll64", r"pe32\+?[^\|]+dll[^\|]+Aarch64[^\|]+windows"],
    ["executable/windows/arm/pe64", r"pe32\+?[^\|]+Aarch64[^\|]+windows"],
    ["executable/windows/dll64", r"pe32\+[^\|]+dll[^\|]+windows"],
    ["executable/windows/pe64", r"pe32\+[^\|]+windows"],
    ["executable/windows/dll32", r"pe32[^\|]+dll"],
    ["executable/windows/pe32", r"pe32[^\|]+windows"],
    ["executable/windows/pe", r"pe unknown[^\|]+windows"],
    ["executable/windows/dos", r"(ms-)?dos executable"],
    ["executable/windows/com", r"^com executable"],
    ["executable/windows/dos", r"^8086 relocatable"],
    ["executable/windows/coff", r"^MS Windows COFF"],
    ["executable/linux/elf32", r"^elf 32-bit (l|m)sb +executable"],
    ["executable/linux/elf64", r"^elf 64-bit (l|m)sb +(pie )?executable"],
    ["executable/linux/so32", r"^elf 32-bit (l|m)sb +shared object"],
    ["executable/linux/so64", r"^elf 64-bit (l|m)sb +shared object"],
    ["executable/linux/coff32", r"^(Intel 80386|i386|80386) COFF"],
    ["executable/linux/coff64", r"^64-bit XCOFF"],
    ["executable/linux/ia/coff64", r"^Intel ia64 COFF"],
    ["executable/linux/misp/ecoff", r"^MIPS[^\|]+ ECOFF"],
    ["executable/linux/a.out", r"^a.out"],
    ["executable/mach-o", r"^Mach-O"],
    ["archive/7-zip", r"^7-zip archive data"],
    ["archive/ace", r"^ACE archive data"],
    ["archive/bzip2", r"^bzip2 compressed data"],
    ["archive/cabinet", r"^installshield cab"],
    ["archive/cabinet", r"^microsoft cabinet archive data"],
    ["archive/cpio", r"cpio archive"],
    ["archive/gzip", r"^gzip compressed data"],
    ["archive/iso", r"ISO 9660"],
    ["archive/lzma", r"^LZMA compressed data"],
    ["archive/rar", r"^rar archive data"],
    ["archive/tar", r"^(GNU|POSIX) tar archive"],
    ["archive/ar", r"ar archive"],
    ["archive/xz", r"^XZ compressed data"],
    ["archive/zip", r"^zip archive data"],
    ["network/tcpdump", r"^(tcpdump|pcap)"],
    ["document/pdf", r"^pdf document"],
    ["image/bmp", r"^pc bitmap"],
    ["image/gif", r"^gif image data"],
    ["image/jpg", r"^jpeg image data"],
    ["image/png", r"^png image data"],
    ["image/webp", r"Web/P image"],
    ["document/installer/windows", r"(Installation Database|Windows Installer)"],
    ["document/office/excel", r"Microsoft[^\|]+Excel"],
    ["document/office/powerpoint", r"Microsoft.*PowerPoint"],
    ["document/office/word", r"Microsoft[^\|]+Word"],
    ["document/office/rtf", r"Rich Text Format"],
    ["document/office/ole", r"OLE 2"],
    ["document/office/hwp", r"Hangul \(Korean\) Word Processor File"],
    ["document/office/unknown", r"Composite Document File|CDFV2"],
    ["document/office/unknown", r"Microsoft[^\|]+(OOXML|Document)"],
    ["document/office/unknown", r"Number of (Characters|Pages|Words)"],
    ["audiovisual/flash", r"Macromedia Flash"],
    ["code/autorun", r"microsoft windows autorun"],
    ["code/batch", r"dos batch file"],
    ["java/jar", r"[ (]Jar[) ]"],
    ["java/class", r"java class data"],
    ["resource/pyc", r"python [^\|]+byte"],
    ["code/xml", r"OpenGIS KML"],
    ["code/xml", r"xml"],
    ["image/tim", r"TIM image"],
    ["network/sff", r"Frame Format"],
    ["shortcut/windows", r"^MS Windows shortcut"],
    ["document/email", r"Mime entity text"],
    ["metadata/sysmon/evt", r"MS Windows Vista Event Log"],
    ["image/emf", r"Windows Enhanced Metafile"],
    ["resource/msvc", r"MSVC \.res"],
]

magic_patterns = [[x[0], re.compile(x[1], re.IGNORECASE)] for x in magic_patterns]

trusted_mimes = {
    # Mpeg Audio
    "audio/mp2": "audio/mp2",
    "audio/x-mp2": "audio/mp2",
    "audio/mpeg": "audio/mp3",
    "audio/mp3": "audio/mp3",
    "audio/mpg": "audio/mp3",
    "audio/x-mpeg": "audio/mp3",
    "audio/x-mp3": "audio/mp3",
    "audio/x-mpg": "audio/mp3",
    "audio/x-mp4a-latm": "audio/mp4",
    "audio/x-m4a": "audio/mp4",
    "audio/m4a": "audio/mp4",
    # Wav Audio
    "audio/x-wav": "audio/wav",
    "audio/wav": "audio/wav",
    "audio/vnd.wav": "audio/wav",
    # Ogg Audio
    "audio/ogg": "audio/ogg",
    "audio/x-ogg": "audio/ogg",
    # S3M Audio
    "audio/s3m": "audio/s3m",
    "audio/x-s3m": "audio/s3m",
    # MIDI Audio
    "audio/midi": "audio/midi",
    "audio/x-midi": "audio/midi",
    # Mpeg video
    "video/mp4": "video/mp4",
    # Avi video
    "video/x-msvideo": "video/avi",
    "video/x-avi": "video/avi",
    "video/avi": "video/avi",
    "video/msvideo": "video/avi",
    # Divx video
    "video/divx": "video/divx",
    "video/vnd.divx": "video/divx",
    # Quicktime video
    "video/quicktime": "video/quicktime",
    # Source code C/C++
    "text/x-c++": "text/plain",
    "text/x-c": "text/plain",
    # Configuration file
    "application/x-wine-extension-ini": "text/ini",
    # Python
    "text/x-python": "code/python",
    # PHP
    "text/x-php": "code/php",
    # XML file
    "text/xml": "code/xml",
    # HTML file
    "text/html": "text/plain",
    # Shell script
    "text/x-shellscript": "code/shell",
    # RTF
    "text/rtf": "document/office/rtf",
    # Java
    "text/x-java": "code/java",
    # Batch
    "text/x-msdos-batch": "code/batch",

    # JSON file
    "application/json": "text/json",

    # Autorun files
    "application/x-setupscript": "code/autorun",
    # Bittorrent files
    "application/x-bittorrent": "application/torrent",
    "application/x-torrent": "application/torrent",
    # Database files
    "application/x-dbf": "db/dbf",
    "application/x-sqlite3": "db/sqlite",
    # Font
    "application/vnd.ms-opentype": "resource/font/opentype",
    "application/x-font-sfn": "resource/font/x11",

    # Image Icon
    "image/vnd.microsoft.icon": "image/icon",
    "application/ico": "image/icon",
    "image/ico": "image/icon",
    "image/icon": "image/icon",
    "image/x-ico": "image/icon",
    "image/x-icon": "image/icon",
    "text/ico": "image/icon",
    "image/x-icns": "image/icon",
    # Image gif
    "image/gif": "image/gif",
    # Image WebP
    "image/webp": "image/webp",
    # Image BMP
    "image/bmp": "image/bmp",
    "image/x-bmp": "image/bmp",
    "image/x-ms-bmp": "image/bmp",
    # Image metafile
    "image/wmf": "image/wmf",
    # Image SVG
    "image/svg": "image/svg",
    "image/svg+xml": "image/svg",
    # Image JPEG
    "image/jpeg": "image/jpg",
    "image/pjpeg": "image/jpg",
    # Image PNG
    "image/png": "image/png",
    # Image TGA
    "image/x-tga": "image/tga",
    "image/x-icb": "image/tga",
    # Image Cursor
    "image/x-win-bitmap": "image/cursor",

    # Office Outlook email
    "application/vnd.ms-outlook": "document/office/email",
    # Office Powerpoint
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "document/office/powerpoint",
    "application/vnd.ms-powerpoint": "document/office/powerpoint",
    # Office Excel
    "application/vnd.ms-excel": "document/office/excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "document/office/excel",
    # Office Word
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "document/office/word",
    "application/msword": "document/office/word",
    # Office encrypted docs
    "application/encrypted": "document/office/passwordprotected",
    # MSI file
    "application/vnd.ms-msi": "document/installer/windows",
    # PDF Document
    "application/pdf": "document/pdf",
    # Postscript document
    "application/postscript": "document/ps",
    # Open Document files
    "application/vnd.oasis.opendocument.chart": "document/odt/chart",
    "application/vnd.oasis.opendocument.chart-template": "document/odt/chart",
    "application/vnd.oasis.opendocument.database": "db/odt",
    "application/vnd.oasis.opendocument.formula": "document/odt/formula",
    "application/vnd.oasis.opendocument.formula-template": "document/odt/formula",
    "application/vnd.oasis.opendocument.graphics": "document/odt/graphics",
    "application/vnd.oasis.opendocument.graphics-flat-xml": "document/odt/graphics",
    "application/vnd.oasis.opendocument.graphics-template": "document/odt/graphics",
    "application/vnd.oasis.opendocument.presentation": "document/odt/presentation",
    "application/vnd.oasis.opendocument.presentation-flat-xml": "document/odt/presentation",
    "application/vnd.oasis.opendocument.presentation-template": "document/odt/presentation",
    "application/vnd.oasis.opendocument.spreadsheet": "document/odt/spreadsheet",
    "application/vnd.oasis.opendocument.spreadsheet-flat-xml": "document/odt/spreadsheet",
    "application/vnd.oasis.opendocument.spreadsheet-template": "document/odt/spreadsheet",
    "application/vnd.oasis.opendocument.text": "document/odt/text",
    "application/vnd.oasis.opendocument.text-flat-xml": "document/odt/text",
    "application/vnd.oasis.opendocument.text-template": "document/odt/text",
    "application/vnd.oasis.opendocument.text-master": "document/odt/text",
    "application/vnd.oasis.opendocument.text-master-template": "document/odt/text",
    "application/vnd.oasis.opendocument.web": "document/odt/web",

    # Archives
    "application/x-7z-compressed": "archive/7-zip",
    "application/x-tar": "archive/tar",
    "application/x-tarapplication/x-dbt": "archive/tar",
    "application/gzip": "archive/gzip",
    "application/vnd.ms-tnef": "archive/tnef",
    "application/x-cpio": "archive/cpio",
    "application/x-archive": "archive/ar",
    "application/zip": "archive/zip",
    "application/zlib": "archive/zlib",
    "application/x-arj": "archive/arj",
    "application/x-lzip": "archive/lzip",
    "application/x-lzh-compressed": "archive/lzh",
    "application/x-ms-compress-szdd": "archive/szdd",
    "application/x-arc": "archive/arc",
    "application/x-iso9660-image": "archive/iso",
    "application/x-rar": "archive/rar",
    "application/x-xz": "archive/xz",
    "application/vnd.ms-cab-compressed": "archive/cabinet",

    # JAVA Class
    "application/x-java-applet": "java/class",

    # Packet capture
    "application/vnd.tcpdump.pcap": "network/tcpdump",

    "message/rfc822": "document/email",
    "text/calendar": "text/calendar",
    "application/x-mach-binary": "executable/mach-o",
    "application/x-iso9660-image": "archive/iso",
    "application/x-gettext-translation": "resource/mo",
    "application/x-hwp": "document/office/hwp",
    "application/vnd.iccprofile": "metadata/iccprofile",
    "application/vnd.lotus-1-2-3": "document/lotus/spreadsheet",

    # Firefox modules
    "application/x-xpinstall": "application/mozilla/extension",
    # Chrome extensions
    "application/x-chrome-extension": "application/chrome/extension"
}

custom = re.compile(r"^custom: ", re.IGNORECASE)

ssdeep_from_file = None
magic_lock = None
file_type = None
mime_type = None

magic_file, yara_file = get_identify_paths()

if platform.system() != "Windows":
    magic_lock = threading.Lock()

    file_type = magic.magic_open(magic.MAGIC_CONTINUE + magic.MAGIC_RAW)
    magic.magic_load(file_type, magic_file)

    mime_type = magic.magic_open(
        magic.MAGIC_CONTINUE + magic.MAGIC_RAW + magic.MAGIC_MIME
    )
    magic.magic_load(mime_type, magic_file)
    ssdeep_from_file = ssdeep.hash_from_file

yara_default_externals = {'mime': '', 'magic': '', 'type': ''}
yara_rules = yara.compile(filepaths={"default": yara_file}, externals=yara_default_externals)


def ident(buf, length: int, path) -> Dict:
    data = {"ascii": None, "hex": None, "magic": None, "mime": None, "type": "unknown"}

    if length <= 0:
        return data

    header = buf[: min(64, length)]
    data["ascii"] = dotdump(header)
    data["hex"] = safe_str(hexlify(header))

    # noinspection PyBroadException
    try:
        # Loop over the labels returned by libmagic, ...
        labels = []
        if file_type:
            with magic_lock:
                try:
                    labels = magic.magic_file(file_type, path).split(b"\n")
                except magic.MagicException as me:
                    labels = me.message.split(b"\n")
                labels = [
                    label[2:].strip() if label.startswith(b"- ") else label.strip()
                    for label in labels
                ]

        mimes = []
        if mime_type:
            with magic_lock:
                try:
                    mimes = magic.magic_file(mime_type, path).split(b"\n")
                except magic.MagicException as me:
                    mimes = me.message.split(b"\n")
                mimes = [
                    mime[2:].strip() if mime.startswith(b"- ") else mime.strip()
                    for mime in mimes
                ]

        # For user feedback set the mime and magic meta data to always be the primary
        # libmagic responses
        if len(labels) > 0:

            def find_special_words(word, labels):
                for index, label in enumerate(labels):
                    if word in label:
                        return index
                return -1

            # If an expected label is not the first label returned by Magic, then make it so
            # Manipulating the mime accordingly varies between special word cases
            special_word_cases = [
                (b"OLE 2 Compound Document : Microsoft Word Document", False),
                (b"Lotus 1-2-3 WorKsheet", True),
            ]
            for word, alter_mime in special_word_cases:
                index = find_special_words(word, labels)
                if index >= 0:
                    labels.insert(0, labels.pop(index))
                    if len(labels) == len(mimes) and alter_mime:
                        mimes.insert(0, mimes.pop(index))
            data["magic"] = safe_str(labels[0])

        for mime in mimes:
            if mime != b"":
                data["mime"] = safe_str(mime)
                break

        # First lets try to find any custom types
        for label in labels:
            label = dotdump(label)

            if custom.match(label):
                data["type"] = label.split("custom: ")[1].strip()
                break

        # Second priority is mime times marked as trusted
        if data["type"] == "unknown":
            for mime in mimes:
                mime = dotdump(mime)

                if mime in trusted_mimes:
                    data["type"] = trusted_mimes[mime]
                    break

        # As a third priority try matching the magic_patterns
        if data["type"] == "unknown":
            found = False
            for label in labels:
                for entry in magic_patterns:
                    if entry[1].search(dotdump(label)):  # pylint: disable=E1101
                        data['type'] = entry[0]
                        found = True
                        break
                if found:
                    break

    except Exception as e:
        LOGGER.error(str(e))
        pass

    # If mime is text/* and type is unknown, set text/plain to trigger
    # language detection later.
    if data["type"] == "unknown" and data['mime'] is not None and data['mime'].startswith("text/"):
        data["type"] = "text/plain"

    # Lookup office documents by GUID if we're still not sure what they are
    if data["type"] == "document/office/unknown":
        # noinspection PyBroadException
        try:
            root_entry_property_offset = buf.find(u"Root Entry".encode("utf-16-le"))
            if -1 != root_entry_property_offset:
                # Get root entry's GUID and try to guess document type
                clsid_offset = root_entry_property_offset + 0x50
                if len(buf) >= clsid_offset + 16:
                    clsid = buf[clsid_offset: clsid_offset + 16]
                    if len(clsid) == 16 and clsid != b"\0" * len(clsid):
                        clsid_str = uuid.UUID(bytes_le=clsid)
                        clsid_str = clsid_str.urn.rsplit(":", 1)[-1].upper()
                        if clsid_str in OLE_CLSID_GUIDs:
                            data["type"] = OLE_CLSID_GUIDs[clsid_str]
                    else:
                        bup_details_offset = buf[
                            : root_entry_property_offset + 0x100
                        ].find(u"Details".encode("utf-16-le"))
                        if -1 != bup_details_offset:
                            data["type"] = "quarantine/mcafee"
        except Exception:
            pass

    return data


def zip_ident(path: str, fallback: str) -> str:
    file_list = []

    try:
        with zipfile.ZipFile(path, "r") as zf:
            file_list = [zfname for zfname in zf.namelist()]
    except Exception:
        try:
            stdout, _ = subprocess.Popen(
                ["unzip", "-l", path], stderr=subprocess.PIPE, stdout=subprocess.PIPE
            ).communicate()
            lines = stdout.splitlines()
            index = lines[1].index(b"Name")
            for file_name in lines[3:-2]:
                file_list.append(safe_str(file_name[index:]))
        except Exception:
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
        if file_name[:8] == "META-INF" and file_name[9:] == "MANIFEST.MF":
            is_jar = True
        elif file_name == "AndroidManifest.xml":
            android_manifest = True
        elif file_name == "classes.dex":
            android_dex = True
        elif file_name.startswith("Payload/") and file_name.endswith(".app/Info.plist"):
            is_ipa = True
        elif file_name.endswith(".class"):
            tot_class += 1
        elif file_name.endswith(".jar"):
            tot_jar += 1
        elif file_name.startswith("word/"):
            is_word = True
        elif file_name.startswith("xl/"):
            is_excel = True
        elif file_name.startswith("ppt/"):
            is_ppt = True
        elif file_name.startswith("docProps/"):
            doc_props = True
        elif file_name.startswith("_rels/"):
            doc_rels = True
        elif file_name == "[Content_Types].xml":
            doc_types = True

        tot_files += 1

    if 0 < tot_files < (tot_class + tot_jar) * 2:
        is_jar = True

    if is_jar and android_manifest and android_dex:
        return "android/apk"
    elif is_ipa:
        return "ios/ipa"
    elif is_jar:
        return "java/jar"
    elif (doc_props or doc_rels) and doc_types:
        if is_word:
            return "document/office/word"
        elif is_excel:
            return "document/office/excel"
        elif is_ppt:
            return "document/office/powerpoint"
        else:
            return "document/office/unknown"
    else:
        return "archive/zip"


# noinspection PyBroadException
def cart_ident(path: str) -> str:
    try:
        metadata = get_metadata_only(path)
    except Exception:
        return "corrupted/cart"
    return metadata.get("al", {}).get("type", "archive/cart")


def dos_ident(path: str) -> str:
    # noinspection PyBroadException
    try:
        with open(path, "rb") as fh:
            file_header = fh.read(0x40)
            if file_header[0:2] != b"MZ":
                raise ValueError()

            (header_pos,) = struct.unpack("<I", file_header[-4:])
            fh.seek(header_pos)
            if fh.read(4) != b"PE\x00\x00":
                raise ValueError()
            (machine_id,) = struct.unpack("<H", fh.read(2))
            if machine_id == 0x014C:
                width = 32
            elif machine_id == 0x8664:
                width = 64
            else:
                raise ValueError()
            (characteristics,) = struct.unpack("<H", fh.read(18)[-2:])
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


def yara_ident(path: str, info: Dict, fallback="unknown") -> Tuple[str, Union[str, int]]:
    externals = {k: v or "" for k, v in info.items() if k in yara_default_externals}
    try:
        matches = yara_rules.match(path, externals=externals, fast=True)
        matches.sort(key=lambda x: x.meta.get('score', 0), reverse=True)
        for match in matches:
            return match.meta['type']
    except Exception as e:
        LOGGER.warning(f"Yara file identifier failed with error: {str(e)}")
        matches = []

    return fallback


def fileinfo(path: str) -> Dict:
    path = safe_str(path)
    data = get_digests_for_file(path, on_first_block=ident)
    data["ssdeep"] = ssdeep_from_file(path) if ssdeep_from_file else ""

    # Check if file empty
    if not int(data.get("size", -1)):
        data["type"] = "empty"

    # Futher identify zip files based of their content
    elif data["type"] in ["archive/zip", "java/jar", "document/office/unknown"]:
        data["type"] = zip_ident(path, data["type"])

    # Further check CaRT files, they may have an explicit type set
    elif data["type"] == "archive/cart":
        data["type"] = cart_ident(path)

    # Further identify dos executables has this may be a PE that has been misidentified
    elif data["type"] == "executable/windows/dos":
        data["type"] = dos_ident(path)

    # If we're so far failed to identified the file, lets run the yara rules
    elif "unknown" in data["type"] or data["type"] == "text/plain":
        data["type"] = yara_ident(path, data, fallback=data["type"])

    # Extra checks for office documents
    #  - Check for encryption
    if data["type"] in [
        "document/office/word",
        "document/office/excel",
        "document/office/powerpoint",
        "document/office/unknown",
    ]:
        try:
            msoffcrypto_obj = msoffcrypto.OfficeFile(open(path, "rb"))
            if msoffcrypto_obj and msoffcrypto_obj.is_encrypted():
                data["type"] = "document/office/passwordprotected"
        except Exception:
            # If msoffcrypto can't handle the file to confirm that it is/isn't password protected,
            # then it's not meant to be. Moving on!
            pass

    # Extra checks for PDF documents
    #  - Check for encryption
    #  - Check for PDF collection (portfolio)
    if data["type"] == "document/pdf":
        # Password protected documents typically contain '/Encrypt'
        pdf_content = open(path, "rb").read()
        if re.search(b"/Encrypt", pdf_content):
            data["type"] = "document/pdf/passwordprotected"
        # Portfolios typically contain '/Type/Catalog/Collection
        elif re.search(b"/Type/Catalog/Collection", pdf_content):
            data["type"] = "document/pdf/portfolio"

    return data


if __name__ == "__main__":
    from pprint import pprint

    # noinspection PyBroadException
    if len(sys.argv) > 1:
        pprint(fileinfo(sys.argv[1]))
    else:
        name = sys.stdin.readline().strip()
        while name:
            a = fileinfo(name)
            print(
                "\t".join(
                    dotdump(str(a[k]))
                    for k in (
                        "type",
                        "ascii",
                        "entropy",
                        "hex",
                        "magic",
                        "mime",
                        "md5",
                        "sha1",
                        "sha256",
                        "ssdeep",
                        "size",
                    )
                )
            )
            name = sys.stdin.readline().strip()
