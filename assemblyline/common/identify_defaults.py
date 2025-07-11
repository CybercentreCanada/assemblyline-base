# GUID Used to further identify office documents
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

# Assemblyline type to file extension mapping
type_to_extension = {
    "archive/chm": ".chm",
    "archive/iso": ".iso",
    "archive/rar": ".rar",
    "archive/udf": ".udf",
    "archive/vhd": ".vhd",
    "archive/zip": ".zip",
    "archive/7-zip": ".7z",
    "audiovisual/flash": ".swf",
    "code/a3x": ".a3x",
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
    "code/shell": ".sh",
    "code/vbe": ".vbe",
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
    "executable/web/wasm": ".wasm",
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
    "text/windows/registry": ".reg",
}

# Regex patterns used to find Assemblyline type in the reported magic labels
# Magic bytes translated to possible libmagic labels: https://en.wikipedia.org/wiki/List_of_file_signatures
magic_patterns = [
    {"al_type": "network/tnef", "regex": r"Transport Neutral Encapsulation Format"},
    {"al_type": "archive/chm", "regex": r"MS Windows HtmlHelp Data"},
    {"al_type": "executable/web/wasm", "regex": r"WebAssembly \(wasm\) binary module"},
    {"al_type": "executable/windows/dll64", "regex": r"pe32\+[^\|]+dll[^\|]+x86\-64"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L159
    {"al_type": "executable/windows/dll64", "regex": r"pe32\+[^\|]+dll[^\|]+windows"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L157
    {"al_type": "executable/windows/dll32", "regex": r"pe32[^\|]+dll"},
    {"al_type": "executable/windows/pe64", "regex": r"pe32\+[^\|]+x86\-64[^\|]+windows"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L155
    {"al_type": "executable/windows/pe64", "regex": r"pe32\+[^\|]+windows"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L153
    {"al_type": "executable/windows/pe32", "regex": r"pe32[^\|]+windows"},
    {"al_type": "executable/windows/ia/dll64", "regex": r"pe32\+?[^\|]+dll[^\|]+Intel Itanium[^\|]+windows"},
    {"al_type": "executable/windows/ia/pe64", "regex": r"pe32\+?[^\|]+Intel Itanium[^\|]+windows"},
    {"al_type": "executable/windows/arm/dll64", "regex": r"pe32\+?[^\|]+dll[^\|]+Aarch64[^\|]+windows"},
    {"al_type": "executable/windows/arm/pe64", "regex": r"pe32\+?[^\|]+Aarch64[^\|]+windows"},
    {"al_type": "executable/windows/pe", "regex": r"pe unknown[^\|]+windows"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L183
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L185
    {"al_type": "executable/windows/dos", "regex": r"(ms-)?dos executable"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L187
    {"al_type": "executable/windows/com", "regex": r"^com executable"},
    {"al_type": "executable/windows/dos", "regex": r"^8086 relocatable"},
    {"al_type": "executable/windows/coff", "regex": r"^MS Windows COFF"},
    # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_elf.yara
    {"al_type": "executable/linux/elf32", "regex": r"^elf 32-bit (l|m)sb executable"},
    {"al_type": "executable/linux/elf64", "regex": r"^elf 64-bit (l|m)sb executable"},
    {"al_type": "executable/linux/pie32", "regex": r"^elf 32-bit (l|m)sb pie executable"},
    {"al_type": "executable/linux/pie64", "regex": r"^elf 64-bit (l|m)sb pie executable"},
    {"al_type": "executable/linux/so32", "regex": r"^elf 32-bit (l|m)sb +shared object"},
    {"al_type": "executable/linux/so64", "regex": r"^elf 64-bit (l|m)sb +shared object"},
    {"al_type": "executable/linux/coff32", "regex": r"^(Intel 80386|i386|80386) COFF"},
    {"al_type": "executable/linux/coff64", "regex": r"^64-bit XCOFF"},
    {"al_type": "executable/linux/ia/coff64", "regex": r"^Intel ia64 COFF"},
    {"al_type": "executable/linux/misp/ecoff", "regex": r"^MIPS[^\|]+ ECOFF"},
    {"al_type": "executable/linux/a.out", "regex": r"^a.out"},
    # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_macho.yara
    {"al_type": "executable/mach-o", "regex": r"^Mach-O"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L171
    {"al_type": "archive/7-zip", "regex": r"^7-zip archive data"},
    {"al_type": "archive/ace", "regex": r"^ACE archive data"},
    {"al_type": "archive/asar", "regex": r"^Electron ASAR archive"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L173
    {"al_type": "archive/bzip2", "regex": r"^bzip2 compressed data"},
    {"al_type": "archive/cabinet", "regex": r"^installshield cab"},
    # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_cab.yara
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L199
    {"al_type": "archive/cabinet", "regex": r"^microsoft cabinet archive data"},
    {"al_type": "archive/cpio", "regex": r"cpio archive"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L175
    {"al_type": "archive/gzip", "regex": r"^gzip compressed data"},
    {"al_type": "archive/iso", "regex": r"ISO 9660"},
    {"al_type": "archive/lzma", "regex": r"^LZMA compressed data"},
    # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_rar.yara
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L179
    {"al_type": "archive/rar", "regex": r"^rar archive data"},
    {"al_type": "archive/squashfs", "regex": r"^Squashfs filesystem"},
    # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_tar.yara
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L177
    {"al_type": "archive/tar", "regex": r"^(GNU|POSIX) tar archive"},
    {"al_type": "archive/ar", "regex": r"^current ar archive"},
    {"al_type": "archive/vhd", "regex": r"^Microsoft Disk Image"},
    {"al_type": "archive/vmdk", "regex": r"^VMware4? disk image"},
    {"al_type": "archive/xz", "regex": r"^XZ compressed data"},
    # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_zip.yara
    {"al_type": "archive/zip", "regex": r"^zip archive data"},
    {"al_type": "archive/zstd", "regex": r"^Zstandard compressed data"},
    {"al_type": "archive/zpaq", "regex": r"^ZPAQ file"},
    {"al_type": "network/tcpdump", "regex": r"^(tcpdump|pcap)"},
    # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_pdf.yara
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L149
    {"al_type": "document/pdf", "regex": r"^pdf document"},
    {"al_type": "document/epub", "regex": r"^EPUB document"},
    {"al_type": "document/mobi", "regex": r"^Mobipocket E-book"},
    {"al_type": "resource/map/warcraft3", "regex": r"^Warcraft III map file$"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L169
    {"al_type": "image/bmp", "regex": r"^pc bitmap"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L145
    {"al_type": "image/gif", "regex": r"^gif image data"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L147
    {"al_type": "image/jpg", "regex": r"^jpeg image data"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L151
    {"al_type": "image/png", "regex": r"^png image data"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L167
    {"al_type": "image/tiff", "regex": r"^TIFF image data"},
    {"al_type": "image/webp", "regex": r"Web/P image"},
    {"al_type": "document/installer/windows", "regex": r"(Installation Database|Windows Installer)"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L141
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L143
    {"al_type": "document/office/excel", "regex": r"Microsoft[^\|]+Excel"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L135
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L137
    {"al_type": "document/office/powerpoint", "regex": r"Microsoft.*PowerPoint"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L131
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L133
    {"al_type": "document/office/word", "regex": r"Microsoft[^\|]+Word"},
    # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_rtf.yara
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L139
    {"al_type": "document/office/rtf", "regex": r"Rich Text Format"},
    {"al_type": "document/office/ole", "regex": r"OLE 2"},
    {"al_type": "document/office/hwp", "regex": r"Hangul \(Korean\) Word Processor File"},
    # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_ole_cf.yara
    {"al_type": "document/office/unknown", "regex": r"Composite Document File|CDFV2"},
    {"al_type": "document/office/unknown", "regex": r"Microsoft[^\|]+(OOXML|Document)"},
    {"al_type": "document/office/unknown", "regex": r"Number of (Characters|Pages|Words)"},
    # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_swf.yara
    {"al_type": "audiovisual/flash", "regex": r"Macromedia Flash"},
    {"al_type": "code/autorun", "regex": r"microsoft windows autorun"},
    {"al_type": "code/batch", "regex": r"dos batch file"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L181
    {"al_type": "java/jar", "regex": r"[ (]Jar[) ]"},
    # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_java_class.yara
    {"al_type": "java/class", "regex": r"java class data"},
    {"al_type": "resource/pyc", "regex": r"python [^\|]+byte"},
    {"al_type": "resource/pyc", "regex": r"^Byte-compiled Python module"},
    {"al_type": "android/apk", "regex": r"Android package \(APK\)"},
    {"al_type": "code/xml", "regex": r"OpenGIS KML"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L161
    {"al_type": "code/xml", "regex": r"xml"},
    {"al_type": "image/tim", "regex": r"TIM image"},
    {"al_type": "network/sff", "regex": r"Frame Format"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L197
    {"al_type": "shortcut/windows", "regex": r"^MS Windows shortcut"},
    {"al_type": "document/email", "regex": r"Mime entity text"},
    {"al_type": "document/email", "regex": r"MIME entity, ASCII text"},
    {"al_type": "metadata/sysmon/evt", "regex": r"MS Windows Vista(-8.1)? Event Log"},
    {"al_type": "metadata/sysmon/evt", "regex": r"MS Windows 10-11 Event Log"},
    {"al_type": "metadata/minidump", "regex": r"Mini DuMP crash report"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L165
    {"al_type": "image/emf", "regex": r"Windows Enhanced Metafile"},
    {"al_type": "resource/msvc", "regex": r"MSVC \.res"},
    {"al_type": "pgp/pubkey", "regex": r"^PGP public key"},
    {"al_type": "pgp/privkey", "regex": r"^PGP private key block"},
    {"al_type": "pgp/encrypted", "regex": r"^PGP RSA encrypted session key"},
    {"al_type": "pgp/message", "regex": r"^PGP message Public-Key Encrypted Session Key"},
    {"al_type": "gpg/symmetric", "regex": r"^GPG symmetrically encrypted data"},
    {"al_type": "video/asf", "regex": r"^Microsoft ASF"},
    # Supported by https://github.com/mitre/multiscanner/blob/86e0145ba3c4a34611f257dc78cd2482ed6358db/multiscanner/modules/Metadata/fileextensions.py#L201
    {"al_type": "code/php", "regex": r"^PHP script"},
]

# LibMagic mimetypes that we blindly trust to assign an Assemblyline type
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
    # ASF video
    "video/x-ms-asf": "video/asf",
    # Source code C/C++
    "text/x-c++": "text/plain",
    "text/x-c": "text/plain",
    # Configuration file
    "application/x-wine-extension-ini": "text/ini",
    # Python
    "text/x-python": "code/python",
    "text/x-script.python": "code/python",
    "application/x-bytecode.python": "resource/pyc",
    "text/x-bytecode.python": "resource/pyc",
    # PHP
    "text/x-php": "code/php",
    # XML file
    "text/xml": "code/xml",
    # SGML file
    "text/sgml": "code/sgml",
    # HTML file
    "text/html": "text/plain",
    # Shell script
    "text/x-shellscript": "code/shell",
    # RTF
    "text/rtf": "document/office/rtf",
    # Troff
    "text/troff": "text/troff",
    # Java
    # The text/x-java mime type is not a trusted mime to map to code/java as there are false positives with this.
    # But it is good enough to confirm that the type is at least text/plain.
    # A type of text/plain will then get sent to the yara identification stage.
    "text/x-java": "text/plain",
    # Batch
    "text/x-msdos-batch": "code/batch",
    # Registry file
    "text/x-ms-regedit": "text/windows/registry",
    # Sysmon EVTX file
    "application/x-ms-evtx": "metadata/sysmon/evt",
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
    # Image TIFF
    "image/tiff": "image/tiff",
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
    "application/x-msi": "document/installer/windows",
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
    "application/x-virtualbox-vhd": "archive/vhd",
    "application/x-xz": "archive/xz",
    "application/vnd.ms-cab-compressed": "archive/cabinet",
    "application/zstd": "archive/zstd",
    "application/x-zstd": "archive/zstd",
    "application/x-bzip2": "archive/bzip2",
    "application/java-archive": "java/jar",
    # JAVA Class
    "application/x-java-applet": "java/class",
    # EPUB
    "application/epub+zip": "document/epub",
    # Packet capture
    "application/vnd.tcpdump.pcap": "network/tcpdump",
    "message/rfc822": "document/email",
    "text/calendar": "text/calendar",
    "application/x-mach-binary": "executable/mach-o",
    "application/x-gettext-translation": "resource/mo",
    "application/x-hwp": "document/office/hwp",
    "application/vnd.iccprofile": "metadata/iccprofile",
    "application/vnd.lotus-1-2-3": "document/lotus/spreadsheet",
    # Firefox modules
    "application/x-xpinstall": "application/mozilla/extension",
    # Chrome extensions
    "application/x-chrome-extension": "application/chrome/extension",
    # Android
    "application/vnd.android.package-archive": "android/apk",
}

# LibMagic mimetypes that we will fallback to when we can't determine a type
untrusted_mimes = {
    "application/javascript": "code/javascript",
    "application/x-powershell": "code/ps1",
    "text/x-java": "code/java",
    "text/html": "code/html",
    "text/x-c++": "code/c++",
    "text/x-c": "code/c",
}
