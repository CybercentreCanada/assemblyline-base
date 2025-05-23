import csv
import json
import logging
import os
import re
import struct
import subprocess
import sys
import threading
import uuid
import zipfile
from binascii import hexlify
from itertools import islice
from tempfile import NamedTemporaryFile
from typing import Dict, Optional, Tuple, Union
from urllib.parse import unquote, urlparse

import magic
import msoffcrypto
from pathlib import Path
import yaml
import yara

from assemblyline.common.digests import DEFAULT_BLOCKSIZE, get_digests_for_file
from assemblyline.common.forge import get_cachestore, get_config, get_constants, get_datastore
from assemblyline.common.identify_defaults import OLE_CLSID_GUIDs, untrusted_mimes
from assemblyline.common.identify_defaults import magic_patterns as default_magic_patterns
from assemblyline.common.identify_defaults import trusted_mimes as default_trusted_mimes
from assemblyline.common.str_utils import dotdump, safe_str
from assemblyline.filestore import FileStoreException
from assemblyline.remote.datatypes.events import EventWatcher
from cart import get_metadata_only, unpack_file
from magika import Magika

constants = get_constants()


# These headers are found in the custom.magic file to assist with identification, and are imported by services
# that can create files with a high-confidence type
CUSTOM_PS1_ID = b"#!/usr/bin/env pwsh\n"
CUSTOM_BATCH_ID = b"REM Batch extracted by Assemblyline\n"
CUSTOM_URI_ID = "# Assemblyline URI file\n"


class Identify:
    def __init__(self, use_cache: bool = True, config=None, datastore=None, log=None) -> None:
        self.log = log or logging.getLogger("assemblyline.identify")
        self.config = None
        self.datastore = None
        self.use_cache = use_cache
        self.custom = re.compile(r"^custom: ", re.IGNORECASE)
        self.lock = threading.Lock()
        self.yara_default_externals = {"mime": "", "magic": "", "type": ""}
        self.magika = Magika()

        # If cache is use, load the config and datastore objects to load potential items from cache
        if self.use_cache:
            self.log.info("Using cache with identify")
            self.config = config or get_config()
            self.datastore = datastore or get_datastore(config)

        # Load all data for the first time
        self._load_magic_file()
        self._load_yara_file()
        self._load_magic_patterns()
        self._load_trusted_mimes()

        # Register hot reloader
        if self.use_cache:
            self.reload_map = {
                "magic": self._load_magic_file,
                "mimes": self._load_trusted_mimes,
                "patterns": self._load_magic_patterns,
                "yara": self._load_yara_file,
            }
            self.reload_watcher: Optional[EventWatcher[str]] = EventWatcher()
            self.reload_watcher.register("system.identify", self._handle_reload_event)
            self.reload_watcher.start()
        else:
            self.reload_watcher = None
            self.reload_map = {}

    def _handle_reload_event(self, data: Optional[str]):
        if data is None:
            # handle disconnect event, we may be out of sync
            for reload_func in self.reload_map.values():
                reload_func()
        else:
            # update information
            func = self.reload_map.get(data, None)
            if func is not None:
                func()
            else:
                self.log.error(f"Invalid system.identify message received: {data}")

    def _load_magic_patterns(self):
        self.magic_patterns = default_magic_patterns

        if self.use_cache:
            self.log.info("Checking for custom magic patterns...")
            with get_cachestore("system", config=self.config, datastore=self.datastore) as cache:
                try:
                    patterns = cache.get("custom_patterns")
                    if patterns:
                        self.magic_patterns = yaml.safe_load(patterns)
                        self.log.info("Custom magic patterns loaded!")
                    else:
                        self.log.info("No custom magic patterns found.")
                except FileStoreException:
                    self.log.info("No custom magic patterns found.")

        compiled_patterns = [[x["al_type"], re.compile(x["regex"], re.IGNORECASE)] for x in self.magic_patterns]
        with self.lock:
            self.compiled_magic_patterns = compiled_patterns

    def _load_trusted_mimes(self):
        trusted_mimes = default_trusted_mimes

        if self.use_cache:
            self.log.info("Checking for custom trusted mimes...")
            with get_cachestore("system", config=self.config, datastore=self.datastore) as cache:
                try:
                    mimes = cache.get("custom_mimes")
                    if mimes:
                        trusted_mimes = yaml.safe_load(mimes)
                        self.log.info("Custom trusted mimes loaded!")
                    else:
                        self.log.info("No custom magic patterns found.")
                except FileStoreException:
                    self.log.info("No custom trusted mimes found.")

        with self.lock:
            self.trusted_mimes = trusted_mimes

    def _load_magic_file(self):
        self.magic_file = ":".join((constants.MAGIC_RULE_PATH, "/usr/share/file/magic.mgc"))

        if self.use_cache:
            self.log.info("Checking for custom magic file...")
            with get_cachestore("system", config=self.config, datastore=self.datastore) as cache:
                try:
                    custom_magic = "/tmp/custom.magic"
                    cache.download("custom_magic", custom_magic)
                    self.magic_file = ":".join((custom_magic, "/usr/share/file/magic.mgc"))
                    self.log.info("Custom magic file loaded!")
                except FileStoreException:
                    self.log.info("No custom magic file found.")

        with self.lock:
            self.file_type = magic.magic_open(magic.MAGIC_CONTINUE + magic.MAGIC_RAW)
            magic.magic_load(self.file_type, self.magic_file)

            self.mime_type = magic.magic_open(magic.MAGIC_CONTINUE + magic.MAGIC_RAW + magic.MAGIC_MIME)
            magic.magic_load(self.mime_type, self.magic_file)

    def _load_yara_file(self):
        self.yara_file = constants.YARA_RULE_PATH

        if self.use_cache:
            self.log.info("Checking for custom yara file...")
            with get_cachestore("system", config=self.config, datastore=self.datastore) as cache:
                try:
                    custom_yara = "/tmp/custom.yara"
                    cache.download("custom_yara", custom_yara)
                    self.yara_file = custom_yara
                    self.log.info("Custom yara file loaded!")
                except FileStoreException:
                    self.log.info("No custom magic file found.")

        yara_rules = yara.compile(filepaths={"default": self.yara_file}, externals=self.yara_default_externals)
        with self.lock:
            self.yara_rules = yara_rules

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stop()

    def stop(self):
        if self.reload_watcher:
            self.reload_watcher.stop()

    def ident(self, buf, length: int, path) -> Dict:
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
            mimes = []

            with self.lock:
                try:
                    labels = magic.magic_file(self.file_type, path).split(b"\n")
                except magic.MagicException as me:
                    labels = me.message.split(b"\n")

                try:
                    mimes = magic.magic_file(self.mime_type, path).split(b"\n")
                except magic.MagicException as me:
                    mimes = me.message.split(b"\n")

            mimes = [mime[2:].strip() if mime.startswith(b"- ") else mime.strip() for mime in mimes]
            labels = [label[2:].strip() if label.startswith(b"- ") else label.strip() for label in labels]

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

                if self.custom.match(label):
                    # Some things, like executable have additional data appended to their identification, like
                    # ", dynamically linked, stripped" that we do not want to use as part of the type.
                    data["type"] = label.split("custom: ")[1].split(",", 1)[0].strip()
                    break

            # Second priority is mime times marked as trusted
            if data["type"] == "unknown":
                with self.lock:
                    trusted_mimes = self.trusted_mimes

                for mime in mimes:
                    mime = dotdump(mime)

                    if mime in trusted_mimes:
                        data["type"] = trusted_mimes[mime]
                        break

            # As a third priority try matching the magic_patterns
            if data["type"] == "unknown":
                found = False
                with self.lock:
                    compiled_magic_patterns = self.compiled_magic_patterns

                for label in labels:
                    for entry in compiled_magic_patterns:
                        if entry[1].search(dotdump(label)):  # pylint: disable=E1101
                            data["type"] = entry[0]
                            found = True
                            break
                    if found:
                        break

        except Exception as e:
            self.log.error(f"An error occured during file identification: {e.__class__.__name__}({str(e)})")
            pass

        # If mime is text/* and type is unknown, set text/plain to trigger
        # language detection later.
        if data["type"] == "unknown" and data["mime"] is not None and data["mime"].startswith("text/"):
            data["type"] = "text/plain"

        # Lookup office documents by GUID if we're still not sure what they are
        if data["type"] == "document/office/unknown":
            # noinspection PyBroadException
            try:
                root_entry_property_offset = buf.find("Root Entry".encode("utf-16-le"))
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
                            bup_details_offset = buf[: root_entry_property_offset + 0x100].find(
                                "Details".encode("utf-16-le")
                            )
                            if -1 != bup_details_offset:
                                data["type"] = "quarantine/mcafee"
            except Exception:
                pass

        return data

    def yara_ident(self, path: str, info: Dict, fallback="unknown") -> Tuple[str, Union[str, int]]:
        externals = {k: v or "" for k, v in info.items() if k in self.yara_default_externals}
        try:
            with self.lock:
                yara_rules = self.yara_rules
            matches = yara_rules.match(path, externals=externals, fast=True)
            matches.sort(key=lambda x: x.meta.get("score", 0), reverse=True)
            for match in matches:
                ftype = match.meta.get("type", None)
                if ftype:
                    return ftype
        except Exception as e:
            self.log.warning(f"Yara file identifier failed with error: {str(e)}")
            matches = []

        return fallback

    def fileinfo(
        self, path: str, generate_hashes: bool = True, skip_fuzzy_hashes: bool = False, calculate_entropy: bool = True
    ) -> Dict:
        path = safe_str(path)
        if generate_hashes:
            data = get_digests_for_file(
                path,
                on_first_block=self.ident,
                skip_fuzzy_hashes=skip_fuzzy_hashes,
                calculate_entropy=calculate_entropy,
            )
        else:
            with open(path, "rb") as f:
                first_block = f.read(DEFAULT_BLOCKSIZE)
            data = self.ident(first_block, len(first_block), path)
            data["size"] = os.path.getsize(path)

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

        # If we identified the file as 'uri' from libmagic, we should further identify it, or return it as text/plain
        elif data["type"] == "uri":
            data["type"] = uri_ident(path, data)

        # If we're so far failed to identified the file, lets run the yara rules
        elif "unknown" in data["type"] or data["type"] == "text/plain":
            # We do not trust magic/mimetype's CSV identification, so we test it first
            if data["magic"] == "CSV text" or data["mime"] in ["text/csv", "application/csv"]:
                with open(path, newline='') as csvfile:
                    try:
                        # Try to read the file as a normal csv without special sniffed dialect
                        complete_data = [x for x in islice(csv.reader(csvfile), 100)]
                        if len(complete_data) > 2 and len(set([len(x) for x in complete_data])) == 1:
                            data["type"] = "text/csv"
                            # Final type identified, shortcut further processing
                            return data
                    except Exception:
                        pass
                    csvfile.seek(0)
                    try:
                        # Normal CSV didn't work, try sniffing the csv to see how we could parse it
                        dialect = csv.Sniffer().sniff(csvfile.read(1024))
                        csvfile.seek(0)
                        complete_data = [x for x in islice(csv.reader(csvfile, dialect), 100)]
                        if len(complete_data) > 2 and len(set([len(x) for x in complete_data])) == 1:
                            data["type"] = "text/csv"
                            # Final type identified, shortcut further processing
                            return data
                    except Exception:
                        pass

            if data["type"] == "text/plain":
                # Check if the file is a misidentified json first before running the yara rules
                try:
                    json.load(open(path))
                    data["type"] = "text/json"
                    # Final type identified, shortcut further processing
                    return data
                except Exception:
                    pass

            # Only if the file was not identified as a csv or a json
            data["type"] = self.yara_ident(path, data, fallback=data["type"])

            if ("unknown" in data["type"] or data["type"] == "text/plain"):
                magika_mime_type = None
                if data["size"] >= 200:
                    magika_mime_type = self.magika.identify_path(Path(path)).output.mime_type
                    with self.lock:
                        trusted_mimes = self.trusted_mimes

                    # Some entries in trusted_mimes are forcing text/plain to force yara identification
                    # They are redefined in untrusted_mimes with more precision
                    if magika_mime_type in trusted_mimes and magika_mime_type not in untrusted_mimes:
                        data["type"] = trusted_mimes[magika_mime_type]
                        return data

                if data["mime"] in untrusted_mimes:
                    # Rely on untrusted mimes with magic
                    data["type"] = untrusted_mimes[data["mime"]]
                elif magika_mime_type in untrusted_mimes:
                    # Rely on untrusted mimes with Magika
                    data["type"] = untrusted_mimes[magika_mime_type]

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
    nuspec = False
    psmdcp = False

    for file_name in file_list:
        # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_jar.yara#L11
        if file_name.startswith("META-INF/"):
            is_jar = True
        elif file_name == "AndroidManifest.xml":
            android_manifest = True
        elif file_name == "classes.dex":
            android_dex = True
        elif file_name.startswith("Payload/") and file_name.endswith(".app/Info.plist"):
            is_ipa = True
        elif file_name.endswith(".nuspec"):
            nuspec = True
        elif file_name.startswith("package/services/metadata/core-properties/") and file_name.endswith(".psmdcp"):
            psmdcp = True
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
        # Supported by https://github.com/EmersonElectricCo/fsf/blob/15303aa298414397f9aa5d19ca343040a0fe0bbd/fsf-server/yara/ft_office_open_xml.yara
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
        elif nuspec and psmdcp:
            # It is a nupkg file. Identify as archive/zip for now.
            return "archive/zip"
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


def uri_ident(path: str, info: Dict) -> str:
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    except Exception:
        return "text/plain"

    if "uri" not in data:
        return "text/plain"

    try:
        u = urlparse(data["uri"])
    except Exception:
        return "text/plain"

    if not u.scheme:
        return "text/plain"

    info["uri_info"] = dict(
        uri=data["uri"],
        scheme=u.scheme,
        netloc=u.netloc,
    )
    if u.path:
        info["uri_info"]["path"] = u.path
    if u.params:
        info["uri_info"]["params"] = u.params
    if u.query:
        info["uri_info"]["query"] = u.query
    if u.fragment:
        info["uri_info"]["fragment"] = u.fragment
    if u.username:
        info["uri_info"]["username"] = unquote(u.username)
    if u.password:
        info["uri_info"]["password"] = unquote(u.password)
    info["uri_info"]["hostname"] = u.hostname
    if u.port:
        info["uri_info"]["port"] = u.port

    return f"uri/{u.scheme}"


if __name__ == "__main__":
    from pprint import pprint

    use_cache = True
    uncart = False
    args = sys.argv[1:]
    if "--no-cache" in args:
        args.remove("--no-cache")
        use_cache = False
    if "--uncart" in args:
        args.remove("--uncart")
        uncart = True

    identify = Identify(use_cache=use_cache)

    if len(args) > 0:
        fileinfo_data = identify.fileinfo(args[0])

        if fileinfo_data["type"] == "archive/cart" and uncart:
            with NamedTemporaryFile("w") as f:
                unpack_file(args[0], f.name)
                fileinfo_data = identify.fileinfo(f.name)

        pprint(fileinfo_data)
    else:
        name = sys.stdin.readline().strip()
        while name:
            a = identify.fileinfo(name, skip_fuzzy_hashes=True)
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
