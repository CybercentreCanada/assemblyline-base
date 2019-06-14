
tag_map = {
    "attribution": {
        "actor": ['THREAT_ACTOR'],
        "campaign": ['CAMPAIGN_NAME'],
        "exploit": ['EXPLOIT_NAME'],
        "implant": ['IMPLANT_NAME'],
        "family": ['IMPLANT_FAMILY'],
        "network": ['NET_ATTRIBUTION'],
     },
    "av": {
        "heuristic": ['AV_HEURISTIC'],
        "virus_name": ['AV_VIRUS_NAME'],
    },
    "cert": {
        "extended_key_usage": ['CERT_EXTENDED_KEY_USAGE'],
        "issuer": ['ANDROID_CERT_ISSUER', 'CERT_ISSUER'],
        "key_usage": ['CERT_KEY_USAGE'],
        "owner": ['ANDROID_CERT_OWNER'],
        "serial_no": ['CERT_SERIAL_NO'],
        "signature_algo": ['CERT_SIGNATURE_ALGO'],
        "subject": ['CERT_SUBJECT'],
        "subject_alt_name": ['CERT_SUBJECT_ALT_NAME'],
        "thumbprint": ['CERT_THUMBPRINT'],
        "valid": {
            "start": ['ANDROID_CERT_START_DATE', 'CERT_VALID_FROM'],
            "end": ['ANDROID_CERT_END_DATE', 'CERT_VALID_TO'],
        },
    },
    "dynamic": {
        "autorun_location": ['AUTORUN_LOCATION'],
        "dos_device": ['DOS_DEVICE_NAME,'],
        "mutex": ['DYNAMIC_MUTEX_NAME'],
        "registry_key": ['REGISTRY_KEY'],
        "process": {
            "file_name": ['DYNAMIC_PROCESS_FNAME'],
            "command_line": ['DYNAMIC_PROCESS_COMMANDLINE'],
        },
        "signature": {
            "category": ['DYNAMIC_SIGNATURE_CATEGORY'],
            "family": ['DYNAMIC_SIGNATURE_NAME'],
            "name": ['DYNAMIC_SIGNATURE_FAMILY'],
        },
        "ssdeep": {
            "cls_ids": ['DYNAMIC_CLSIDS_SSDEEP'],
            "regkeys": ['DYNAMIC_REGKEYS_SSDEEP'],
            "dynamic_classes": ['ANDROID_DYNAMIC_CLASSES_SSDEEP'],
        },
        "window": {
            "name": ['DYNAMIC_WINDOW_NAME'],
            "class_name": ['DYNAMIC_WINDOW_CLASSNAME'],
        },
    },
    "info": {
        "phone_number": ['NET_PHONE_NUMBER'],
    },
    "file": {
        "api_string": ['WIN_API_STRING'],
        "compiler": ['INFO_COMPILER'],
        "config": ['FILE_CONFIG'],
        "lib": ['INFO_LIBS'],
        "name": {
            "anomaly": ['FILENAME_ANOMALIES'],
            "extracted": ['FILE_NAME'],
        },
        "path": ['FILE_PATH_NAME', 'DYNAMIC_DROP_PATH,'],
        "rule": {
            "tagcheck": ['TAGCHECK_RULE'],
            "yara": ['FILE_YARA_RULE'],
        },
        "string":{
            "blacklisted": ['PESTUDIO_BLACKLIST_STRING'],
            "decoded": ['FILE_DECODED_STRING'],
            "extracted": ['FILE_STRING'],
        },
        "summary": ['FILE_SUMMARY'],
        "apk": {
            "activity": ['ANDROID_ACTIVITY'],
            "app": {
                "label": ['ANDROID_APP_LABEL'],
                "version": ['ANDROID_APP_VERSION'],
            },
            "feature": ['ANDROID_FEATURE'],
            "locale": ['ANDROID_LOCALE'],
            "permission": ['ANDROID_PERMISSION'],
            "pkg_name": ['ANDROID_PKG_NAME'],
            "provides_component": ['ANDROID_PROVIDES_COMPONENT'],
            "sdk": {
                "min": ['ANDROID_PKG_NAME'],
                "target": ['ANDROID_TARGET_SDK'],
            },
            "used_library": ['ANDROID_USE_LIBRARY'],
        },
        "img": {
            "exif_tool": {
                "creator_tool": ['EXIFTOOL_XMP_CREATOR_TOOL'],
                "derived_document_id": ['EXIFTOOL_XMP_DERIVED_DOCUMENT_ID'],
                "document_id": ['EXIFTOOL_XMP_DOCUMENT_ID'],
                "instance_id": ['EXIFTOOL_XMP_INSTANCE_ID'],
                "toolkit": ['EXIFTOOL_XMP_TOOLKIT'],
            },
            "mega_pixels": ['IMAGE_MEGAPIXELS'],
            "mode": ['IMAGE_MODE'],
            "size": ['IMAGE_SIZE'],
            "sorted_metadata_hash": ['SORTED_METADATA_HASH'],
        },
        "ole": {
            "clsid": ['OLE_CLSID'],
            "date": {
                "creation": ['OLE_CREATION_TIME'],
                "last_modified": ['OLE_LASTMOD_TIME'],
            },
            "dde_link": ['OLE_DDE_LINK'],
            "fib_timestamp": ['OLE_FIB_TIMESTAMP'],
            "macro": {
                "sha256": ['OLE_MACRO_SHA256'],
                "suspicious_string": ['OLE_MACRO_SUSPICIOUS_STRINGS'],
            },
            "summary": {
                "author": ['OLE_SUMMARY_AUTHOR'],
                "codepage": ['OLE_SUMMARY_CODEPAGE'],
                "comment": ['OLE_SUMMARY_COMMENTS'],
                "company": ['OLE_SUMMARY_COMPANY'],
                "create_time": ['OLE_SUMMARY_CREATETIME'],
                "last_printed": ['OLE_SUMMARY_LASTPRINTED'],
                "last_saved_by": ['OLE_SUMMARY_LASTSAVEDBY'],
                "last_saved_time": ['OLE_SUMMARY_LASTSAVEDTIME'],
                "manager": ['OLE_SUMMARY_MANAGER'],
                "subject": ['OLE_SUMMARY_SUBJECT'],
                "title": ['OLE_SUMMARY_TITLE'],
            },
        },
        "pe": {
            "api_vector": ['PE_APIVECTOR'],
            "exports": {
                "function_name": ['PE_EXPORT_FCT_NAME'],
                "module_name": ['PE_EXPORT_MODULE_NAME'],
            },
            "imports": {
                "fuzzy": ['PE_IMPORT_FUZZY'],
                "md5": ['PE_IMPORT_MD5'],
                "sorted_fuzzy": ['PE_IMPORT_SORTED_FUZZY'],
                "sorted_sha1": ['PE_IMPORT_SORTED_SHA1'],
                "suspicious": ['SUSPICIOUS_IMPORTS'],
            },
            "linker": {
                "timestamp": ['PE_LINK_TIME_STAMP'],
            },
            "oep": {
                "bytes": ['PE_OEP_BYTES'],
                "hexdump": ['PE_OEP_HEXDUMP'],
            },
            "pdb_filename": ['PE_PDB_FILENAME', 'FILE_PDB_STRING'],
            "resources": {
                "language": ['PE_RESOURCE_LANGUAGE'],
                "name": ['PE_RESOURCE_NAME'],
            },
            "sections": {
                "hash": ['PE_SECTION_HASH'],
                "name": ['PE_SECTION_NAME', 'PE_UNEXPECTED_SECTION_NAME'],
            },
            "version": {
                "description": ['PE_VERSION_INFO_FILE_DESCRIPTION'],
                "filename": ['PE_VERSION_INFO_ORIGINAL_FILENAME'],
            },
        },
        "pdf": {
            "date": {
                "creation": ['PDF_DATE_CREATION'],
                "last_modified": ['PDF_DATE_LASTMODIFIED'],
                "modified": ['PDF_DATE_MOD'],
                "pdfx": ['PDF_DATE_PDFX'],
                "source_modified": ['PDF_DATE_SOURCEMODIFIED'],
            },
            "javascript": {
                "sha1": ['PDF_JAVASCRIPT_SHA1']
            },
            "stats": {
                "sha1": ['PDF_STATS_SHA1']
            },
        },
        "plist": {
            "installer_url": ['PLIST_APINSTALLERURL'],
            "build":{
                "machine_os": ['PLIST_BUILDMACHINEOSBUILD']
            },
            "cf_bundle":{
                "development_region": ['PLIST_CFBUNDLEDEVELOPMENTREGION'],
                "display_name": ['PLIST_CFBUNDLEDISPLAYNAME'],
                "executable": ['PLIST_CFBUNDLEEXECUTABLE'],
                'identifier': ['PLIST_CFBUNDLEIDENTIFIER'],
                'name': ['PLIST_CFBUNDLENAME'],
                "pkg_type": ['PLIST_CFBUNDLEPACKAGETYPE'],
                "signature": ['PLIST_CFBUNDLESIGNATURE'],
                "url_scheme": ['PLIST_CFBUNDLEURLSCHEMES'],
                "version": {
                    'long': ['PLIST_CFBUNDLEVERSION'],
                    'short': ['PLIST_CFBUNDLESHORTVERSIONSTRING'],
                }
            },
            "dt": {
                "compiler": ['PLIST_DTCOMPILER'],
                "platform": {
                    "build": ['PLIST_DTPLATFORMBUILD'],
                    "name": ['PLIST_DTPLATFORMNAME'],
                    "version": ['PLIST_DTPLATFORMVERSION'],
                }
            },
            "ls": {
                "background_only": ['PLIST_LSBACKGROUNDONLY'],
                "min_system_version": ['PLIST_LSMINIMUMSYSTEMVERSION'],
            },
            "min_os_version": ['PLIST_MINIMUMOSVERSION'],
            "ns": {
                "apple_script_enabled": ['PLIST_NSAPPLESCRIPTENABLED'],
                "principal_class": ['PLIST_NSPRINCIPALCLASS'],
            },
            "requests_open_access": ['PLIST_REQUESTSOPENACCESS'],
            "ui": {
                "background_modes": ['PLIST_UIBACKGROUNDMODES'],
                "requires_persistent_wifi": ['PLIST_UIREQUIRESPERSISTENTWIFI']
            },
            "wk": {
                "app_bundle_identifier": ['PLIST_WKAPPBUNDLEIDENITIFER'],
            }
        },
    # TODO: Model done up to here...
        "powershell":{
            "cmdlet": ['POWERSHELL_CMDLET']
        },
        "swf": {
            "header": {
                "frame": {
                    "size": ['SWF_HEADER_FRAME_SIZE'],
                    "rate": ['SWF_HEADER_FRAME_RATE'],
                    "count": ['SWF_HEADER_FRAME_COUNT'],
                },
                "version": ['SWF_HEADER_VERSION'],
            },
            "tags_ssdeep": ['SWF_TAGS_SSDEEP'],
        },
    },
    "network": {
        "attack": ['NET_ATTACK'],
        "domain": ['NET_DOMAIN_NAME'],
        "email": {
            "address": ['NET_EMAIL'],
            "date": ['NET_EMAIL_DATE'],
            "subject": ['NET_EMAIL_SUBJECT'],
            "msg_id": ['NET_EMAIL_MSG_ID'],
        },
        "ip": ['NET_IP'],
        "mac_address": [],
        "port": ['NET_PORT'],
        "protocol": ['NET_PROTOCOL', 'NET_PROTOCOL_SUSPICIOUS'],
        "signature":{
            "signature_id": ['SURICATA_SIGNATURE_ID'],
            "message": ['SURICATA_SIGNATURE_MESSAGE']
        },
        "tls":{
            "ja3_hash": ['TLS_JA3_HASH'],
            "ja3_string": ['TLS_JA3_STRING'],
        },
        "uri": ['NET_FULL_URI'],
        "uri_path": ['NET_NO_DOMAIN_URI'],
    },
    "source": ['SOURCE'],
    "technique": {
        "comms_routine": ['TECHNIQUE_COMMS_ROUTINE'],
        "config": ['TECHNIQUE_CONFIG'],
        "crypto": ['TECHNIQUE_CRYPTO'],
        "keylogger": ['TECHNIQUE_KEYLOGGER'],
        "macro": ['TECHNIQUE_MACROS'],
        "masking_algo": ['MASKING_ALGO'],
        "obfuscation": ['TECHNIQUE_OBFUSCATION', 'FILE_OBFUSCATION'],
        "packer": ['TECHNIQUE_PACKER'],
        "persistence": ['TECHNIQUE_PERSISTENCE'],
        "shellcode": ['SHELLCODE', 'TECHNIQUE_SHELLCODE'],
        "string": ['IMPLANT_STRINGS'],
    },
}

UNSUSED = [
    'BASE64_ALPHABET',
    'FILE_MIMETYPE',
    'FILE_EXTENSION',
    'SERVICE_NAME',
    'SERVICE_DISPLAY_NAME',
    'SERVICE_DESCRIPTION',
    'DYNAMIC_MALWARE_PATTERN',
    'DYNAMIC_MALICIOUSNESS',
    'HEURISTIC',
    "REQUEST_USERNAME",
    "REQUEST_SCORE",
    "DISPLAY_SEARCH_STRING"
]

def flatten(data, parent_key=None):
    items = []
    for k, v in data.items():
        cur_key = f"{parent_key}.{k}" if parent_key is not None else k
        if isinstance(v, dict):
            items.extend(flatten(v, cur_key).items())
        else:
            items.append((cur_key, v))

    return dict(items)

def reverse_map(data):
    output = {}
    for k, v in data.items():
        for x in v:
            output[x] = k

    return output

v3_lookup_map = reverse_map(flatten(tag_map))
v3_lookup_map.update({k: None for k in UNSUSED})

from pprint import pprint
pprint(v3_lookup_map)