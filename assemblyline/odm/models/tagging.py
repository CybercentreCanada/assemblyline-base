from assemblyline import odm
from assemblyline.odm.randomizer import random_model_obj, random_minimal_obj

# TODO: only for heuristics maybe?!
CATEGORIES = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Effects"
]


## Tag definition
@odm.model(index=True, store=False)
class Tag(odm.Model):
    classification = odm.Classification()                                         # Classification of the tag
    value = odm.Keyword(copyto="__text__")  # Value of the tag
    context = odm.Optional(odm.Keyword())                                         # Context of the tag
    category = odm.Optional(odm.Enum(values=CATEGORIES, copyto="__text__"))       # Category of tag


@odm.model(index=True, store=False)
class TagSha1(odm.Model):
    classification = odm.Classification()                                             # Classification of the tag
    value = odm.ValidatedKeyword(r"^[a-z0-9]{40}$",
                                 copyto="__text__")                                   # Value of the tag
    context = odm.Optional(odm.Keyword())                                             # Context of the tag
    category = odm.Optional(odm.Enum(values=CATEGORIES, copyto="__text__"))           # Category of tag


@odm.model(index=True, store=False)
class TagSSDeep(odm.Model):
    classification = odm.Classification()                                             # Classification of the tag
    value = odm.ValidatedKeyword(r"^[0-9]{1,18}:[a-zA-Z0-9]{1,64}:[a-zA-Z0-9]{1,64}$",
                                 copyto="__text__")                                   # Value of the tag
    context = odm.Optional(odm.Keyword())                                             # Context of the tag
    category = odm.Optional(odm.Enum(values=CATEGORIES, copyto="__text__"))           # Category of tag


@odm.model(index=True, store=False)
class TagPhone(odm.Model):
    classification = odm.Classification()                                             # Classification of the tag
    value = odm.ValidatedKeyword(r"^(\+?\d{1,2})?[ .-]?(\(\d{3}\)|\d{3})[ .-](\d{3})[ .-](\d{4})$",
                                 copyto="__text__")                                   # Value of the tag
    context = odm.Optional(odm.Keyword())                                             # Context of the tag
    category = odm.Optional(odm.Enum(values=CATEGORIES, copyto="__text__"))           # Category of tag


## Model definition
@odm.model(index=True, store=False)
class Tagging(odm.Model):
    @odm.model(index=True, store=False)
    class Attribution(odm.Model):
        actor = odm.Optional(odm.List(odm.Compound(Tag)))
        campaign = odm.Optional(odm.List(odm.Compound(Tag)))
        exploit = odm.Optional(odm.List(odm.Compound(Tag)))
        implant = odm.Optional(odm.List(odm.Compound(Tag)))
        family = odm.Optional(odm.List(odm.Compound(Tag)))
        network = odm.Optional(odm.List(odm.Compound(Tag)))

    @odm.model(index=True, store=False)
    class AV(odm.Model):
        heuristic = odm.Optional(odm.List(odm.Compound(Tag)))
        virus_name = odm.Optional(odm.List(odm.Compound(Tag)))

    @odm.model(index=True, store=False)
    class Cert(odm.Model):
        @odm.model(index=True, store=False)
        class CertValid(odm.Model):
            start = odm.Optional(odm.List(odm.Compound(Tag)))
            end = odm.Optional(odm.List(odm.Compound(Tag)))

        extended_key_usage = odm.Optional(odm.List(odm.Compound(Tag)))
        issuer = odm.Optional(odm.List(odm.Compound(Tag)))
        key_usage = odm.Optional(odm.List(odm.Compound(Tag)))
        owner = odm.Optional(odm.List(odm.Compound(Tag)))
        serial_no = odm.Optional(odm.List(odm.Compound(Tag)))
        signature_algo = odm.Optional(odm.List(odm.Compound(Tag)))
        subject = odm.Optional(odm.List(odm.Compound(Tag)))
        subject_alt_name = odm.Optional(odm.List(odm.Compound(Tag)))
        thumbprint = odm.Optional(odm.List(odm.Compound(Tag)))
        valid = odm.Optional(odm.Compound(CertValid))

    @odm.model(index=True, store=False)
    class Dynamic(odm.Model):
        @odm.model(index=True, store=False)
        class DynamicProcess(odm.Model):
            command_line = odm.Optional(odm.List(odm.Compound(Tag)))
            file_name = odm.Optional(odm.List(odm.Compound(Tag)))

        @odm.model(index=True, store=False)
        class DynamicSignature(odm.Model):
            category = odm.Optional(odm.List(odm.Compound(Tag)))
            family = odm.Optional(odm.List(odm.Compound(Tag)))
            name = odm.Optional(odm.List(odm.Compound(Tag)))

        @odm.model(index=True, store=False)
        class DynamicSSDeep(odm.Model):
            cls_ids = odm.Optional(odm.List(odm.Compound(TagSSDeep)))
            dynamic_classes = odm.Optional(odm.List(odm.Compound(TagSSDeep)))
            regkeys = odm.Optional(odm.List(odm.Compound(TagSSDeep)))

        @odm.model(index=True, store=False)
        class DynamicWindow(odm.Model):
            cls_ids = odm.Optional(odm.List(odm.Compound(Tag)))
            dynamic_classes = odm.Optional(odm.List(odm.Compound(Tag)))
            regkeys = odm.Optional(odm.List(odm.Compound(Tag)))

        autorun_location = odm.Optional(odm.List(odm.Compound(Tag)))
        dos_device = odm.Optional(odm.List(odm.Compound(Tag)))
        mutex = odm.Optional(odm.List(odm.Compound(Tag)))
        registry_key = odm.Optional(odm.List(odm.Compound(Tag)))
        process = odm.Optional(odm.Compound(DynamicProcess))
        signature = odm.Optional(odm.Compound(DynamicSignature))
        ssdeep = odm.Optional(odm.Compound(DynamicSSDeep))
        window = odm.Optional(odm.Compound(DynamicWindow))

    @odm.model(index=True, store=False)
    class Info(odm.Model):
        phone_number = odm.Optional(odm.List(odm.Compound(TagPhone)))

    @odm.model(index=True, store=False)
    class File(odm.Model):
        @odm.model(index=True, store=False)
        class FileName(odm.Model):
            anomaly = odm.Optional(odm.List(odm.Compound(Tag)))
            extracted = odm.Optional(odm.List(odm.Compound(Tag)))

        @odm.model(index=True, store=False)
        class FileRule(odm.Model):
            tagcheck = odm.Optional(odm.List(odm.Compound(Tag)))
            yara = odm.Optional(odm.List(odm.Compound(Tag)))

        @odm.model(index=True, store=False)
        class FileStrings(odm.Model):
            blacklisted = odm.Optional(odm.List(odm.Compound(Tag)))
            decoded = odm.Optional(odm.List(odm.Compound(Tag)))
            extracted = odm.Optional(odm.List(odm.Compound(Tag)))

        @odm.model(index=True, store=False)
        class FileAPK(odm.Model):
            @odm.model(index=True, store=False)
            class FileAPKApp(odm.Model):
                label = odm.Optional(odm.List(odm.Compound(Tag)))
                version = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FileAPKSDK(odm.Model):
                min = odm.Optional(odm.List(odm.Compound(Tag)))
                target = odm.Optional(odm.List(odm.Compound(Tag)))

            activity = odm.Optional(odm.List(odm.Compound(Tag)))
            app = odm.Optional(odm.Compound(FileAPKApp))
            feature = odm.Optional(odm.List(odm.Compound(Tag)))
            locale = odm.Optional(odm.List(odm.Compound(Tag)))
            permission = odm.Optional(odm.List(odm.Compound(Tag)))
            pkg_name = odm.Optional(odm.List(odm.Compound(Tag)))
            provides_component = odm.Optional(odm.List(odm.Compound(Tag)))
            sdk = odm.Optional(odm.Compound(FileAPKSDK))
            used_library = odm.Optional(odm.List(odm.Compound(Tag)))

        @odm.model(index=True, store=False)
        class FileIMG(odm.Model):
            @odm.model(index=True, store=False)
            class FileIMGExiftool(odm.Model):
                creator_tool = odm.Optional(odm.List(odm.Compound(Tag)))
                derived_document_id = odm.Optional(odm.List(odm.Compound(Tag)))
                document_id = odm.Optional(odm.List(odm.Compound(Tag)))
                instance_id = odm.Optional(odm.List(odm.Compound(Tag)))
                toolkit = odm.Optional(odm.List(odm.Compound(Tag)))

            exiftool = odm.Optional(odm.Compound(FileIMGExiftool))
            mega_pixels = odm.Optional(odm.List(odm.Compound(Tag)))
            mode = odm.Optional(odm.List(odm.Compound(Tag)))
            size = odm.Optional(odm.List(odm.Compound(Tag)))
            sorted_metadata_hash = odm.Optional(odm.List(odm.Compound(Tag)))

        @odm.model(index=True, store=False)
        class FileOLE(odm.Model):
            @odm.model(index=True, store=False)
            class FileOLEDate(odm.Model):
                creation = odm.Optional(odm.List(odm.Compound(Tag)))
                last_modified = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FileOLEMacro(odm.Model):
                sha256 = odm.Optional(odm.List(odm.Compound(Tag)))
                suspicious_string = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FileOLESummary(odm.Model):
                author = odm.Optional(odm.List(odm.Compound(Tag)))
                codepage = odm.Optional(odm.List(odm.Compound(Tag)))
                comment = odm.Optional(odm.List(odm.Compound(Tag)))
                company = odm.Optional(odm.List(odm.Compound(Tag)))
                create_time = odm.Optional(odm.List(odm.Compound(Tag)))
                last_printed = odm.Optional(odm.List(odm.Compound(Tag)))
                last_saved_by = odm.Optional(odm.List(odm.Compound(Tag)))
                last_saved_time = odm.Optional(odm.List(odm.Compound(Tag)))
                manager = odm.Optional(odm.List(odm.Compound(Tag)))
                subject = odm.Optional(odm.List(odm.Compound(Tag)))
                title = odm.Optional(odm.List(odm.Compound(Tag)))

            date = odm.Optional(odm.Compound(FileOLEDate))
            macro = odm.Optional(odm.Compound(FileOLEMacro))
            summary = odm.Optional(odm.Compound(FileOLESummary))
            clsid = odm.Optional(odm.List(odm.Compound(Tag)))
            dde_link = odm.Optional(odm.List(odm.Compound(Tag)))
            fib_timestamp = odm.Optional(odm.List(odm.Compound(Tag)))

        @odm.model(index=True, store=False)
        class FilePE(odm.Model):
            @odm.model(index=True, store=False)
            class FilePEExports(odm.Model):
                function_name = odm.Optional(odm.List(odm.Compound(Tag)))
                module_name = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FilePEImports(odm.Model):
                fuzzy = odm.Optional(odm.List(odm.Compound(TagSSDeep)))
                md5 = odm.Optional(odm.List(odm.Compound(Tag)))
                sorted_fuzzy = odm.Optional(odm.List(odm.Compound(TagSSDeep)))
                sorted_sha1 = odm.Optional(odm.List(odm.Compound(TagSha1)))
                suspicious = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FilePELinker(odm.Model):
                timestamp = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FilePEOEP(odm.Model):
                bytes = odm.Optional(odm.List(odm.Compound(Tag)))
                hexdump = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FilePEResources(odm.Model):
                language = odm.Optional(odm.List(odm.Compound(Tag)))
                name = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FilePESections(odm.Model):
                hash = odm.Optional(odm.List(odm.Compound(Tag)))
                name = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FilePEVersions(odm.Model):
                description = odm.Optional(odm.List(odm.Compound(Tag)))
                filename = odm.Optional(odm.List(odm.Compound(Tag)))

            api_vector = odm.Optional(odm.List(odm.Compound(Tag)))
            exports = odm.Optional(odm.Compound(FilePEExports))
            imports = odm.Optional(odm.Compound(FilePEImports))
            linker = odm.Optional(odm.Compound(FilePELinker))
            oep = odm.Optional(odm.Compound(FilePEOEP))
            pdb_filename = odm.Optional(odm.List(odm.Compound(Tag)))
            resources = odm.Optional(odm.Compound(FilePEResources))
            sections = odm.Optional(odm.Compound(FilePESections))
            versions = odm.Optional(odm.Compound(FilePEVersions))

        @odm.model(index=True, store=False)
        class FilePDF(odm.Model):
            @odm.model(index=True, store=False)
            class FilePDFDate(odm.Model):
                creation = odm.Optional(odm.List(odm.Compound(Tag)))
                last_modified = odm.Optional(odm.List(odm.Compound(Tag)))
                modified = odm.Optional(odm.List(odm.Compound(Tag)))
                pdfx = odm.Optional(odm.List(odm.Compound(Tag)))
                source_modified = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FilePDFJavascript(odm.Model):
                sha1 = odm.Optional(odm.List(odm.Compound(TagSha1)))

            @odm.model(index=True, store=False)
            class FilePDFStats(odm.Model):
                sha1 = odm.Optional(odm.List(odm.Compound(TagSha1)))

            date = odm.Optional(odm.Compound(FilePDFDate))
            javascript = odm.Optional(odm.Compound(FilePDFJavascript))
            stats = odm.Optional(odm.Compound(FilePDFStats))

        @odm.model(index=True, store=False)
        class FilePList(odm.Model):
            @odm.model(index=True, store=False)
            class FilePListBuild(odm.Model):
                machine_os = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FilePListCFBundle(odm.Model):
                @odm.model(index=True, store=False)
                class FilePListCFBundleVersion(odm.Model):
                    long = odm.Optional(odm.List(odm.Compound(Tag)))
                    short = odm.Optional(odm.List(odm.Compound(Tag)))

                development_region = odm.Optional(odm.List(odm.Compound(Tag)))
                display_name = odm.Optional(odm.List(odm.Compound(Tag)))
                executable = odm.Optional(odm.List(odm.Compound(Tag)))
                identifier = odm.Optional(odm.List(odm.Compound(Tag)))
                name = odm.Optional(odm.List(odm.Compound(Tag)))
                pkg_type = odm.Optional(odm.List(odm.Compound(Tag)))
                signature = odm.Optional(odm.List(odm.Compound(Tag)))
                url_scheme = odm.Optional(odm.List(odm.Compound(Tag)))
                version = odm.Optional(odm.Compound(FilePListCFBundleVersion))

            @odm.model(index=True, store=False)
            class FilePListDT(odm.Model):
                @odm.model(index=True, store=False)
                class FilePListDTPlatform(odm.Model):
                    build = odm.Optional(odm.List(odm.Compound(Tag)))
                    name = odm.Optional(odm.List(odm.Compound(Tag)))
                    version = odm.Optional(odm.List(odm.Compound(Tag)))

                compiler = odm.Optional(odm.List(odm.Compound(Tag)))
                version = odm.Optional(odm.Compound(FilePListDTPlatform))

            @odm.model(index=True, store=False)
            class FilePListLS(odm.Model):
                background_only = odm.Optional(odm.List(odm.Compound(Tag)))
                min_system_version = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FilePListNS(odm.Model):
                apple_script_enabled = odm.Optional(odm.List(odm.Compound(Tag)))
                principal_class = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FilePListUI(odm.Model):
                background_modes = odm.Optional(odm.List(odm.Compound(Tag)))
                requires_persistent_wifi = odm.Optional(odm.List(odm.Compound(Tag)))

            @odm.model(index=True, store=False)
            class FilePListWK(odm.Model):
                app_bundle_identifier = odm.Optional(odm.List(odm.Compound(Tag)))

            installer_url = odm.Optional(odm.List(odm.Compound(Tag)))
            min_os_version = odm.Optional(odm.List(odm.Compound(Tag)))
            requests_open_access = odm.Optional(odm.List(odm.Compound(Tag)))

            build = odm.Optional(odm.Compound(FilePListBuild))
            cf_bundle = odm.Optional(odm.Compound(FilePListCFBundle))
            dt = odm.Optional(odm.Compound(FilePListDT))
            ls = odm.Optional(odm.Compound(FilePListLS))
            ns = odm.Optional(odm.Compound(FilePListNS))
            ui = odm.Optional(odm.Compound(FilePListUI))
            wk = odm.Optional(odm.Compound(FilePListWK))


        api_string = odm.Optional(odm.List(odm.Compound(Tag)))
        compiler = odm.Optional(odm.List(odm.Compound(Tag)))
        config = odm.Optional(odm.List(odm.Compound(Tag)))
        libs = odm.Optional(odm.List(odm.Compound(Tag)))
        name = odm.Optional(odm.Compound(FileName))
        path = odm.Optional(odm.List(odm.Compound(Tag)))
        rule = odm.Optional(odm.Compound(FileRule))
        strings = odm.Optional(odm.Compound(FileStrings))
        summary = odm.Optional(odm.List(odm.Compound(Tag)))
        apk = odm.Optional(odm.Compound(FileAPK))
        img = odm.Optional(odm.Compound(FileIMG))
        ole = odm.Optional(odm.Compound(FileOLE))
        pe = odm.Optional(odm.Compound(FilePE))
        pdf = odm.Optional(odm.Compound(FilePDF))
        plist = odm.Optional(odm.Compound(FilePList))
        # powershell = odm.Optional(odm.Compound(FilePowerShell))
        # swf = odm.Optional(odm.Compound(FileSWF))

    attribution = odm.Optional(odm.Compound(Attribution))
    av = odm.Optional(odm.Compound(AV))
    cert = odm.Optional(odm.Compound(Cert))
    dynamic = odm.Optional(odm.Compound(Dynamic))
    info = odm.Optional(odm.Compound(Info))
    file = odm.Optional(odm.Compound(File))


from pprint import pprint
pprint(random_model_obj(Tagging).as_primitives())
pprint(random_minimal_obj(Tagging).as_primitives(strip_null=True))
assert random_minimal_obj(Tagging).as_primitives(strip_null=True) == {}
