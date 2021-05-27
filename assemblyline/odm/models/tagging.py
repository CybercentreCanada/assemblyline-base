from assemblyline import odm


# Model definition
@odm.model(index=True, store=False)
class Tagging(odm.Model):
    @odm.model(index=True, store=False)
    class Attribution(odm.Model):
        actor = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        campaign = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        exploit = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        implant = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        family = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        network = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

    @odm.model(index=True, store=False)
    class AV(odm.Model):
        heuristic = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        virus_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

    @odm.model(index=True, store=False)
    class Cert(odm.Model):
        @odm.model(index=True, store=False)
        class CertValid(odm.Model):
            start = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            end = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        extended_key_usage = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        issuer = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        key_usage = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        owner = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        serial_no = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        signature_algo = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        subject = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        subject_alt_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        thumbprint = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        valid = odm.Optional(odm.Compound(CertValid))
        version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

    @odm.model(index=True, store=False)
    class Dynamic(odm.Model):
        @odm.model(index=True, store=False)
        class DynamicProcess(odm.Model):
            command_line = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            file_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class DynamicSignature(odm.Model):
            category = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            family = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class DynamicSSDeep(odm.Model):
            cls_ids = odm.Optional(odm.List(odm.SSDeepHash(copyto="__text__")))
            dynamic_classes = odm.Optional(odm.List(odm.SSDeepHash(copyto="__text__")))
            regkeys = odm.Optional(odm.List(odm.SSDeepHash(copyto="__text__")))

        @odm.model(index=True, store=False)
        class DynamicWindow(odm.Model):
            cls_ids = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            dynamic_classes = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            regkeys = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class DynamicOperatingSystem(odm.Model):
            platform = odm.Optional(odm.List(odm.Platform(copyto="__text__")))
            version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            processor = odm.Optional(odm.List(odm.Processor(copyto="__text__")))

        autorun_location = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        dos_device = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        mutex = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        registry_key = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        process = odm.Optional(odm.Compound(DynamicProcess))
        signature = odm.Optional(odm.Compound(DynamicSignature))
        ssdeep = odm.Optional(odm.Compound(DynamicSSDeep))
        window = odm.Optional(odm.Compound(DynamicWindow))
        operating_system = odm.Optional(odm.Compound(DynamicOperatingSystem))

    @odm.model(index=True, store=False)
    class Info(odm.Model):
        phone_number = odm.Optional(odm.List(odm.PhoneNumber(copyto="__text__")))

    @odm.model(index=True, store=False)
    class File(odm.Model):
        @odm.model(index=True, store=False)
        class FileDate(odm.Model):
            creation = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            last_modified = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class FileName(odm.Model):
            anomaly = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            extracted = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class FileStrings(odm.Model):
            api = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            blacklisted = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            decoded = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            extracted = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class FileAPK(odm.Model):
            @odm.model(index=True, store=False)
            class FileAPKApp(odm.Model):
                label = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FileAPKSDK(odm.Model):
                min = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                target = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            activity = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            app = odm.Optional(odm.Compound(FileAPKApp))
            feature = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            locale = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            permission = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            pkg_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            provides_component = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            sdk = odm.Optional(odm.Compound(FileAPKSDK))
            used_library = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class FileJAR(odm.Model):
            main_class = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            main_package = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class FileIMG(odm.Model):
            @odm.model(index=True, store=False)
            class FileIMGExiftool(odm.Model):
                creator_tool = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                derived_document_id = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                document_id = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                instance_id = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                toolkit = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            exif_tool = odm.Optional(odm.Compound(FileIMGExiftool))
            mega_pixels = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            mode = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            size = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            sorted_metadata_hash = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class FileOLE(odm.Model):
            @odm.model(index=True, store=False)
            class FileOLEMacro(odm.Model):
                sha256 = odm.Optional(odm.List(odm.SHA256(copyto="__text__")))
                suspicious_string = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FileOLESummary(odm.Model):
                author = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                codepage = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                comment = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                company = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                create_time = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                last_printed = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                last_saved_by = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                last_saved_time = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                manager = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                subject = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                title = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            macro = odm.Optional(odm.Compound(FileOLEMacro))
            summary = odm.Optional(odm.Compound(FileOLESummary))
            clsid = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            dde_link = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            fib_timestamp = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class FilePE(odm.Model):
            @odm.model(index=True, store=False)
            class FilePEExports(odm.Model):
                function_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                module_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FilePEImports(odm.Model):
                fuzzy = odm.Optional(odm.List(odm.SSDeepHash(copyto="__text__")))
                md5 = odm.Optional(odm.List(odm.MD5(copyto="__text__")))
                sorted_fuzzy = odm.Optional(odm.List(odm.SSDeepHash(copyto="__text__")))
                sorted_sha1 = odm.Optional(odm.List(odm.SHA1(copyto="__text__")))
                suspicious = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FilePELinker(odm.Model):
                timestamp = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FilePEOEP(odm.Model):
                bytes = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                hexdump = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FilePEResources(odm.Model):
                language = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FilePESections(odm.Model):
                hash = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FilePEVersions(odm.Model):
                description = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                filename = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            api_vector = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            exports = odm.Optional(odm.Compound(FilePEExports))
            imports = odm.Optional(odm.Compound(FilePEImports))
            linker = odm.Optional(odm.Compound(FilePELinker))
            oep = odm.Optional(odm.Compound(FilePEOEP))
            pdb_filename = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            resources = odm.Optional(odm.Compound(FilePEResources))
            sections = odm.Optional(odm.Compound(FilePESections))
            versions = odm.Optional(odm.Compound(FilePEVersions))

        @odm.model(index=True, store=False)
        class FilePDF(odm.Model):
            @odm.model(index=True, store=False)
            class FilePDFDate(odm.Model):
                modified = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                pdfx = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                source_modified = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FilePDFJavascript(odm.Model):
                sha1 = odm.Optional(odm.List(odm.SHA1(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FilePDFStats(odm.Model):
                sha1 = odm.Optional(odm.List(odm.SHA1(copyto="__text__")))

            date = odm.Optional(odm.Compound(FilePDFDate))
            javascript = odm.Optional(odm.Compound(FilePDFJavascript))
            stats = odm.Optional(odm.Compound(FilePDFStats))

        @odm.model(index=True, store=False)
        class FilePList(odm.Model):
            @odm.model(index=True, store=False)
            class FilePListBuild(odm.Model):
                machine_os = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FilePListCFBundle(odm.Model):
                @odm.model(index=True, store=False)
                class FilePListCFBundleVersion(odm.Model):
                    long = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                    short = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

                development_region = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                display_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                executable = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                identifier = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                pkg_type = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                signature = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                url_scheme = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                version = odm.Optional(odm.Compound(FilePListCFBundleVersion))

            @odm.model(index=True, store=False)
            class FilePListDT(odm.Model):
                @odm.model(index=True, store=False)
                class FilePListDTPlatform(odm.Model):
                    build = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                    name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                    version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

                compiler = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                platform = odm.Optional(odm.Compound(FilePListDTPlatform))

            @odm.model(index=True, store=False)
            class FilePListLS(odm.Model):
                background_only = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                min_system_version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FilePListNS(odm.Model):
                apple_script_enabled = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                principal_class = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FilePListUI(odm.Model):
                background_modes = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
                requires_persistent_wifi = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            @odm.model(index=True, store=False)
            class FilePListWK(odm.Model):
                app_bundle_identifier = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            installer_url = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            min_os_version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            requests_open_access = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

            build = odm.Optional(odm.Compound(FilePListBuild))
            cf_bundle = odm.Optional(odm.Compound(FilePListCFBundle))
            dt = odm.Optional(odm.Compound(FilePListDT))
            ls = odm.Optional(odm.Compound(FilePListLS))
            ns = odm.Optional(odm.Compound(FilePListNS))
            ui = odm.Optional(odm.Compound(FilePListUI))
            wk = odm.Optional(odm.Compound(FilePListWK))

        @odm.model(index=True, store=False)
        class FilePowerShell(odm.Model):
            cmdlet = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class FileSWF(odm.Model):
            @odm.model(index=True, store=False)
            class FileSWFHeader(odm.Model):
                @odm.model(index=True, store=False)
                class FileSWFHeaderFrame(odm.Model):
                    count = odm.Optional(odm.List(odm.Integer()))
                    rate = odm.Optional(odm.List(odm.Keyword()))
                    size = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

                frame = odm.Optional(odm.Compound(FileSWFHeaderFrame))
                version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            header = odm.Optional(odm.Compound(FileSWFHeader))
            tags_ssdeep = odm.Optional(odm.List(odm.SSDeepHash(copyto="__text__")))

        behavior = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        compiler = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        config = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        date = odm.Optional(odm.Compound(FileDate))
        lib = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        name = odm.Optional(odm.Compound(FileName))
        path = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        rule = odm.Optional(odm.Mapping(odm.List(odm.Keyword(copyto="__text__"))))
        string = odm.Optional(odm.Compound(FileStrings))
        apk = odm.Optional(odm.Compound(FileAPK))
        jar = odm.Optional(odm.Compound(FileJAR))
        img = odm.Optional(odm.Compound(FileIMG))
        ole = odm.Optional(odm.Compound(FileOLE))
        pe = odm.Optional(odm.Compound(FilePE))
        pdf = odm.Optional(odm.Compound(FilePDF))
        plist = odm.Optional(odm.Compound(FilePList))
        powershell = odm.Optional(odm.Compound(FilePowerShell))
        swf = odm.Optional(odm.Compound(FileSWF))

    @odm.model(index=True, store=False)
    class Network(odm.Model):
        @odm.model(index=True, store=False)
        class NetworkIOCs(odm.Model):
            domain = odm.Optional(odm.List(odm.Domain(copyto="__text__")))
            ip = odm.Optional(odm.List(odm.IP(copyto="__text__")))
            uri = odm.Optional(odm.List(odm.URI(copyto="__text__")))
            uri_path = odm.Optional(odm.List(odm.URIPath(copyto="__text__")))

        @odm.model(index=True, store=False)
        class NetworkEmail(odm.Model):
            address = odm.Optional(odm.List(odm.Email(copyto="__text__")))
            date = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            subject = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            msg_id = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class NetworkSignature(odm.Model):
            signature_id = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            message = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        @odm.model(index=True, store=False)
        class NetworkTLS(odm.Model):
            ja3_hash = odm.Optional(odm.List(odm.MD5(copyto="__text__")))
            ja3_string = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
            sni = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

        attack = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        dynamic = odm.Optional(odm.Compound(NetworkIOCs))
        email = odm.Optional(odm.Compound(NetworkEmail))
        mac_address = odm.Optional(odm.List(odm.MAC(copyto="__text__")))
        port = odm.Optional(odm.List(odm.Integer()))
        protocol = odm.Optional(odm.List(odm.Keyword()))
        signature = odm.Optional(odm.Compound(NetworkSignature))
        static = odm.Optional(odm.Compound(NetworkIOCs))
        tls = odm.Optional(odm.Compound(NetworkTLS))

    @odm.model(index=True, store=False)
    class Technique(odm.Model):
        comms_routine = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        config = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        crypto = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        keylogger = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        macro = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        masking_algo = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        obfuscation = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        packer = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        persistence = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        shellcode = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
        string = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))

    attribution = odm.Optional(odm.Compound(Attribution))
    av = odm.Optional(odm.Compound(AV))
    cert = odm.Optional(odm.Compound(Cert))
    dynamic = odm.Optional(odm.Compound(Dynamic))
    info = odm.Optional(odm.Compound(Info))
    file = odm.Optional(odm.Compound(File))
    network = odm.Optional(odm.Compound(Network))
    source = odm.Optional(odm.List(odm.Keyword(copyto="__text__")))
    technique = odm.Optional(odm.Compound(Technique))
