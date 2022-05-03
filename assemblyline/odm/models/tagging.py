from assemblyline import odm


@odm.model(index=True, store=False, description="Tagging Model")
class Tagging(odm.Model):
    @odm.model(index=True, store=False, description="Attribution Tag Model")
    class Attribution(odm.Model):
        actor = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Actor")
        campaign = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Campaign")
        exploit = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Exploit")
        implant = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Implant")
        family = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Family")
        network = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Network")

    @odm.model(index=True, store=False, description="Antivirus Tag Model")
    class AV(odm.Model):
        heuristic = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="List of heuristics")
        virus_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                  description="Collection of virus names identified by antivirus tools")

    @odm.model(index=True, store=False, description="Certificate Tag Model")
    class Cert(odm.Model):
        @odm.model(index=True, store=False, description="Valid Certificate Period")
        class CertValid(odm.Model):
            start = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                 description="Start date of certificate validity")
            end = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="End date of certificate validity")

        extended_key_usage = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Extended Key Usage")
        issuer = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Issuer")
        key_usage = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Key Usage")
        owner = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Owner")
        serial_no = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Serial Number")
        signature_algo = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Signature Algorithm")
        subject = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Subject Name")
        subject_alt_name = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Alternative Subject Name")
        thumbprint = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Thumbprint")
        valid = odm.Optional(odm.Compound(CertValid), description="Validity Information")
        version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Version")

    @odm.model(index=True, store=False, description="Dynamic Tag Model. Commonly Used by Dynamic Analysis")
    class Dynamic(odm.Model):
        @odm.model(index=True, store=False, description="Dynamic Process")
        class DynamicProcess(odm.Model):
            command_line = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Commandline")
            file_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Filename")
            shortcut = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Shortcut")

        @odm.model(index=True, store=False, description="Signatures")
        class DynamicSignature(odm.Model):
            category = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Signature Category")
            family = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Signature Family")
            name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Signature Name")

        @odm.model(index=True, store=False, description="SSDeep")
        class DynamicSSDeep(odm.Model):
            cls_ids = odm.Optional(odm.List(odm.SSDeepHash(copyto="__text__")), description="CLSIDs")
            dynamic_classes = odm.Optional(odm.List(odm.SSDeepHash(copyto="__text__")), description="Dynamic Classes")
            regkeys = odm.Optional(odm.List(odm.SSDeepHash(copyto="__text__")), description="Registry Keys")

        @odm.model(index=True, store=False, description="Windows")
        class DynamicWindow(odm.Model):
            cls_ids = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="CLSIDs")
            dynamic_classes = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Dynamic Classes")
            regkeys = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Registry Keys")

        @odm.model(index=True, store=False, description="Operating System")
        class DynamicOperatingSystem(odm.Model):
            platform = odm.Optional(odm.List(odm.Platform(copyto="__text__")), description="Platform")
            version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Version")
            processor = odm.Optional(odm.List(odm.Processor(copyto="__text__")), description="Processor")

        autorun_location = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Autorun location")
        dos_device = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="DOS Device")
        mutex = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Mutex")
        registry_key = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Registy Keys")
        process = odm.Optional(odm.Compound(DynamicProcess), description="Sandbox Processes")
        signature = odm.Optional(odm.Compound(DynamicSignature), description="Sandbox Signatures")
        ssdeep = odm.Optional(odm.Compound(DynamicSSDeep), description="Sandbox SSDeep")
        window = odm.Optional(odm.Compound(DynamicWindow), description="Sandbox Window")
        operating_system = odm.Optional(odm.Compound(DynamicOperatingSystem), description="Sandbox Operating System")
        processtree_id = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Process Tree ID")

    @odm.model(index=True, store=False, description="General Information Tag Model")
    class Info(odm.Model):
        phone_number = odm.Optional(odm.List(odm.PhoneNumber(copyto="__text__")))
        password = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Password")

    @odm.model(index=True, store=False, description="File Tag Model")
    class File(odm.Model):
        @odm.model(index=True, store=False, description="APK File Model")
        class FileAPK(odm.Model):
            @odm.model(index=True, store=False, description="APK Application Model")
            class FileAPKApp(odm.Model):
                label = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Label")
                version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Version")

            @odm.model(index=True, store=False, description="APK SDK Model")
            class FileAPKSDK(odm.Model):
                min = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Minimum OS required")
                target = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Target OS")

            activity = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Activity")
            app = odm.Optional(odm.Compound(FileAPKApp), description="APK Application Information")
            feature = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Features")
            locale = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Locale")
            permission = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Permissions")
            pkg_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Package Name")
            provides_component = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                              description="Components Provided")
            sdk = odm.Optional(odm.Compound(FileAPKSDK), description="APK SDK Information")
            used_library = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Libraries Used")

        @odm.model(index=True, store=False, description="File Date Model")
        class FileDate(odm.Model):
            creation = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="File Creation Date")
            last_modified = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                         description="File Last Modified Date")

        @odm.model(index=True, store=False, description="ELF File Tag Model")
        class FileELF(odm.Model):
            @odm.model(index=True, store=False, description="ELF Sections")
            class FileELFSections(odm.Model):
                name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Section Name")

            @odm.model(index=True, store=False, description="ELF Segments")
            class FileELFSegments(odm.Model):
                type = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Segment Type")

            @odm.model(index=True, store=False, description="ELF Notes")
            class FileELFNotes(odm.Model):
                name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Note Name")
                type = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Note Type")
                type_core = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Note Core Type")

            libraries = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Libraries")
            interpreter = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Interpreter")
            sections = odm.Optional(odm.Compound(FileELFSections), description="ELF Sections")
            segments = odm.Optional(odm.Compound(FileELFSegments), description="ELF Segments")
            notes = odm.Optional(odm.Compound(FileELFNotes), description="ELF Notes")

        @odm.model(index=True, store=False, description="Image File Tag Model")
        class FileIMG(odm.Model):
            @odm.model(index=True, store=False, description="Exiftool Information Model")
            class FileIMGExiftool(odm.Model):
                creator_tool = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Image Creation Tool")
                derived_document_id = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                                   description="Derived Document ID")
                document_id = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Document ID")
                instance_id = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Instance ID")
                toolkit = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Toolkit")

            exif_tool = odm.Optional(odm.Compound(FileIMGExiftool), description="Exiftool Information")
            mega_pixels = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Megapixels")
            mode = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Image Mode")
            size = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Image Size")
            sorted_metadata_hash = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                                description="Sorted Metadata Hash")

        @odm.model(index=True, store=False, description="JAR File Tag Model")
        class FileJAR(odm.Model):
            main_class = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Main Class")
            main_package = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Main Package")

        @odm.model(index=True, store=False, description="File Name Model")
        class FileName(odm.Model):
            anomaly = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Name of Anomaly")
            extracted = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Name of Extracted")

        @odm.model(index=True, store=False, description="OLE File Tag Model")
        class FileOLE(odm.Model):
            @odm.model(index=True, store=False, description="OLE Macro Model")
            class FileOLEMacro(odm.Model):
                sha256 = odm.Optional(odm.List(odm.SHA256(copyto="__text__")), description="SHA256 of Macro")
                suspicious_string = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                                 description="Suspicious Strings")

            @odm.model(index=True, store=False, description="OLE Summary Model")
            class FileOLESummary(odm.Model):
                author = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Author")
                codepage = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Code Page")
                comment = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Comment")
                company = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Company")
                create_time = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Creation Time")
                last_printed = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Date Last Printed")
                last_saved_by = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="User Last Saved By")
                last_saved_time = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Date Last Saved")
                manager = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Manager")
                subject = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Subject")
                title = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Title")

            macro = odm.Optional(odm.Compound(FileOLEMacro), description="OLE Macro")
            summary = odm.Optional(odm.Compound(FileOLESummary), description="OLE Summary")
            clsid = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="CLSID")
            dde_link = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="DDE Link")
            fib_timestamp = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="FIB Timestamp")

        @odm.model(index=True, store=False, description="PDF File Tag Model")
        class FilePDF(odm.Model):
            @odm.model(index=True, store=False, description="PDF Date Model")
            class FilePDFDate(odm.Model):
                modified = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Date Modified")
                pdfx = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="PDFx")
                source_modified = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                               description="Date Source Modified")

            @odm.model(index=True, store=False, description="PDF Javascript Model")
            class FilePDFJavascript(odm.Model):
                sha1 = odm.Optional(odm.List(odm.SHA1(copyto="__text__")), description="SHA1 of Javascript")

            @odm.model(index=True, store=False, description="PDF Statistics Model")
            class FilePDFStats(odm.Model):
                sha1 = odm.Optional(odm.List(odm.SHA1(copyto="__text__")), description="SHA1 of Statistics")

            date = odm.Optional(odm.Compound(FilePDFDate), description="PDF Date Information")
            javascript = odm.Optional(odm.Compound(FilePDFJavascript), description="PDF Javascript Information")
            stats = odm.Optional(odm.Compound(FilePDFStats), description="PDF Statistics Information")

        @odm.model(index=True, store=False, description="PE File Tag Model")
        class FilePE(odm.Model):
            @odm.model(index=True, store=False, description="PE Debug Model")
            class FilePEDebug(odm.Model):
                guid = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="GUID")

            @odm.model(index=True, store=False, description="PE Exports Model")
            class FilePEExports(odm.Model):
                function_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Function Name")
                module_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Module Name")

            @odm.model(index=True, store=False, description="PE Imports Model")
            class FilePEImports(odm.Model):
                fuzzy = odm.Optional(odm.List(odm.SSDeepHash(copyto="__text__")), description="Fuzzy")
                md5 = odm.Optional(odm.List(odm.MD5(copyto="__text__")), description="MD5")
                imphash = odm.Optional(odm.List(odm.MD5(copyto="__text__")), description="Imphash")
                sorted_fuzzy = odm.Optional(odm.List(odm.SSDeepHash(copyto="__text__")), description="Sorted Fuzzy")
                sorted_sha1 = odm.Optional(odm.List(odm.SHA1(copyto="__text__")), description="Sorted SHA1")
                suspicious = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Suspicious")

            @odm.model(index=True, store=False, description="PE Linker Model")
            class FilePELinker(odm.Model):
                timestamp = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Timestamp")

            @odm.model(index=True, store=False, description="PE OEP Model")
            class FilePEOEP(odm.Model):
                bytes = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Bytes")
                hexdump = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Hex Dump")

            @odm.model(index=True, store=False, description="PE Resources Model")
            class FilePEResources(odm.Model):
                language = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Language")
                name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Name")

            @odm.model(index=True, store=False, description="PE Rich Header Model")
            class FilePERichHeader(odm.Model):
                hash = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Hash")

            @odm.model(index=True, store=False, description="PE Sections Model")
            class FilePESections(odm.Model):
                hash = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Hash")
                name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Name")

            @odm.model(index=True, store=False, description="PE Versions Model")
            class FilePEVersions(odm.Model):
                description = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Description")
                filename = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Filename")

            api_vector = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="API Vector")
            debug = odm.Optional(odm.Compound(FilePEDebug), description="PE Debug Information")
            exports = odm.Optional(odm.Compound(FilePEExports), description="PE Exports Information")
            imports = odm.Optional(odm.Compound(FilePEImports), description="PE Imports Information")
            linker = odm.Optional(odm.Compound(FilePELinker), description="PE Linker Information")
            oep = odm.Optional(odm.Compound(FilePEOEP), description="PE OEP Information")
            pdb_filename = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="PDB Filename")
            resources = odm.Optional(odm.Compound(FilePEResources), description="PE Resources Information")
            rich_header = odm.Optional(odm.Compound(FilePERichHeader), description="PE Rich Header Information")
            sections = odm.Optional(odm.Compound(FilePESections), description="PE Sections Information")
            versions = odm.Optional(odm.Compound(FilePEVersions), description="PE Versions Information")

        @odm.model(index=True, store=False, description="PList File Tag Model")
        class FilePList(odm.Model):
            @odm.model(index=True, store=False, description="PList Build Model")
            class FilePListBuild(odm.Model):
                machine_os = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Machine OS")

            @odm.model(index=True, store=False, description="PList CF Bundle Model")
            class FilePListCFBundle(odm.Model):
                @odm.model(index=True, store=False, description="PList CF Bundle Version Model")
                class FilePListCFBundleVersion(odm.Model):
                    long = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Long Version")
                    short = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Short Version")

                development_region = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                                  description="Development Region")
                display_name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Display Name")
                executable = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Executable Name")
                identifier = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Identifier Name")
                name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Bundle Name")
                pkg_type = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Package Type")
                signature = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Signature")
                url_scheme = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="URL Scheme")
                version = odm.Optional(odm.Compound(FilePListCFBundleVersion), description="Bundle Version Information")

            @odm.model(index=True, store=False, description="PList DT Model")
            class FilePListDT(odm.Model):
                @odm.model(index=True, store=False, description="PList DT Platform Model")
                class FilePListDTPlatform(odm.Model):
                    build = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Build")
                    name = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Name")
                    version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Version")

                compiler = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Compiler")
                platform = odm.Optional(odm.Compound(FilePListDTPlatform), description="Platform Information")

            @odm.model(index=True, store=False, description="PList LS Model")
            class FilePListLS(odm.Model):
                background_only = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Background Only")
                min_system_version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                                  description="Minimum System Versuion")

            @odm.model(index=True, store=False, description="PList NS Model")
            class FilePListNS(odm.Model):
                apple_script_enabled = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                                    description="Apple Script Enabled")
                principal_class = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Principal Class")

            @odm.model(index=True, store=False, description="PList UI Model")
            class FilePListUI(odm.Model):
                background_modes = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Background Modes")
                requires_persistent_wifi = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                                        description="Requires Persistent WIFI")

            @odm.model(index=True, store=False, description="PList WK Model")
            class FilePListWK(odm.Model):
                app_bundle_identifier = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                                     description="App Bundle ID")

            installer_url = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Installer URL")
            min_os_version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Minimum OS Version")
            requests_open_access = odm.Optional(odm.List(odm.Keyword(copyto="__text__")),
                                                description="Requests Open Access")

            build = odm.Optional(odm.Compound(FilePListBuild), description="Build Information")
            cf_bundle = odm.Optional(odm.Compound(FilePListCFBundle), description="CF Bundle Information")
            dt = odm.Optional(odm.Compound(FilePListDT), description="DT Information")
            ls = odm.Optional(odm.Compound(FilePListLS), description="LS Information")
            ns = odm.Optional(odm.Compound(FilePListNS), description="NS Information")
            ui = odm.Optional(odm.Compound(FilePListUI), description="UI Information")
            wk = odm.Optional(odm.Compound(FilePListWK), description="WK Information")

        @odm.model(index=True, store=False, description="PowerShell File Tag Model")
        class FilePowerShell(odm.Model):
            cmdlet = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Cmdlet")

        @odm.model(index=True, store=False, description="Shortcut File Tag Model")
        class FileShortcut(odm.Model):
            command_line = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Command Line")
            icon_location = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Icon Location")
            machine_id = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Machine ID")
            tracker_mac = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")), description="Possible MAC address from the Tracker block"
            )

        @odm.model(index=True, store=False, description="Strings File Model")
        class FileStrings(odm.Model):
            api = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="API")
            blacklisted = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Blacklisted")
            decoded = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Decoded")
            extracted = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Extracted")

        @odm.model(index=True, store=False, description="SWF File Tag Model")
        class FileSWF(odm.Model):
            @odm.model(index=True, store=False, description="SWF Header Model")
            class FileSWFHeader(odm.Model):
                @odm.model(index=True, store=False, description="SWF Header Frame")
                class FileSWFHeaderFrame(odm.Model):
                    count = odm.Optional(odm.List(odm.Integer()), description="Number of Frames")
                    rate = odm.Optional(odm.List(odm.Keyword()), description="Speed of Animation")
                    size = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Size of Frame")

                frame = odm.Optional(odm.Compound(FileSWFHeaderFrame), description="Header Frame Information")
                version = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Version")

            header = odm.Optional(odm.Compound(FileSWFHeader), description="Header Information")
            tags_ssdeep = odm.Optional(odm.List(odm.SSDeepHash(copyto="__text__")), description="Tags SSDeep")

        behavior = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="File Behaviour")
        compiler = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Compiler of File")
        config = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="File Configuration")
        date = odm.Optional(odm.Compound(FileDate), description="File's Date Information")
        elf = odm.Optional(odm.Compound(FileELF), description="ELF File Properties")
        lib = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="File Libraries")
        name = odm.Optional(odm.Compound(FileName), description="File Name")
        path = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="File Path")
        rule = odm.Optional(odm.Mapping(odm.List(odm.Keyword(copyto="__text__"))), description="Rule/Signature File")
        string = odm.Optional(odm.Compound(FileStrings), description="File Strings Properties")
        apk = odm.Optional(odm.Compound(FileAPK), description="APK File Properties")
        jar = odm.Optional(odm.Compound(FileJAR), description="JAR File Properties")
        img = odm.Optional(odm.Compound(FileIMG), description="Image File Properties")
        ole = odm.Optional(odm.Compound(FileOLE), description="OLE File Properties")
        pe = odm.Optional(odm.Compound(FilePE), description="PE File Properties")
        pdf = odm.Optional(odm.Compound(FilePDF), description="PDF File Properties")
        plist = odm.Optional(odm.Compound(FilePList), description="PList File Properties")
        powershell = odm.Optional(odm.Compound(FilePowerShell), description="PowerShell File Properties")
        shortcut = odm.Optional(odm.Compound(FileShortcut), description="Shortcut File Properties")
        swf = odm.Optional(odm.Compound(FileSWF), description="SWF File Properties")

    @odm.model(index=True, store=False, description="Network Tag Model")
    class Network(odm.Model):
        @odm.model(index=True, store=False, description="Network IOC Model")
        class NetworkIOCs(odm.Model):
            domain = odm.Optional(odm.List(odm.Domain(copyto="__text__")), description="Domain")
            ip = odm.Optional(odm.List(odm.IP(copyto="__text__")), description="IP")
            uri = odm.Optional(odm.List(odm.URI(copyto="__text__")), description="URI")
            uri_path = odm.Optional(odm.List(odm.URIPath(copyto="__text__")), description="URI Path")

        @odm.model(index=True, store=False, description="Network Email Model")
        class NetworkEmail(odm.Model):
            address = odm.Optional(odm.List(odm.Email(copyto="__text__")), description="Email Address")
            date = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Date")
            subject = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Subject")
            msg_id = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Message ID")

        @odm.model(index=True, store=False, description="Network Signature Model")
        class NetworkSignature(odm.Model):
            signature_id = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Signature ID")
            message = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Signature Message")

        @odm.model(index=True, store=False, description="Network TLS Model")
        class NetworkTLS(odm.Model):
            ja3_hash = odm.Optional(odm.List(odm.MD5(copyto="__text__")), description="JA3 Hash")
            ja3_string = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="JA3 String")
            sni = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="SNI")

        attack = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Attack")
        dynamic = odm.Optional(odm.Compound(NetworkIOCs), description="Dynamic IOCs")
        email = odm.Optional(odm.Compound(NetworkEmail), description="Email")
        mac_address = odm.Optional(odm.List(odm.MAC(copyto="__text__")), description="MAC Address")
        port = odm.Optional(odm.List(odm.Integer()), description="Port")
        protocol = odm.Optional(odm.List(odm.Keyword()), description="Protocol")
        signature = odm.Optional(odm.Compound(NetworkSignature), description="Signatures")
        static = odm.Optional(odm.Compound(NetworkIOCs), description="Static IOCs")
        tls = odm.Optional(odm.Compound(NetworkTLS), description="TLS")
        user_agent = odm.Optional(odm.List(odm.Keyword()), description="User Agent")

    @odm.model(index=True, store=False, description="Technique Tag Model")
    class Technique(odm.Model):
        comms_routine = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Communication Routine")
        config = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Configuration")
        crypto = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Cryptography")
        keylogger = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Keylogger")
        macro = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Macro")
        masking_algo = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Masking Algorithm")
        obfuscation = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Obfuscation")
        packer = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Packer")
        persistence = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Persistence")
        shellcode = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Shell Code")
        string = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="String")

    attribution = odm.Optional(odm.Compound(Attribution), description="Attribution Tagging")
    av = odm.Optional(odm.Compound(AV), description="Antivirus Tagging")
    cert = odm.Optional(odm.Compound(Cert), description="Certificate Tagging")
    dynamic = odm.Optional(odm.Compound(Dynamic), description="Dynamic Analysis Tagging")
    info = odm.Optional(odm.Compound(Info), description="Informational Tagging")
    file = odm.Optional(odm.Compound(File), description="File Tagging")
    network = odm.Optional(odm.Compound(Network), description="Network Tagging")
    source = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Source Tagging")
    technique = odm.Optional(odm.Compound(Technique), description="Technique Tagging")
    vector = odm.Optional(odm.List(odm.Keyword(copyto="__text__")), description="Vector Tagging")


if __name__ == "__main__":
    from pprint import pprint

    pprint(list(Tagging().flat_fields().keys()))
