from assemblyline import odm


@odm.model(
    index=True,
    store=False,
    description="Top-level model containing all tagging metadata for an analysis.",
)
class Tagging(odm.Model):
    @odm.model(
        index=True,
        store=False,
        description="Attribution-related tags such as actors, campaigns, and families.",
    )
    class Attribution(odm.Model):
        actor = odm.Optional(
            odm.List(odm.UpperKeyword(copyto="__text__")),
            description="Threat actors or groups attributed to this sample.",
        )
        campaign = odm.Optional(
            odm.List(odm.UpperKeyword(copyto="__text__")),
            description="Named campaigns or operations associated with this sample.",
        )
        category = odm.Optional(
            odm.List(odm.UpperKeyword(copyto="__text__")),
            description="High-level attribution categories (e.g. crimeware, nation-state).",
        )
        exploit = odm.Optional(
            odm.List(odm.UpperKeyword(copyto="__text__")),
            description="Named exploits or vulnerability identifiers used by this sample.",
        )
        implant = odm.Optional(
            odm.List(odm.UpperKeyword(copyto="__text__")),
            description="Malware implants or tools linked to the attributed actor.",
        )
        family = odm.Optional(
            odm.List(odm.UpperKeyword(copyto="__text__")),
            description="Malware families or codebases related to this sample.",
        )
        network = odm.Optional(
            odm.List(odm.UpperKeyword(copyto="__text__")),
            description="Network infrastructure or clusters used for attribution.",
        )

    @odm.model(
        index=True,
        store=False,
        description="Tags derived from antivirus detections and heuristics.",
    )
    class AV(odm.Model):
        heuristic = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Antivirus heuristic names or identifiers triggered by the sample.",
        )
        virus_name = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Virus or malware names reported by antivirus engines.",
        )

    @odm.model(
        index=True,
        store=False,
        description="Metadata tags extracted from digital certificates.",
    )
    class Cert(odm.Model):
        @odm.model(
            index=True,
            store=False,
            description="Certificate validity period (notBefore / notAfter).",
        )
        class CertValid(odm.Model):
            start = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Earliest date from which the certificate is valid.",
            )
            end = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Latest date until which the certificate is valid.",
            )

        extended_key_usage = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Extended key usage values indicating allowed certificate purposes.",
        )
        issuer = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Issuer distinguished name fields for the certificate.",
        )
        key_usage = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Key usage flags describing how the certificate key may be used.",
        )
        owner = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Subject entity that owns or controls the certificate.",
        )
        serial_no = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Certificate serial numbers.",
        )
        signature_algo = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Signature algorithm used to sign the certificate.",
        )
        subject = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Certificate subject distinguished name.",
        )
        subject_alt_name = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Subject alternative names (e.g. DNS names, IPs, emails).",
        )
        thumbprint = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Certificate thumbprints (hashes of the full certificate).",
        )
        valid = odm.Optional(
            odm.Compound(CertValid),
            description="Structured validity period information for the certificate.",
        )
        version = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Certificate version numbers.",
        )

    @odm.model(
        index=True,
        store=False,
        description="Tags describing code-level relationships between samples.",
    )
    class Code(odm.Model):
        sha256 = odm.Optional(
            odm.List(odm.SHA256(copyto="__text__")),
            description="SHA256 hashes of related code blobs, modules, or snippets.",
        )

    @odm.model(
        index=True,
        store=False,
        description="Tags produced by dynamic/sandbox analysis about runtime behavior.",
    )
    class Dynamic(odm.Model):
        @odm.model(
            index=True,
            store=False,
            description="Processes observed during dynamic execution.",
        )
        class DynamicProcess(odm.Model):
            command_line = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Command-line strings for processes started at runtime.",
            )
            file_name = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Executable or script filenames launched by the sample.",
            )
            shortcut = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Shortcut (.lnk) names or targets created or accessed.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Dynamic analysis signatures that fired.",
        )
        class DynamicSignature(odm.Model):
            category = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="High-level behavioral category for the dynamic signature.",
            )
            family = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Malware family name associated with the dynamic signature.",
            )
            name = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Human-readable name of the dynamic analysis signature.",
            )

        @odm.model(
            index=True,
            store=False,
            description="SSDeep-based similarity hashes for dynamic artifacts.",
        )
        class DynamicSSDeep(odm.Model):
            cls_ids = odm.Optional(
                odm.List(odm.SSDeepHash(copyto="__text__")),
                description="SSDeep hashes of CLSID-like identifiers seen during analysis.",
            )
            dynamic_classes = odm.Optional(
                odm.List(odm.SSDeepHash(copyto="__text__")),
                description="SSDeep hashes of dynamically loaded classes or COM objects.",
            )
            regkeys = odm.Optional(
                odm.List(odm.SSDeepHash(copyto="__text__")),
                description="SSDeep hashes of registry key strings accessed at runtime.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Raw Windows-related identifiers from dynamic analysis.",
        )
        class DynamicWindow(odm.Model):
            cls_ids = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="CLSIDs or similar identifiers observed during execution.",
            )
            dynamic_classes = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Names of dynamically loaded classes or COM objects.",
            )
            regkeys = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Registry key paths accessed or modified.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Operating system environment in the sandbox.",
        )
        class DynamicOperatingSystem(odm.Model):
            platform = odm.Optional(
                odm.List(odm.Platform(copyto="__text__")),
                description="OS platform identifiers (e.g. Windows, Linux).",
            )
            version = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="OS version strings observed (e.g. 10.0.19045).",
            )
            processor = odm.Optional(
                odm.List(odm.Processor(copyto="__text__")),
                description="CPU architecture (e.g. x86, x64) used in the sandbox.",
            )

        autorun_location = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Locations where persistence or autorun entries were created.",
        )
        dos_device = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="DOS device paths (e.g. \\\\.\\) referenced during execution.",
        )
        mutex = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Mutex names used for synchronization or infection markers.",
        )
        registry_key = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Registry keys created, read, or modified at runtime.",
        )
        process = odm.Optional(
            odm.Compound(DynamicProcess),
            description="Structured process information from sandbox execution.",
        )
        signature = odm.Optional(
            odm.Compound(DynamicSignature),
            description="Structured list of sandbox or dynamic signatures that fired.",
        )
        ssdeep = odm.Optional(
            odm.Compound(DynamicSSDeep),
            description="SSDeep-based fingerprints derived from dynamic artifacts.",
        )
        window = odm.Optional(
            odm.Compound(DynamicWindow),
            description="Windows opened during dynamic analysis.",
        )
        operating_system = odm.Optional(
            odm.Compound(DynamicOperatingSystem),
            description="Operating-system metadata from the sandbox environment.",
        )
        processtree_id = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Identifiers for nodes in the sandbox process tree.",
        )

    @odm.model(
        index=True,
        store=False,
        description="General informational tags extracted from content.",
    )
    class Info(odm.Model):
        phone_number = odm.Optional(
            odm.List(odm.PhoneNumber(copyto="__text__")),
            description="Phone numbers extracted from the sample.",
        )
        password = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Passwords or password-like strings extracted from the sample.",
        )

    @odm.model(
        index=True,
        store=False,
        description="Tags describing file structure, content, and embedded formats.",
    )
    class File(odm.Model):
        @odm.model(
            index=True,
            store=False,
            description="Metadata extracted from Android APK packages.",
        )
        class FileAPK(odm.Model):
            @odm.model(
                index=True,
                store=False,
                description="High-level information about the Android application.",
            )
            class FileAPKApp(odm.Model):
                label = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="User-facing application label shown on the device.",
                )
                version = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Application version strings from the manifest.",
                )

            @odm.model(
                index=True, store=False, description="Android SDK version requirements."
            )
            class FileAPKSDK(odm.Model):
                min = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Minimum Android SDK/API level required to run the app.",
                )
                target = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Target Android SDK/API level the app was built for.",
                )

            activity = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Declared Android activities within the APK.",
            )
            app = odm.Optional(
                odm.Compound(FileAPKApp),
                description="Application-level information from the APK.",
            )
            feature = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Optional hardware or software features requested by the app.",
            )
            locale = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Locales or languages supported by the application.",
            )
            permission = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Android permissions requested by the application.",
            )
            pkg_name = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Application package names (e.g. com.example.app).",
            )
            provides_component = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Components exposed by the APK (activities, services, providers, etc.).",
            )
            sdk = odm.Optional(
                odm.Compound(FileAPKSDK),
                description="Structured Android SDK version information for the app.",
            )
            used_library = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Third-party or system libraries referenced by the APK.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Timestamp-related metadata associated with the file.",
        )
        class FileDate(odm.Model):
            creation = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="File creation timestamps.",
            )
            last_modified = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="File last-modified timestamps.",
            )

        @odm.model(
            index=True, store=False, description="Metadata extracted from ELF binaries."
        )
        class FileELF(odm.Model):
            @odm.model(
                index=True,
                store=False,
                description="Information about individual ELF sections.",
            )
            class FileELFSections(odm.Model):
                name = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Names of sections within the ELF file.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Information about ELF program segments.",
            )
            class FileELFSegments(odm.Model):
                type = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Segment type identifiers (e.g. LOAD, DYNAMIC).",
                )

            @odm.model(
                index=True,
                store=False,
                description="Metadata contained in ELF NOTE segments.",
            )
            class FileELFNotes(odm.Model):
                name = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="ELF note or owner names.",
                )
                type = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="ELF note type identifiers.",
                )
                type_core = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Core-dump related ELF note type identifiers.",
                )

            libraries = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Shared libraries linked by the ELF file.",
            )
            interpreter = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Dynamic loader or interpreter path used by the ELF.",
            )
            sections = odm.Optional(
                odm.Compound(FileELFSections),
                description="Structured metadata for ELF sections.",
            )
            segments = odm.Optional(
                odm.Compound(FileELFSegments),
                description="Structured metadata for ELF program segments.",
            )
            notes = odm.Optional(
                odm.Compound(FileELFNotes),
                description="Structured metadata for ELF notes.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Metadata extracted from image files and containers.",
        )
        class FileIMG(odm.Model):
            @odm.model(
                index=True,
                store=False,
                description="Exiftool-derived metadata about the image.",
            )
            class FileIMGExiftool(odm.Model):
                creator_tool = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Application or tool reported as having created the image.",
                )
                derived_document_id = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Identifier for a document derived from the original source.",
                )
                document_id = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Original document identifier stored in metadata.",
                )
                instance_id = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Unique identifier for this specific file instance.",
                )
                toolkit = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Toolkit or library used to generate or edit the image.",
                )

            exif_tool = odm.Optional(
                odm.Compound(FileIMGExiftool),
                description="Exiftool metadata for the image.",
            )
            mega_pixels = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Image size expressed in megapixels.",
            )
            mode = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Mode field from image metadata, typically indicating how the image was captured or encoded.",
            )
            size = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Image dimensions or overall size information.",
            )
            sorted_metadata_hash = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Hash of normalized and sorted metadata fields.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Metadata extracted from Java JAR archives.",
        )
        class FileJAR(odm.Model):
            main_class = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Main class specified in the JAR manifest.",
            )
            main_package = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Package containing the main class.",
            )
            imported_package = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Referenced or imported Java packages.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Observed file name variants and anomalies.",
        )
        class FileName(odm.Model):
            anomaly = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Suspicious or unusual filename patterns.",
            )
            extracted = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Names of files extracted from the original sample.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Metadata extracted from OLE/Office compound documents.",
        )
        class FileOLE(odm.Model):
            @odm.model(
                index=True,
                store=False,
                description="Information about embedded OLE macros.",
            )
            class FileOLEMacro(odm.Model):
                sha256 = odm.Optional(
                    odm.List(odm.SHA256(copyto="__text__")),
                    description="SHA256 hashes of extracted macro streams.",
                )
                suspicious_string = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Strings from macros that were flagged as suspicious.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Standard document summary properties from OLE.",
            )
            class FileOLESummary(odm.Model):
                author = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Document author metadata.",
                )
                codepage = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Character encoding or code page information.",
                )
                comment = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Document comments or summary notes.",
                )
                company = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Company or organization name from metadata.",
                )
                create_time = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Original document creation timestamp.",
                )
                last_printed = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Timestamp when the document was last printed.",
                )
                last_saved_by = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="User name that last saved the document.",
                )
                last_saved_time = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Timestamp when the document was last saved.",
                )
                manager = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Manager field from document properties.",
                )
                subject = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Document subject or brief description.",
                )
                title = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Document title string.",
                )

            macro = odm.Optional(
                odm.Compound(FileOLEMacro),
                description="Structured metadata describing macros embedded in the file.",
            )
            summary = odm.Optional(
                odm.Compound(FileOLESummary),
                description="Structured summary/document-property metadata.",
            )
            clsid = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Class IDs (CLSIDs) for embedded OLE objects.",
            )
            dde_link = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Dynamic Data Exchange (DDE) link targets.",
            )
            fib_timestamp = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Timestamps from the File Information Block (FIB).",
            )

        @odm.model(
            index=True,
            store=False,
            description="Metadata and analysis artifacts from PDF documents.",
        )
        class FilePDF(odm.Model):
            @odm.model(
                index=True,
                store=False,
                description="Date-related metadata fields from the PDF.",
            )
            class FilePDFDate(odm.Model):
                modified = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="PDF modification timestamps.",
                )
                pdfx = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="PDF/X standard-related metadata values.",
                )
                source_modified = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Timestamp when the source document was last modified.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Metadata about JavaScript embedded in the PDF.",
            )
            class FilePDFJavascript(odm.Model):
                sha1 = odm.Optional(
                    odm.List(odm.SHA1(copyto="__text__")),
                    description="SHA1 hashes of JavaScript streams found in the PDF.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Statistical fingerprints for the PDF structure.",
            )
            class FilePDFStats(odm.Model):
                sha1 = odm.Optional(
                    odm.List(odm.SHA1(copyto="__text__")),
                    description="SHA1 hashes representing PDF structural statistics.",
                )

            date = odm.Optional(
                odm.Compound(FilePDFDate),
                description="Structured collection of PDF date-related metadata.",
            )
            javascript = odm.Optional(
                odm.Compound(FilePDFJavascript),
                description="Structured metadata about JavaScript embedded inside the PDF.",
            )
            stats = odm.Optional(
                odm.Compound(FilePDFStats),
                description="Structured statistics metadata describing the PDF layout.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Metadata extracted from Windows PE executables and libraries.",
        )
        class FilePE(odm.Model):
            @odm.model(
                index=True,
                store=False,
                description="Debug directory information from the PE file.",
            )
            class FilePEDebug(odm.Model):
                guid = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Debug GUIDs (e.g. PDB signature identifiers).",
                )

            @odm.model(
                index=True,
                store=False,
                description="Information about exported PE functions.",
            )
            class FilePEExports(odm.Model):
                function_name = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Names of functions exported by the PE file.",
                )
                module_name = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Name of the module (DLL/EXE) providing the export.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Information and fingerprints of imported PE functions.",
            )
            class FilePEImports(odm.Model):
                fuzzy = odm.Optional(
                    odm.List(odm.SSDeepHash(copyto="__text__")),
                    description="SSDeep hashes computed over the import table.",
                )
                md5 = odm.Optional(
                    odm.List(odm.MD5(copyto="__text__")),
                    description="MD5 hashes representing imported symbols or modules.",
                )
                imphash = odm.Optional(
                    odm.List(odm.MD5(copyto="__text__")),
                    description="Canonical import-hash (imphash) values for the PE.",
                )
                sorted_fuzzy = odm.Optional(
                    odm.List(odm.SSDeepHash(copyto="__text__")),
                    description="Fuzzy hashes computed over sorted import entries.",
                )
                sorted_sha1 = odm.Optional(
                    odm.List(odm.SHA1(copyto="__text__")),
                    description="SHA1 hashes computed over sorted import entries.",
                )
                gimphash = odm.Optional(
                    odm.List(odm.SHA256(copyto="__text__")),
                    description="Go-style import-hash values for Go binaries.",
                )
                suspicious = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Flags or descriptors for suspicious import patterns.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Metadata related to the PE linker.",
            )
            class FilePELinker(odm.Model):
                timestamp = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Linker timestamp value from the PE header.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Metadata about the PE original entry point (OEP).",
            )
            class FilePEOEP(odm.Model):
                bytes = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Raw bytes taken around the entry point.",
                )
                hexdump = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Hexadecimal dump of bytes at the entry point.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Metadata about embedded PE resources.",
            )
            class FilePEResources(odm.Model):
                language = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Resource language identifiers.",
                )
                name = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Resource names or identifiers.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Information about the PE Rich header.",
            )
            class FilePERichHeader(odm.Model):
                hash = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Hashes summarizing Rich header contents.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Information about sections within the PE file.",
            )
            class FilePESections(odm.Model):
                hash = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Hashes of section contents or characteristics.",
                )
                name = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Section names (e.g. .text, .rsrc).",
                )

            @odm.model(
                index=True,
                store=False,
                description="Version-information resources from the PE file.",
            )
            class FilePEVersions(odm.Model):
                description = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Product or file description from version info.",
                )
                filename = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Original filename recorded in version info.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Authenticode signature and catalog metadata.",
            )
            class FilePEAuthenticode(odm.Model):
                @odm.model(
                    index=True,
                    store=False,
                    description="SpcSpOpusInfo attributes describing the signed program.",
                )
                class FilePEAuthenticodeSpcSpOpusInfo(odm.Model):
                    program_name = odm.Optional(
                        odm.List(odm.Keyword(copyto="__text__")),
                        description="Program name string from the Authenticode signature.",
                    )

                spc_sp_opus_info = odm.Optional(
                    odm.Compound(FilePEAuthenticodeSpcSpOpusInfo),
                    description="SpcSpOpusInfo metadata about the signed program.",
                )

            api_vector = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Vector of imported or used APIs summarizing sample behavior.",
            )
            authenticode = odm.Optional(
                odm.Compound(FilePEAuthenticode),
                description="Authenticode signature metadata for the PE.",
            )
            debug = odm.Optional(
                odm.Compound(FilePEDebug),
                description="Debug directory metadata from the PE.",
            )
            exports = odm.Optional(
                odm.Compound(FilePEExports), description="PE export table metadata."
            )
            imports = odm.Optional(
                odm.Compound(FilePEImports),
                description="PE import table metadata and associated hashes.",
            )
            linker = odm.Optional(
                odm.Compound(FilePELinker), description="PE linker metadata."
            )
            oep = odm.Optional(
                odm.Compound(FilePEOEP),
                description="Entry-point bytes and hexdump information.",
            )
            pdb_filename = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Names or paths of referenced PDB debug symbol files.",
            )
            resources = odm.Optional(
                odm.Compound(FilePEResources), description="PE resource metadata."
            )
            rich_header = odm.Optional(
                odm.Compound(FilePERichHeader),
                description="Rich header metadata for the PE.",
            )
            sections = odm.Optional(
                odm.Compound(FilePESections),
                description="Metadata describing PE sections.",
            )
            versions = odm.Optional(
                odm.Compound(FilePEVersions), description="Version resource metadata."
            )

        @odm.model(
            index=True,
            store=False,
            description="Metadata extracted from Apple property list (plist) files.",
        )
        class FilePList(odm.Model):
            @odm.model(
                index=True,
                store=False,
                description="Build-environment metadata from the plist.",
            )
            class FilePListBuild(odm.Model):
                machine_os = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Operating system version of the build machine.",
                )

            @odm.model(
                index=True, store=False, description="CFBundle-related bundle metadata."
            )
            class FilePListCFBundle(odm.Model):
                @odm.model(
                    index=True,
                    store=False,
                    description="Bundle version metadata.",
                )
                class FilePListCFBundleVersion(odm.Model):
                    long = odm.Optional(
                        odm.List(odm.Keyword(copyto="__text__")),
                        description="Full or long-form bundle version string.",
                    )
                    short = odm.Optional(
                        odm.List(odm.Keyword(copyto="__text__")),
                        description="Short marketing version string.",
                    )

                development_region = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Default localization or development region.",
                )
                display_name = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Human-readable application display name.",
                )
                executable = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Name of the main executable binary.",
                )
                identifier = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Bundle identifier string (e.g. com.example.app).",
                )
                name = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Internal bundle name.",
                )
                pkg_type = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Package type code (e.g. APPL).",
                )
                signature = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Legacy creator/signature code values.",
                )
                url_scheme = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Custom URL schemes registered by the application.",
                )
                version = odm.Optional(
                    odm.Compound(FilePListCFBundleVersion),
                    description="Structured bundle version information.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Developer tools (DT*) metadata fields.",
            )
            class FilePListDT(odm.Model):
                @odm.model(
                    index=True,
                    store=False,
                    description="Platform-specific build metadata.",
                )
                class FilePListDTPlatform(odm.Model):
                    build = odm.Optional(
                        odm.List(odm.Keyword(copyto="__text__")),
                        description="Platform build identifier.",
                    )
                    name = odm.Optional(
                        odm.List(odm.Keyword(copyto="__text__")),
                        description="Platform name (e.g. iPhoneOS, MacOSX).",
                    )
                    version = odm.Optional(
                        odm.List(odm.Keyword(copyto="__text__")),
                        description="Platform version number.",
                    )

                compiler = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Compiler or build tool identifier.",
                )
                platform = odm.Optional(
                    odm.Compound(FilePListDTPlatform),
                    description="Structured platform metadata used for building the app.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Launch Services (LS*) metadata from the plist.",
            )
            class FilePListLS(odm.Model):
                background_only = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Indicates whether the app is background-only.",
                )
                min_system_version = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Minimum operating system version required by Launch Services.",
                )

            @odm.model(
                index=True,
                store=False,
                description="Cocoa (NS*) behavior flags from the plist.",
            )
            class FilePListNS(odm.Model):
                apple_script_enabled = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Whether AppleScript automation is allowed for the app.",
                )
                principal_class = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Name of the app's principal Objective-C class.",
                )

            @odm.model(
                index=True,
                store=False,
                description="User-interface-related plist keys.",
            )
            class FilePListUI(odm.Model):
                background_modes = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="UI background modes the app declares.",
                )
                requires_persistent_wifi = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Indicates if the app requires persistent Wi-Fi connectivity.",
                )

            @odm.model(
                index=True, store=False, description="WatchKit or WK* related metadata."
            )
            class FilePListWK(odm.Model):
                app_bundle_identifier = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="Bundle identifier of the associated application.",
                )

            installer_url = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="URL used to obtain or install the app.",
            )
            min_os_version = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Minimum OS version required to run the software.",
            )
            requests_open_access = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Indicates whether a component (e.g. keyboard) requests full access.",
            )

            build = odm.Optional(
                odm.Compound(FilePListBuild),
                description="Structured build-environment details from the plist.",
            )
            cf_bundle = odm.Optional(
                odm.Compound(FilePListCFBundle),
                description="Structured CFBundle-related metadata.",
            )
            dt = odm.Optional(
                odm.Compound(FilePListDT),
                description="Structured developer tools (DT*) metadata.",
            )
            ls = odm.Optional(
                odm.Compound(FilePListLS),
                description="Structured Launch Services configuration from the plist.",
            )
            ns = odm.Optional(
                odm.Compound(FilePListNS),
                description="Structured Cocoa (NS*) configuration and behaviors.",
            )
            ui = odm.Optional(
                odm.Compound(FilePListUI),
                description="Structured UI behavior metadata.",
            )
            wk = odm.Optional(
                odm.Compound(FilePListWK),
                description="Structured WatchKit (WK*) metadata.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Metadata extracted from PowerShell files or commands.",
        )
        class FilePowerShell(odm.Model):
            cmdlet = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="PowerShell cmdlets referenced or invoked by the script.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Metadata from Windows shortcut (.lnk) files.",
        )
        class FileShortcut(odm.Model):
            command_line = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Command line stored in or invoked by the shortcut.",
            )
            icon_location = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Path of the icon referenced by the shortcut.",
            )
            machine_id = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Machine identifier recorded within the shortcut.",
            )
            tracker_mac = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Potential MAC addresses recovered from the shortcut tracker block.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Categorized strings extracted from the file.",
        )
        class FileStrings(odm.Model):
            api = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Extracted strings that resemble API or function names.",
            )
            blacklisted = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Strings matching blacklist patterns or known bad indicators.",
            )
            decoded = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Strings obtained after decoding or deobfuscation.",
            )
            extracted = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Raw printable strings extracted from the file.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Metadata extracted from Adobe Flash (SWF) files.",
        )
        class FileSWF(odm.Model):
            @odm.model(
                index=True,
                store=False,
                description="Header-level metadata from the SWF file.",
            )
            class FileSWFHeader(odm.Model):
                @odm.model(
                    index=True,
                    store=False,
                    description="Frame-rate and size information from the SWF header.",
                )
                class FileSWFHeaderFrame(odm.Model):
                    count = odm.Optional(
                        odm.List(odm.Integer()),
                        description="Total number of frames in the SWF animation.",
                    )
                    rate = odm.Optional(
                        odm.List(odm.Keyword(copyto="__text__")),
                        description="Frame rate (speed) of the SWF animation.",
                    )
                    size = odm.Optional(
                        odm.List(odm.Keyword(copyto="__text__")),
                        description="Logical stage size or frame dimensions.",
                    )

                frame = odm.Optional(
                    odm.Compound(FileSWFHeaderFrame),
                    description="Structured SWF header frame information.",
                )
                version = odm.Optional(
                    odm.List(odm.Keyword(copyto="__text__")),
                    description="SWF file format version.",
                )

            header = odm.Optional(
                odm.Compound(FileSWFHeader),
                description="Structured SWF header metadata.",
            )
            tags_ssdeep = odm.Optional(
                odm.List(odm.SSDeepHash(copyto="__text__")),
                description="SSDeep hashes computed over SWF tags for similarity.",
            )

        ancestry = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Tags describing file genealogy or derivation relationships.",
        )
        behavior = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Behavioral characteristics inferred from analysis.",
        )
        compiler = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Compiler or toolchain used to build the file.",
        )
        config = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Configuration blocks or key-value settings extracted from the file.",
        )
        date = odm.Optional(
            odm.Compound(FileDate),
            description="Structured date and timestamp metadata for the file.",
        )
        elf = odm.Optional(
            odm.Compound(FileELF),
            description="Structured properties specific to ELF binaries.",
        )
        lib = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Libraries the file depends on or bundles.",
        )
        lsh = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Locality-sensitive hashes (LSH) computed for fuzzy similarity.",
        )
        name = odm.Optional(
            odm.Compound(FileName),
            description="Structured tags describing observed file names and anomalies.",
        )
        path = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="File system or archive paths where the file was seen.",
        )
        rule = odm.Optional(
            odm.Mapping(odm.List(odm.Keyword(copyto="__text__"))),
            description="Rules or signatures that matched this file, grouped by source.",
        )
        string = odm.Optional(
            odm.Compound(FileStrings),
            description="Structured categories of strings extracted from the file.",
        )
        apk = odm.Optional(
            odm.Compound(FileAPK),
            description="Detailed properties specific to Android APK files.",
        )
        jar = odm.Optional(
            odm.Compound(FileJAR),
            description="Detailed properties specific to Java JAR archives.",
        )
        img = odm.Optional(
            odm.Compound(FileIMG),
            description="Detailed properties specific to image files.",
        )
        ole = odm.Optional(
            odm.Compound(FileOLE),
            description="Detailed properties specific to OLE/Office documents.",
        )
        pe = odm.Optional(
            odm.Compound(FilePE),
            description="Detailed properties specific to Windows PE binaries.",
        )
        pdf = odm.Optional(
            odm.Compound(FilePDF),
            description="Detailed properties specific to PDF documents.",
        )
        plist = odm.Optional(
            odm.Compound(FilePList),
            description="Detailed properties specific to Apple plist files.",
        )
        powershell = odm.Optional(
            odm.Compound(FilePowerShell),
            description="Detailed properties specific to PowerShell scripts.",
        )
        shortcut = odm.Optional(
            odm.Compound(FileShortcut),
            description="Detailed properties specific to Windows shortcut files.",
        )
        swf = odm.Optional(
            odm.Compound(FileSWF),
            description="Detailed properties specific to SWF files.",
        )

    @odm.model(
        index=True,
        store=False,
        description="Tags for network indicators and traffic-related artifacts.",
    )
    class Network(odm.Model):
        @odm.model(
            index=True,
            store=False,
            description="Network indicators of compromise (IOCs).",
        )
        class NetworkIOCs(odm.Model):
            domain = odm.Optional(
                odm.List(odm.Domain(copyto="__text__")),
                description="Domain names contacted, embedded, or otherwise referenced.",
            )
            ip = odm.Optional(
                odm.List(odm.IP(copyto="__text__")),
                description="IP addresses contacted, embedded, or otherwise referenced.",
            )
            unc_path = odm.Optional(
                odm.List(odm.UNCPath(copyto="__text__")),
                description="Windows UNC paths (\\\\server\\share) used by the sample.",
            )
            uri = odm.Optional(
                odm.List(odm.URI(copyto="__text__")),
                description="Full URIs or URLs observed (including scheme and host).",
            )
            uri_path = odm.Optional(
                odm.List(odm.URIPath(copyto="__text__")),
                description="URI path components without scheme or host.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Metadata from email-related network artifacts.",
        )
        class NetworkEmail(odm.Model):
            address = odm.Optional(
                odm.List(odm.Email(copyto="__text__")),
                description="Sender or recipient email addresses observed.",
            )
            date = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Email date header values.",
            )
            subject = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Email subject lines.",
            )
            msg_id = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Email Message-ID header values.",
            )

        @odm.model(
            index=True,
            store=False,
            description="Network IDS/IPS or rule-engine signatures.",
        )
        class NetworkSignature(odm.Model):
            signature_id = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Identifier of the network detection signature (e.g. SID).",
            )
            message = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Human-readable description of the network signature.",
            )

        @odm.model(
            index=True, store=False, description="TLS fingerprint and metadata tags."
        )
        class NetworkTLS(odm.Model):
            ja3_hash = odm.Optional(
                odm.List(odm.MD5(copyto="__text__")),
                description="MD5 hash of the JA3 TLS client fingerprint.",
            )
            ja3_string = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Raw JA3 TLS client fingerprint string.",
            )
            ja3s_hash = odm.Optional(
                odm.List(odm.MD5(copyto="__text__")),
                description="MD5 hash of the JA3S TLS server fingerprint.",
            )
            ja3s_string = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Raw JA3S TLS server fingerprint string.",
            )
            ja4_hash = odm.Optional(
                odm.List(
                    odm.ValidatedKeyword(
                        validation_regex=odm.JA4_REGEX, copyto="__text__"
                    )
                ),
                description="Validated JA4 TLS client fingerprint hash.",
            )
            ja4s_hash = odm.Optional(
                odm.List(
                    odm.ValidatedKeyword(
                        validation_regex=odm.JA4_REGEX, copyto="__text__"
                    )
                ),
                description="Validated JA4S TLS server fingerprint hash.",
            )
            sni = odm.Optional(
                odm.List(odm.Keyword(copyto="__text__")),
                description="Server Name Indication (SNI) values from TLS handshakes.",
            )

        attack = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="High-level classification of observed or attempted attacks.",
        )
        dynamic = odm.Optional(
            odm.Compound(NetworkIOCs),
            description="Network IOCs derived from dynamic/sandbox analysis.",
        )
        email = odm.Optional(
            odm.Compound(NetworkEmail),
            description="Structured email-related network metadata.",
        )
        mac_address = odm.Optional(
            odm.List(odm.MAC(copyto="__text__")),
            description="MAC addresses observed in network or related artifacts.",
        )
        port = odm.Optional(
            odm.List(odm.Integer()),
            description="Network port numbers used by the sample.",
        )
        protocol = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Application or transport protocols observed (e.g. HTTP, TCP).",
        )
        signature = odm.Optional(
            odm.Compound(NetworkSignature),
            description="Structured metadata for network detection signatures.",
        )
        static = odm.Optional(
            odm.Compound(NetworkIOCs),
            description="Network IOCs derived from static analysis of the sample.",
        )
        tls = odm.Optional(
            odm.Compound(NetworkTLS),
            description="Structured TLS handshake and fingerprint information.",
        )
        user_agent = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="HTTP or other user-agent strings observed.",
        )

    @odm.model(
        index=True,
        store=False,
        description="Tags capturing techniques and tradecraft used by the sample.",
    )
    class Technique(odm.Model):
        comms_routine = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Patterns or routines used for C2 or other communications.",
        )
        config = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Technique-related configuration data (e.g. keys, flags).",
        )
        crypto = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Use of cryptographic algorithms, keys, or primitives.",
        )
        exploit = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Exploit techniques or identifiers used by the sample.",
        )
        keylogger = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Keylogging components or behaviors.",
        )
        macro = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Macro-based execution techniques or mechanisms.",
        )
        masking_algo = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Algorithms used for masking, encoding, or hiding data.",
        )
        obfuscation = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Obfuscation or anti-analysis techniques observed.",
        )
        packer = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Packers or protectors used to wrap the sample.",
        )
        persistence = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Persistence techniques used to survive reboot or logoff.",
        )
        shellcode = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Shellcode payloads or shellcode-based techniques.",
        )
        string = odm.Optional(
            odm.List(odm.Keyword(copyto="__text__")),
            description="Technique-related string patterns (e.g. markers, protocol strings).",
        )

    attribution = odm.Optional(
        odm.Compound(Attribution),
        description="All attribution-related tags (actors, campaigns, tooling, etc.).",
    )
    av = odm.Optional(
        odm.Compound(AV),
        description="Tags derived from antivirus detection names and heuristics.",
    )
    cert = odm.Optional(
        odm.Compound(Cert),
        description="Tags derived from digital certificates and related fields.",
    )
    code = odm.Optional(
        odm.Compound(Code),
        description="Tags capturing relationships to other code samples.",
    )
    dynamic = odm.Optional(
        odm.Compound(Dynamic),
        description="Tags generated from sandbox or other dynamic analysis.",
    )
    info = odm.Optional(
        odm.Compound(Info),
        description="General informational tags not covered by other categories.",
    )
    file = odm.Optional(
        odm.Compound(File),
        description="Tags describing file content, structure, and embedded formats.",
    )
    network = odm.Optional(
        odm.Compound(Network),
        description="Tags describing network indicators and communication patterns.",
    )
    source = odm.Optional(
        odm.List(odm.Keyword(copyto="__text__")),
        description="Tags describing where the sample or tagging information originated.",
    )
    technique = odm.Optional(
        odm.Compound(Technique),
        description="Tags summarizing techniques, tactics, and tradecraft used.",
    )
    vector = odm.Optional(
        odm.List(odm.Keyword(copyto="__text__")),
        description="Tags describing delivery or infection vectors for the sample.",
    )

if __name__ == "__main__":
    from pprint import pprint

    pprint(list(Tagging().flat_fields().keys()))
