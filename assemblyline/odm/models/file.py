from assemblyline import odm

REACTIONS_TYPES = {"thumbs_up", "thumbs_down", "love", "smile", "surprised", "party"}


@odm.model(index=True, store=True, description="""Detailed breakdown model of a file's Uniform Resource Identifier (URI).

URIInfo dissects a file's URI into its fundamental components, providing granular data for advanced search and identification. This includes the scheme, network location, path, and other elements such as query parameters and fragments. By parsing these components, Assemblyline allows for a more nuanced analysis of the source and context of a file, which is essential for forensic investigations and threat intelligence gathering.

Each of these descriptions aims to provide a clearer understanding of the purpose and utility of the respective models within Assemblyline, highlighting their roles in the broader context of malware analysis and cyber security operations.
""")
class URIInfo(odm.Model):
    uri: str = odm.Keyword(description="The complete Uniform Resource Identifier (URI) of the file.")

    # https://www.rfc-editor.org/rfc/rfc1808.html#section-2.1
    scheme: str = odm.Keyword(description="The scheme component of the URI (e.g., \"http\", \"ftp\").")
    netloc: str = odm.Keyword(description="The network location part of the URI, including the domain name and port.")
    path: str = odm.Optional(odm.Keyword(),description="The path component of the URI, specifying the resource within the host.")
    params: str = odm.Optional(odm.Keyword(), description="The parameters component of the URI, often used for session management.")
    query: str = odm.Optional(odm.Keyword(), description="The query string of the URI, containing data for server-side processing.")
    fragment: str = odm.Optional(odm.Keyword(), description="The fragment identifier of the URI, used to navigate to a specific part of the resource.")

    # Ease-of-use elements
    username: str = odm.Optional(odm.Keyword(), description="The username specified in the URI, if any.")
    password: str = odm.Optional(odm.Keyword(), description="The password specified in the URI, if any.")
    hostname: str = odm.Keyword(description="The hostname extracted from the netloc, representing the domain of the URI.")
    port: int = odm.Optional(odm.Integer(), description="The port number extracted from the netloc, representing the communication endpoint.")


@odm.model(index=True, store=True, description="""Tracking model for the occurrence and frequency of a file within the system.

The Seen model is designed to record and quantify the instances in which a file is encountered by Assemblyline. It keeps a count of the file's occurrences and logs the timestamps of the first and most recent sightings. This temporal information is crucial for understanding the prevalence and distribution of a file over time, aiding in threat trend analysis and situational awareness.
""")
class Seen(odm.Model):
    count = odm.Integer(default=1, description="The total number of times the file has been observed by the system.")
    first = odm.Date(default="NOW", description="The timestamp of the file's first sighting.")
    last = odm.Date(default="NOW", description="The timestamp of the file's most recent sighting.")


@odm.model(index=True, store=True, description="""Structured categorization model for labels applied to a file.

LabelCategories provide a systematic approach to classifying the characteristics and threat indicators of a file. This model organizes labels into distinct categories such as informational tags, technical techniques, and attribution links. By categorizing labels, analysts can efficiently navigate and assess the nature and potential threats associated with a file, streamlining the malware analysis process.
""")
class LabelCategories(odm.Model):
    info = odm.List(
        odm.Keyword(),
        description="Informational labels providing additional context about the file.", default=[])
    technique = odm.List(
        odm.Keyword(),
        description="An array of labels identifying the specific tactics, techniques, and procedures (TTPs) as defined by the MITRE ATT&CK® framework that are exhibited by the malware within the file. This field also includes labels for any detection signatures that triggered during analysis, providing insight into the malware's behavior and potential impact. Analysts can use these labels to correlate files with known adversary behavior and to enhance threat hunting and incident response activities.",
        default=[])
    attribution = odm.List(
        odm.Keyword(),
        description="Labels that relate to the attribution of the file, such as the associated threat actor or campaign.",
        default=[])


@odm.model(index=True, store=False, description="""Model that encapsulates user interactions with a comment.

The Reaction model captures the responses of users to comments made on a file. Reactions are simple expressions of agreement, disagreement, or sentiment, represented by a set of predefined icons. These reactions facilitate a quick, non-verbal form of feedback from users, enhancing collaborative analysis and engagement within the Assemblyline platform.
""")
class Reaction(odm.Model):
    icon = odm.Enum(values=REACTIONS_TYPES, description="Icon name representing the type of reaction given to a comment.")
    uname = odm.Keyword(description="The username of the individual who reacted to the comment.")


@odm.model(index=True, store=False, description="""Model that represents user annotations attached to a file.

A Comment is a user-generated note or observation that can be added to a file within Assemblyline. This feature enables analysts to record insights, share findings, and collaborate on the analysis of a file. Each comment is timestamped and associated with the username of the individual who authored it, creating an audit trail of analytical discourse.
""")
class Comment(odm.Model):
    cid = odm.UUID(description="Unique identifier for the comment.")
    uname = odm.Keyword(description="The username of the individual who authored the comment.")
    date = odm.Date(store=True, default="NOW", description="The date and time when the comment was posted.")
    text = odm.Text(description="The content of the comment as written by the user.")
    reactions = odm.List(odm.Compound(Reaction), default=[], description="An array of user reactions to the comment, such as likes or dislikes.")


@odm.model(index=True, store=True, description="""This section presents the detailed schema of the File object model within the Assemblyline application. Each entry in the schema represents a field that constitutes a File document within the File index. The information provided for each field includes the data type, a concise description, its requirement status, and the default value if any.

Understanding this schema is crucial for constructing effective and precise Lucene search queries. By leveraging the fields outlined in the table below, you can craft queries to retrieve specific information about files analyzed by Assemblyline. These fields are integral for in-depth data analysis, enabling you to filter and locate files based on various attributes such as type, hash values, classification, and many others.

Utilize this schema as a reference to enhance your search capabilities within the Assemblyline system, allowing for more targeted and refined data retrieval that aligns with your cybersecurity analysis needs.
""")
class File(odm.Model):
    archive_ts = odm.Optional(odm.Date(ai=False), description="Timestamp indicating when the file was archived.")
    ascii = odm.Keyword(index=False, store=False,
                        description="Provides a dotted ASCII representation of the first 64 bytes of the file.", ai=False)
    classification = odm.Classification(description="Security classification assigned to the file based on its contents and context.")
    comments = odm.List(odm.Compound(Comment), default=[], description="An array of user-generated comments pertaining to the file. See Comment model for more information.")
    entropy = odm.Float(description="A numerical value representing the file's entropy, which is defined as the level of randomness in the file's content, typically used to detect compression or encryption. High entropy may indicate obfuscation techniques such as encryption, commonly employed by malware to evade detection. This metric is not exclusive to malicious files, as legitimate files can also exhibit high entropy.")
    expiry_ts = odm.Optional(odm.Date(store=False), description="Timestamp indicating when the file is scheduled to expire from the system.", ai=False)
    is_section_image = odm.Boolean(
        default=False, description="Indicates if the file is an image safe for web browser display, often part of analysis results.", ai=False)
    is_supplementary = odm.Boolean(default=False, description="Indicates if the file was created by an AssemblyLine service as supplementary data.", ai=False)
    hex = odm.Keyword(index=False, store=False, description="Hexadecimal representation of the first 64 bytes of the file.", ai=False)
    labels = odm.List(odm.Keyword(copyto="__text__"), description="Array of descriptive labels applied to the file for categorization and analysis.", default=[])
    label_categories = odm.Compound(LabelCategories, default={}, description="Structured categories for the labels applied to the file.", ai=False)
    md5 = odm.MD5(copyto="__text__", description="The MD5 hash of the file, used for identifying duplicates and verifying integrity.", ai=False)
    magic = odm.Keyword(store=False, description="Detailed file format information derived from an analysis using the libmagic library, including text descriptions of the file's content type and encoding.")
    mime = odm.Optional(odm.Keyword(store=False), description="The Multipurpose Internet Mail Extensions (MIME) type of the file as determined by libmagic, which identifies file types by checking their headers according to a predefined list of file types.")
    seen = odm.Compound(Seen, default={}, description="Records the frequency and timestamps of when the file was encountered.", ai=False)
    sha1 = odm.SHA1(copyto="__text__", description="The SHA1 hash of the file, providing a more secure alternative to MD5 for integrity checks.", ai=False)
    sha256 = odm.SHA256(copyto="__text__", description="The SHA256 hash of the file, offering a high level of security for integrity verification.")
    size = odm.Integer(description="Size of the file in bytes.")
    ssdeep = odm.SSDeepHash(store=False, description="The fuzzy hash of the file using SSDEEP, which is useful for identifying similar files.", ai=False)
    type = odm.Keyword(copyto="__text__", description="The file type as determined by the AssemblyLine file type identification service.")
    tlsh = odm.Optional(odm.Keyword(copyto="__text__"), description="A locality-sensitive hash (TLSH) of the file's content, useful for similarity comparisons.", ai=False)
    from_archive = odm.Boolean(index=False, store=False, default=False,
                               description="Indicates whether the file was retrieved from Assemblyline's archive during processing.", ai=False)
    uri_info = odm.Optional(odm.Compound(URIInfo), description="Detailed components of the file's URI for advanced search functionality.")
