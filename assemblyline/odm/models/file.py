from assemblyline import odm


@odm.model(index=True, store=True, description="URI Information Model")
class URIInfo(odm.Model):
    uri: str = odm.Keyword(description="full URI")

    # https://www.rfc-editor.org/rfc/rfc1808.html#section-2.1
    scheme: str = odm.Keyword(description="")
    netloc: str = odm.Keyword(description="")
    path: str = odm.Optional(odm.Keyword(description=""))
    params: str = odm.Optional(odm.Keyword(description=""))
    query: str = odm.Optional(odm.Keyword(description=""))
    fragment: str = odm.Optional(odm.Keyword(description=""))

    # Ease-of-use elements
    username: str = odm.Optional(odm.Keyword(description=""))
    password: str = odm.Optional(odm.Keyword(description=""))
    hostname: str = odm.Keyword(description="")
    port: int = odm.Optional(odm.Integer(description=""))


@odm.model(index=True, store=True, description="File Seen Model")
class Seen(odm.Model):
    count = odm.Integer(default=1, description="How many times have we seen this file?")
    first = odm.Date(default="NOW", description="First seen timestamp")
    last = odm.Date(default="NOW", description="Last seen timestamp")


@odm.model(index=True, store=True, description="Model of File")
class File(odm.Model):
    archive_ts = odm.Optional(odm.Date(store=False, description="Archiving timestamp (Deprecated)"))
    ascii = odm.Keyword(index=False, store=False,
                        description="Dotted ASCII representation of the first 64 bytes of the file")
    classification = odm.Classification(description="Classification of the file")
    entropy = odm.Float(description="Entropy of the file")
    expiry_ts = odm.Optional(odm.Date(store=False), description="Expiry timestamp")
    is_section_image = odm.Boolean(default=False, description="Is this an image from an Image Result Section?")
    hex = odm.Keyword(index=False, store=False, description="Hex dump of the first 64 bytes of the file")
    md5 = odm.MD5(copyto="__text__", description="MD5 of the file")
    magic = odm.Keyword(store=False, description="Output from libmagic related to the file")
    mime = odm.Optional(odm.Keyword(store=False), description="MIME type of the file as identified by libmagic")
    seen = odm.Compound(Seen, default={}, description="Details about when the file was seen")
    sha1 = odm.SHA1(copyto="__text__", description="SHA1 hash of the file")
    sha256 = odm.SHA256(copyto="__text__", description="SHA256 hash of the file")
    size = odm.Integer(description="Size of the file in bytes")
    ssdeep = odm.SSDeepHash(store=False, description="SSDEEP hash of the file")
    type = odm.Keyword(copyto="__text__", description="Type of file as identified by Assemblyline")
    tlsh = odm.Optional(odm.Keyword(copyto="__text__", description="TLSH hash of the file"))
    from_archive = odm.Boolean(index=False, default=False, description="Was loaded from the archive")
    uri_info = odm.Optional(odm.Compound(URIInfo), description="URI structure to speed up specialty file searching")
