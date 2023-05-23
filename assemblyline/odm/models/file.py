from assemblyline import odm


@odm.model(index=True, store=True, description="File Seen Model")
class Seen(odm.Model):
    count = odm.Integer(default=1, description="How many times have we seen this file?")
    first = odm.Date(default="NOW", description="First seen timestamp")
    last = odm.Date(default="NOW", description="Last seen timestamp")


@odm.model(index=True, store=True, description="Label Categories Model")
class LabelCategories(odm.Model):
    info = odm.List(
        odm.Keyword(),
        description="List of extra informational labels about the file", default=[])
    technique = odm.List(
        odm.Keyword(),
        description="List of labels related to the technique used by the file and the signatures that hits on it.",
        default=[])
    attribution = odm.List(
        odm.Keyword(),
        description="List of labels related to attribution of this file (implant name, actor, campain...)",
        default=[])


@odm.model(index=True, store=False, description="Comment Model")
class Comment(odm.Model):
    cid = odm.UUID(description="Comment ID")
    uname = odm.Keyword(description="Username of the user who made the comment")
    date = odm.Date(store=True, default="NOW", description="Datetime the comment was made on")
    text = odm.Text(description="Text of the comment written by the author")


@odm.model(index=True, store=True, description="Model of File")
class File(odm.Model):
    archive_ts = odm.Optional(odm.Date(store=False, description="Archiving timestamp (Deprecated)"))
    ascii = odm.Keyword(index=False, store=False,
                        description="Dotted ASCII representation of the first 64 bytes of the file")
    classification = odm.Classification(description="Classification of the file")
    comments = odm.List(odm.Compound(Comment), default=[], description="List of comments made on a file")
    entropy = odm.Float(description="Entropy of the file")
    expiry_ts = odm.Optional(odm.Date(store=False), description="Expiry timestamp")
    is_section_image = odm.Boolean(default=False, description="Is this an image from an Image Result Section?")
    hex = odm.Keyword(index=False, store=False, description="Hex dump of the first 64 bytes of the file")
    labels = odm.List(odm.Keyword(copyto="__text__"), description="List of labels of the file", default=[])
    label_categories = odm.Compound(LabelCategories, default={}, description="Categories of label")
    md5 = odm.MD5(copyto="__text__", description="MD5 of the file")
    magic = odm.Keyword(store=False, description="Output from libmagic related to the file")
    mime = odm.Optional(odm.Keyword(store=False), description="MIME type of the file as identified by libmagic")
    seen = odm.Compound(Seen, default={}, description="Details about when the file was seen")
    sha1 = odm.SHA1(copyto="__text__", description="SHA1 hash of the file")
    sha256 = odm.SHA256(copyto="__text__", description="SHA256 hash of the file")
    size = odm.Integer(description="Size of the file in bytes")
    ssdeep = odm.SSDeepHash(store=False, description="SSDEEP hash of the file")
    type = odm.Keyword(copyto="__text__", description="Type of file as identified by Assemblyline")
    from_archive = odm.Boolean(index=False, default=False, description="Was loaded from the archive")
