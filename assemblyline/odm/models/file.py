from assemblyline import odm


@odm.model(index=True, store=True)
class Seen(odm.Model):
    count = odm.Integer(default=1)      # Number of time we've seen this file
    first = odm.Date(default="NOW")     # Date of the first time we've seen the file
    last = odm.Date(default="NOW")      # Date of the last time we've seen the file


@odm.model(index=True, store=True)
class File(odm.Model):
    archive_ts = odm.Date(store=False)                # Archiving timestamp
    ascii = odm.Keyword(index=False, store=False)     # Dotted ascii representation of the first 64 bytes of the file
    classification = odm.Classification()             # Classification of the file
    entropy = odm.Float()                             # Entropy of the file
    expiry_ts = odm.Optional(odm.Date(store=False))   # Expiry timestamp
    is_section_image = odm.Boolean(default=False)     # Is this an image from an Image Result Section
    hex = odm.Keyword(index=False, store=False)       # Hex dump of the first 64 bytes of the file
    md5 = odm.MD5(copyto="__text__")                  # MD5 of the top level file
    magic = odm.Keyword(store=False)                  # Output from libmagic related to that file
    mime = odm.Optional(odm.Keyword(store=False))     # Mime type of the file as identified by libmagic
    seen = odm.Compound(Seen, default={})             # Attributes about when the file was seen
    sha1 = odm.SHA1(copyto="__text__")                # SHA1 hash of the file
    sha256 = odm.SHA256(copyto="__text__")            # SHA256 hash of the file
    size = odm.Integer()                              # Size of the file
    ssdeep = odm.SSDeepHash(store=False)              # SSDEEP hash of the file
    type = odm.Keyword(copyto="__text__")             # Type of file as identified by Assemblyline
