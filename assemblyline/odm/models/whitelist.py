from assemblyline import odm

TYPES = ["user", "external"]


@odm.model(index=True, store=False)
class FileInfo(odm.Model):
    md5 = odm.Optional(odm.MD5())                   # MD5 hash of the file
    sha1 = odm.Optional(odm.SHA1())                 # SHA1 Hash of the file
    sha256 = odm.SHA256(store=True)                 # SHA256 Hash of the file
    size = odm.Optional(odm.Integer())              # Size of the file
    type = odm.Optional(odm.Keyword())              # Type of file


@odm.model(index=True, store=False)
class Source(odm.Model):
    name = odm.Keyword(store=True)                  # Name of the source
    type = odm.Enum(values=TYPES)                   # Type of source
    reason = odm.List(odm.Keyword(), default=[])    # Reason why it is whitelisted


@odm.model(index=True, store=True)
class Whitelist(odm.Model):
    added = odm.Date(default="NOW")                       # Date when the hash was added
    classification = odm.Classification()                 # Classification of the hash
    fileinfo = odm.Compound(FileInfo)                     # Informations about the file
    updated = odm.Date(default="NOW")                     # Last date when sources were added to the hash
    sources = odm.List(odm.Compound(Source), default=[])  # List of reasons why it is whitelisted


if __name__ == "__main__":
    from pprint import pprint
    from assemblyline.odm.randomizer import random_model_obj
    pprint(random_model_obj(Whitelist, as_json=True))
