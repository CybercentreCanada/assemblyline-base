from assemblyline import odm
from assemblyline.common import forge

Classification = forge.get_classification()
SAFEHASH_TYPES = ["file", "tag", "signature"]
SOURCE_TYPES = ["user", "external"]


@odm.model(index=True, store=True)
class Hashes(odm.Model):
    md5 = odm.Optional(odm.MD5(copyto="__text__"))        # MD5 hash
    sha1 = odm.Optional(odm.SHA1(copyto="__text__"))      # SHA1 Hash
    sha256 = odm.Optional(odm.SHA256(copyto="__text__"))  # SHA256 Hash


@odm.model(index=True, store=False)
class File(odm.Model):
    name = odm.List(odm.Keyword(store=True, copyto="__text__"), default=[])  # List of names seen for that file
    size = odm.Optional(odm.Integer())                                       # Size of the file
    type = odm.Optional(odm.Keyword())                                       # Type of file


@odm.model(index=True, store=False)
class Source(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED)  # Classification of the source
    name = odm.Keyword(store=True)                                            # Name of the source
    reason = odm.List(odm.Keyword())                                          # Reason why it is safelisted
    type = odm.Enum(values=SOURCE_TYPES)                                      # Type of source


@odm.model(index=True, store=True)
class Tag(odm.Model):
    type = odm.Keyword()                                                      # List of names seen for that file
    value = odm.Keyword(copyto="__text__")                                    # Size of the file


@odm.model(index=True, store=True)
class Signature(odm.Model):
    name = odm.Keyword(copyto="__text__")                                     # Name of the signature


@odm.model(index=True, store=True)
class Safelist(odm.Model):
    added = odm.Date(default="NOW")                       # Date when the safe hash was added
    classification = odm.Classification()                 # Computed max classification for the safe hash
    enabled = odm.Boolean(default=True)                   # The safe hash enabled or not
    hashes = odm.Compound(Hashes, default={})             # List of hashes related to the safe hash
    file = odm.Optional(odm.Compound(File))               # Informations about the file
    sources = odm.List(odm.Compound(Source))              # List of reasons why hash is safelisted
    tag = odm.Optional(odm.Compound(Tag))                 # Informations about the tag
    signature = odm.Optional(odm.Compound(Signature))     # Informations about the signature
    type = odm.Enum(values=SAFEHASH_TYPES)                # Type of safe hash
    updated = odm.Date(default="NOW")                     # Last date when sources were added to the safe hash


if __name__ == "__main__":
    from pprint import pprint
    from assemblyline.odm.randomizer import random_model_obj
    pprint(random_model_obj(Safelist, as_json=True))
