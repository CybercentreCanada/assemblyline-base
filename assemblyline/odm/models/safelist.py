from assemblyline import odm
from assemblyline.common import forge

Classification = forge.get_classification()
SAFEHASH_TYPES = ["file", "tag", "signature"]
SOURCE_TYPES = ["user", "external"]


@odm.model(index=True, store=True, description="Hashes of a safelisted file")
class Hashes(odm.Model):
    md5 = odm.Optional(odm.MD5(copyto="__text__"), description="MD5")
    sha1 = odm.Optional(odm.SHA1(copyto="__text__"), description="SHA1")
    sha256 = odm.Optional(odm.SHA256(copyto="__text__"), description="SHA256")


@odm.model(index=True, store=False, description="File Details")
class File(odm.Model):
    name = odm.List(odm.Keyword(store=True, copyto="__text__"), default=[],
                    description="List of names seen for that file")
    size = odm.Optional(odm.Integer(), description="Size of the file in bytes")
    type = odm.Optional(odm.Keyword(), description="Type of file as identified by Assemblyline")


@odm.model(index=True, store=False, description="Safelist source")
class Source(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED,
                                        description="Classification of the source")
    name = odm.Keyword(store=True, description="Name of the source")
    reason = odm.List(odm.Keyword(), description="Reason for why file was safelisted")
    type = odm.Enum(values=SOURCE_TYPES, description="Type of safelisting source")


@odm.model(index=True, store=True, description="Tag associated to file")
class Tag(odm.Model):
    type = odm.Keyword(description="Tag type")
    value = odm.Keyword(copyto="__text__", description="Tag value")


@odm.model(index=True, store=True, description="Signature")
class Signature(odm.Model):
    name = odm.Keyword(copyto="__text__", description="Name of the signature")


@odm.model(index=True, store=True, description="Safelist Model")
class Safelist(odm.Model):

    added = odm.Date(default="NOW", description="Date when the safelisted hash was added")
    classification = odm.Classification(description="Computed max classification for the safe hash")
    enabled = odm.Boolean(default=True, description="Is safe hash enabled or not?")
    hashes = odm.Compound(Hashes, default={}, description="List of hashes related to the safe hash")
    file = odm.Optional(odm.Compound(File), description="Information about the file")
    sources = odm.List(odm.Compound(Source), description="List of reasons why hash is safelisted")
    tag = odm.Optional(odm.Compound(Tag), description="Information about the tag")
    signature = odm.Optional(odm.Compound(Signature), description="Information about the signature")
    type = odm.Enum(values=SAFEHASH_TYPES, description="Type of safe hash")
    updated = odm.Date(default="NOW", description="Last date when sources were added to the safe hash")


if __name__ == "__main__":
    from pprint import pprint
    from assemblyline.odm.randomizer import random_model_obj
    pprint(random_model_obj(Safelist, as_json=True))
