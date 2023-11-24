from assemblyline import odm
from assemblyline.common import forge

Classification = forge.get_classification()
BADHASH_TYPES = ["file", "tag"]
SOURCE_TYPES = ["user", "external"]


@odm.model(index=True, store=False, description="Attribution Tag Model")
class Attribution(odm.Model):
    actor = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Actor")
    campaign = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Campaign")
    category = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Category")
    exploit = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Exploit")
    implant = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Implant")
    family = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Family")
    network = odm.Optional(odm.List(odm.UpperKeyword(copyto="__text__")), description="Attribution Network")


@odm.model(index=True, store=True, description="Hashes of a badlisted file")
class Hashes(odm.Model):
    md5 = odm.Optional(odm.MD5(copyto="__text__"), description="MD5")
    sha1 = odm.Optional(odm.SHA1(copyto="__text__"), description="SHA1")
    sha256 = odm.Optional(odm.SHA256(copyto="__text__"), description="SHA256")
    ssdeep = odm.Optional(odm.SSDeepHash(copyto="__text__"), description="SSDEEP")
    tlsh = odm.Optional(odm.Keyword(copyto="__text__", description="TLSH"))


@odm.model(index=True, store=False, description="File Details")
class File(odm.Model):
    name = odm.List(odm.Keyword(store=True, copyto="__text__"), default=[],
                    description="List of names seen for that file")
    size = odm.Optional(odm.Integer(), description="Size of the file in bytes")
    type = odm.Optional(odm.Keyword(), description="Type of file as identified by Assemblyline")


@odm.model(index=True, store=False, description="Badlist source")
class Source(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED,
                                        description="Classification of the source")
    name = odm.Keyword(store=True, description="Name of the source")
    reason = odm.List(odm.Keyword(), description="Reason for why file was badlisted")
    type = odm.Enum(values=SOURCE_TYPES, description="Type of badlisting source")


@odm.model(index=True, store=True, description="Tag associated to file")
class Tag(odm.Model):
    type = odm.Keyword(description="Tag type")
    value = odm.Keyword(copyto="__text__", description="Tag value")


@odm.model(index=True, store=True, description="Badlist Model")
class Badlist(odm.Model):
    added = odm.Date(default="NOW", description="Date when the badlisted hash was added")
    attribution = odm.Optional(odm.Compound(Attribution), description="Attribution related to the bad hash")
    classification = odm.Classification(description="Computed max classification for the bad hash")
    enabled = odm.Boolean(default=True, description="Is bad hash enabled or not?")
    expiry_ts = odm.Optional(odm.Date, description="When does this item expire from the list?")
    hashes = odm.Compound(Hashes, default={}, description="List of hashes related to the bad hash")
    file = odm.Optional(odm.Compound(File), description="Information about the file")
    sources = odm.List(odm.Compound(Source), description="List of reasons why hash is badlisted")
    tag = odm.Optional(odm.Compound(Tag), description="Information about the tag")
    type = odm.Enum(values=BADHASH_TYPES, description="Type of bad hash")
    updated = odm.Date(default="NOW", description="Last date when sources were added to the bad hash")


if __name__ == "__main__":
    from pprint import pprint
    from assemblyline.odm.randomizer import random_model_obj
    pprint(random_model_obj(Badlist, as_json=True))
