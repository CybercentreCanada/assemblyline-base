from assemblyline import odm

TYPES = ["user", "external"]


@odm.model(index=True, store=True)
class Source(odm.Model):
    name = odm.Keyword()                            # Name of the source
    type = odm.Enum(values=TYPES)                   # Type of source
    reason = odm.List(odm.Keyword(), default=[])    # Reason why it is whitelisted


@odm.model(index=True, store=True)
class Whitelist(odm.Model):
    hash = odm.SHA256()
    date = odm.Date(default="NOW")                         # Whitelisting date
    sources = odm.List(odm.Compound(Source), default=[])   # List of reasons why it is whitelisted
