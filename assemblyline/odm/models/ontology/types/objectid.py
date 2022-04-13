from assemblyline import odm


@odm.model(description="Details about the characteristics used to identify an object")
class ObjectID(odm.Model):
    guid = odm.Text(description="The GUID associated with the object")
    tag = odm.Optional(odm.Text(), description="The normalized tag of the object")
    treeid = odm.Optional(odm.Text(), description="The hash of the tree ID")
    processtree = odm.Optional(odm.Keyword(), description="Human-readable tree ID (concatenation of tags)")
    time_observed = odm.Optional(odm.Date(), description="The time at which the object was observed")
