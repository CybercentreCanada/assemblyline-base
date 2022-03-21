from assemblyline import odm


# Details about the characteristics used to identify an object
class ObjectID(odm.Model):
    # The GUID associated with the object
    guid = odm.Text()
    # The normalized tag of the object
    tag = odm.Optional(odm.Text())
    # The hash of the tree ID
    treeid = odm.Optional(odm.Text())
    # The time at which the object was observed
    time_observed = odm.Optional(odm.Date())
