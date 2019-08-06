from assemblyline import odm


@odm.model(index=False, store=False)
class FileScore(odm.Model):
    psid = odm.Optional(odm.UUID())      # ID of the parent submission to the associated submission
    expiry_ts = odm.Date(index=True)     # Expiry timestamp, (time field only applies to cache invalidation, this is for garbage collection)
    score = odm.Integer()                # Maximum score for the associated submission
    errors = odm.Integer()               # Number of errors that occured during the previous analysis
    sid = odm.UUID()                     # ID of the associated submission
    time = odm.Float()                   # Epoch time at which the FileScore entry becomes invalid
