from assemblyline import odm


@odm.model(index=False, store=False)
class FileScore(odm.Model):
    psid = odm.Optional(odm.UUID())      # ID of the parent submission to the associated submission
    expiry_ts = odm.Date(index=True)     # Expiry timestamp, used for garbage collection.
    score = odm.Integer()                # Maximum score for the associated submission
    errors = odm.Integer()               # Number of errors that occurred during the previous analysis
    sid = odm.UUID()                     # ID of the associated submission
    time = odm.Float()                   # Epoch time at which the FileScore entry was created
