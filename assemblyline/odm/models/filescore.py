from assemblyline import odm


@odm.model(index=False, store=False, description="Model of Scoring related to a File")
class FileScore(odm.Model):
    psid = odm.Optional(odm.UUID(), description=" Parent submission ID of the associated submission")
    expiry_ts = odm.Date(index=True, description="Expiry timestamp, used for garbage collection")
    score = odm.Integer(description="Maximum score for the associated submission")
    errors = odm.Integer(description="Number of errors that occurred during the previous analysis")
    sid = odm.UUID(description="ID of the associated submission")
    time = odm.Float(description="Epoch time at which the FileScore entry was created")
