from assemblyline import odm


@odm.model(index=True, store=True)
class FileScore(odm.Model):
    psid = odm.Keyword()    # ID of the parent submission to the associated submission
    expiry_ts = odm.Date()  # Expiry timestamp
    score = odm.Integer()   # Maximum score for the associated submission
    sid = odm.Keyword()     # ID of the associated submission
    time = odm.Float()      # Epoch time at which the FileScore entry becomes invalid TODO: is that so?
