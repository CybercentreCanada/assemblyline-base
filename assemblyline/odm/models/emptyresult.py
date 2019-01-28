from assemblyline import odm


@odm.model(index=True, store=True)
class EmptyResult(odm.Model):
    # Empty results are gonna be an abstract construct
    #  Only a record of the key is saved for caching purposes
    expiry_ts = odm.Date(store=False)       # Expiry time stamp
