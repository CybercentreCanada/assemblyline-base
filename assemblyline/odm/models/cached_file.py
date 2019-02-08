from assemblyline import odm


@odm.model(index=True, store=True)
class CachedFile(odm.Model):
    component = odm.Keyword()                         # Component which created the file
    expiry_ts = odm.Date(store=False, default="NOW")  # Expiry time stamp
