from assemblyline import odm


@odm.model(index=True, store=True, description="CachedFile Model")
class CachedFile(odm.Model):
    component = odm.Keyword(description="Name of component which created the file")
    expiry_ts = odm.Date(store=False, description="Expiry timestamp")
