from assemblyline import odm


@odm.model(index=True, store=False)
class SubmissionTags(odm.Model):
    expiry_ts = odm.Date()  # Expiry date
    tags = odm.Keyword()    # Tags cache
