from assemblyline import odm


@odm.model(index=True, store=False)
class SubmissionTree(odm.Model):
    expiry_ts = odm.Date()        # Expiry date
    tree = odm.Text(index=False)  # Tree cache
