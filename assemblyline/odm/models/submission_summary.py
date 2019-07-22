from assemblyline import odm


@odm.model(index=True, store=False)
class SubmissionSummary(odm.Model):
    expiry_ts = odm.Date()        # Expiry date
    tags = odm.Text(index=False)  # Tags cache
    attack_matrix = odm.Text(index=False)  # Tags cache
