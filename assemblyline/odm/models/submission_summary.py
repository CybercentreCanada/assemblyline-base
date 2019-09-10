from assemblyline import odm


@odm.model(index=False, store=False)
class SubmissionSummary(odm.Model):
    expiry_ts = odm.Date(index=True)  # Expiry date
    tags = odm.Text()                 # Tags cache
    attack_matrix = odm.Text()        # Att&ck Matrix cache
    heuristics = odm.Text()           # Heuristics cache
