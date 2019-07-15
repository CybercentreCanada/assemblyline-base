from assemblyline import odm


@odm.model(index=True, store=False)
class SubmissionAttack(odm.Model):
    expiry_ts = odm.Date()        # Expiry date
    attack_matrix = odm.Text(index=False)  # Tags cache
