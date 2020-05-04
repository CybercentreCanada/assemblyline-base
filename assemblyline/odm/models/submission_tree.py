from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()


@odm.model(index=True, store=False)
class SubmissionTree(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED)  # Classification of the cache
    expiry_ts = odm.Date()        # Expiry date
    tree = odm.Text(index=False)  # Tree cache
