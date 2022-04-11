from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()


@odm.model(index=True, store=False, description="Submission Tree Model")
class SubmissionTree(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED, description="Classification of the cache")
    filtered = odm.Boolean(default=False, description="Has this cache entry been filtered?")
    expiry_ts = odm.Date(description="Expiry timestamp")
    supplementary = odm.Text(index=False, description="Tree of supplementary files")
    tree = odm.Text(index=False, description="File tree cache")
