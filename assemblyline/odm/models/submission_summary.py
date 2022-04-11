from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()


@odm.model(index=False, store=False, description="Submission Summary Model")
class SubmissionSummary(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED, description="Classification of the cache")
    filtered = odm.Boolean(default=False, description="Has this cache entry been filtered?")
    expiry_ts = odm.Date(index=True, description="Expiry timestamp")
    tags = odm.Text(description="Tags cache")
    attack_matrix = odm.Text(description="ATT&CK Matrix cache")
    heuristics = odm.Text(description="Heuristics cache")
    heuristic_sections = odm.Text(description="All sections mapping to the heuristics")
    heuristic_name_map = odm.Text(description="Map of heuristic names to IDs")
