from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()


@odm.model(index=False, store=False)
class SubmissionSummary(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED)  # Classification of the cache
    filtered = odm.Boolean(default=False)                                     # Has this cache entry been filtered
    expiry_ts = odm.Date(index=True)                                          # Expiry date
    tags = odm.Text()                                                         # Tags cache
    attack_matrix = odm.Text()                                                # Att&ck Matrix cache
    heuristics = odm.Text()                                                   # Heuristics cache
    heuristic_sections = odm.Text()                                           # All sections mapping to the heuristics
    heuristic_name_map = odm.Text()                                           # Map of heuristic names to IDs
