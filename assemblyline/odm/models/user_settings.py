from assemblyline import odm
from assemblyline.common import forge
from assemblyline.odm.models.submission import ServiceSelection

Classification = forge.get_classification()

ENCODINGS = {"cart", "raw"}
VIEWS = {"report", "details"}


@odm.model(index=False, store=False)
class UserSettings(odm.Model):                                      # User's default settings
    classification = odm.Classification(
        default=Classification.UNRESTRICTED)                          # Default submission classification
    deep_scan = odm.Boolean(default=False)                            # Should a deep scan be performed
    description = odm.Keyword(default="")                             # Default description
    download_encoding = odm.Enum(values=ENCODINGS, default="cart")    # Default download encoding when downloading files
    expand_min_score = odm.Integer(default=500)                       # Auto-expand section when score bigger then this
    ignore_cache = odm.Boolean(default=False)                         # Ignore service caching
    ignore_dynamic_recursion_prevention = odm.Boolean(default=False)  # Ignore dynamic recursion prevention
    ignore_filtering = odm.Boolean(default=False)                     # Ignore filtering services
    malicious = odm.Boolean(default=False)                            # Is the file submitted known to be malicious
    priority = odm.Integer(default=1000)                              # Default priority for the submissions
    profile = odm.Boolean(default=False)                              # Should the submission do extra profiling
    service_spec = odm.Mapping(odm.Keyword(), default={})             # Default service specific settings
    services = odm.Compound(ServiceSelection, default={})             # Default service selection
    submission_view = odm.Enum(values=VIEWS, default="report")        # Default view for completed submissions
    ttl = odm.Integer(default=30)                                     # Default submission Time to Live (days)
