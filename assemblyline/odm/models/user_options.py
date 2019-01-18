from assemblyline import odm
from assemblyline.common.classification import Classification

ENCODINGS = {"cart", "raw"}
DEFAULT_SRV_SEL = ["Filtering", "Antivirus", "Static Analysis", "Extraction"]


@odm.model(index=False, store=False)
class UserOptions(odm.Model):  # User's default options
    classification = odm.Classification(
        default=Classification.NULL_CLASSIFICATION)                   # Default submission classification
    deep_scan = odm.Boolean(default=False)                            # Should a deep scan be performed
    description = odm.Keyword(default="")                             # Default description
    download_encoding = odm.Enum(values=ENCODINGS, default="cart")    # Default download encoding when downloading files
    expand_min_score = odm.Integer(default=50)                        # Auto-expand section when score bigger then this
    hide_raw_results = odm.Boolean(default=True)                      # Hide raw JSON sections
    ignore_cache = odm.Boolean(default=False)                         # Ignore service caching
    ignore_dynamic_recursion_prevention = odm.Boolean(default=False)  # Ignore dynamic recursion prevention
    ignore_filtering = odm.Boolean(default=False)                     # Ignore filtering services
    priority = odm.Integer(default=1000)                              # Default priority for the submissions
    profile = odm.Boolean(default=False)                              # Should the submission do extra profiling
    service_spec = odm.Mapping(odm.Keyword(), default={})             # Default service specific options
    services = odm.List(odm.Keyword(), default=DEFAULT_SRV_SEL)       # Default service selection
    ttl = odm.Integer(default=15)                                     # Default submission Time to Live (days)
