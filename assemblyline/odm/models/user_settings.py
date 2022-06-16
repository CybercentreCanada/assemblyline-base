from assemblyline import odm
from assemblyline.common import forge
from assemblyline.odm.models.submission import ServiceSelection

Classification = forge.get_classification()

ENCODINGS = {"cart", "raw", "zip"}
VIEWS = {"report", "details"}


@odm.model(index=False, store=False, description="Model of User Settings")
class UserSettings(odm.Model):
    allow_external_submit = odm.Boolean(default=False,
                                        description="Allow checking external sha256 source during sha256 submit")
    classification = odm.Classification(default=Classification.UNRESTRICTED,
                                        description="Default submission classification")
    deep_scan = odm.Boolean(default=False, description="Should a deep scan be performed?")
    description = odm.Keyword(default="", description="Default description")
    download_encoding = odm.Enum(values=ENCODINGS, default="cart",
                                 description="Default download encoding when downloading files")
    default_zip_password = odm.Text(
        default="zippy",
        description="Default user-defined password for creating password protected ZIPs when downloading files"
    )
    expand_min_score = odm.Integer(default=500, description="Auto-expand section when score bigger then this")
    ignore_cache = odm.Boolean(default=False, description="Ignore service caching?")
    ignore_dynamic_recursion_prevention = odm.Boolean(default=False, description="Ignore dynamic recursion prevention?")
    ignore_filtering = odm.Boolean(default=False, description="Ignore filtering services?")
    malicious = odm.Boolean(default=False, description="Is the file submitted already known to be malicious?")
    priority = odm.Integer(default=1000, description="Default priority for the submissions")
    profile = odm.Boolean(default=False, description="Should the submission do extra profiling?")
    service_spec = odm.Mapping(odm.Mapping(odm.Any()), default={}, description="Default service specific settings")
    services = odm.Compound(ServiceSelection, default={}, description="Default service selection")
    submission_view = odm.Enum(values=VIEWS, default="report", description="Default view for completed submissions")
    ttl = odm.Integer(default=30, description="Default submission TTL, in days")
