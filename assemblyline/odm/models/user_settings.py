from assemblyline import odm
from assemblyline.common import forge, constants
from assemblyline.odm.models.config import SubmissionProfileParams
from assemblyline.odm.models.submission import ServiceSelection

Classification = forge.get_classification()

ENCODINGS = {"cart", "raw", "zip"}
VIEWS = {"report", "details"}


@odm.model(index=False, store=False, description="Model of User Settings")
class UserSettings(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED,
                                        description="Default submission classification",
                                        deprecation="This will be moved to the \"default\" submission profile")
    deep_scan = odm.Boolean(default=False, description="Should a deep scan be performed?",
                            deprecation="This will be moved to the \"default\" submission profile")
    download_encoding = odm.Enum(values=ENCODINGS, default="cart",
                                 description="Default download encoding when downloading files")
    default_external_sources = odm.List(odm.Keyword(), default=[],
                                        description="List of sha256 sources to check by default")
    default_zip_password = odm.Text(
        default="infected",
        description="Default user-defined password for creating password protected ZIPs when downloading files"
    )
    executive_summary = odm.Boolean(default=True, description="Should executive summary sections be shown?")
    expand_min_score = odm.Integer(default=500, description="Auto-expand section when score bigger then this")
    generate_alert = odm.Boolean(default=False, description="Generate an alert?",
                              deprecation="This will be moved to the \"default\" submission profile")
    ignore_cache = odm.Boolean(default=False, description="Ignore service caching?",
                              deprecation="This will be moved to the \"default\" submission profile")

    # the following 1 line can be removed after assemblyline 4.6+
    ignore_dynamic_recursion_prevention = odm.Boolean(default=False, description="Ignore dynamic recursion prevention?",
                              deprecation="This is replaced by `ignore_recursion_prevention`")
    ignore_recursion_prevention = odm.Boolean(default=False, description="Ignore all service recursion prevention?",
                              deprecation="This will be moved to the \"default\" submission profile")
    ignore_filtering = odm.Boolean(default=False, description="Ignore filtering services?",
                              deprecation="This will be moved to the \"default\" submission profile")
    priority = odm.Integer(default=1000, min=1, max=constants.MAX_PRIORITY,
                           description="Default priority for the submissions",
                           deprecation="This will be moved to the \"default\" submission profile")
    preferred_submission_profile = odm.Optional(odm.Text(), description="Preferred submission profile")
    submission_profiles = odm.Mapping(odm.Compound(SubmissionProfileParams), default={},
                                      description="Default submission profile settings")
    service_spec = odm.Mapping(odm.Mapping(odm.Any()), default={}, description="Default service specific settings",
                              deprecation="This will be moved to the \"default\" submission profile")
    services = odm.Compound(ServiceSelection, default={}, description="Default service selection",
                              deprecation="This will be moved to the \"default\" submission profile")
    submission_view = odm.Enum(values=VIEWS, default="report", description="Default view for completed submissions")
    ttl = odm.Integer(default=30, description="Default submission TTL, in days",
                              deprecation="This will be moved to the \"default\" submission profile")


DEFAULT_USER_PROFILE_SETTINGS = {
    "classification": Classification.UNRESTRICTED,
    "deep_scan": False,
    "download_encoding": "cart",
    "default_external_sources": [],
    "default_zip_password": "infected",
    "executive_summary": True,
    "expand_min_score": 500,
    "generate_alert": False,
    "ignore_cache": False,
    "ignore_dynamic_recursion_prevention": False,
    "ignore_recursion_prevention": False,
    "ignore_filtering": False,
    "priority": 1000,
    "service_spec": {},
    "services": {},
    "submission_view": "report",
    "ttl": 30
}
