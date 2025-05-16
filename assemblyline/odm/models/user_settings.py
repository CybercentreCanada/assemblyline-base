from assemblyline import odm
from assemblyline.common import forge
from assemblyline.odm.models.config import SubmissionProfileParams

Classification = forge.get_classification()

ENCODINGS = {"cart", "raw", "zip"}
VIEWS = {"report", "details"}


@odm.model(index=False, store=False, description="Model of User Settings")
class UserSettings(odm.Model):
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
    preferred_submission_profile = odm.Optional(odm.Text(), description="Preferred submission profile")
    submission_profiles = odm.Mapping(odm.Compound(SubmissionProfileParams), default={},
                                      description="Default submission profile settings")
    submission_view = odm.Enum(values=VIEWS, default="report", description="Default view for completed submissions")


DEFAULT_USER_PROFILE_SETTINGS = {
    "download_encoding": "cart",
    "default_external_sources": [],
    "default_zip_password": "infected",
    "executive_summary": True,
    "expand_min_score": 500,
    "submission_view": "report",
}

DEFAULT_SUBMISSION_PROFILE_SETTINGS = {
    "classification": Classification.UNRESTRICTED,
    "deep_scan": False,
    "generate_alert": False,
    "ignore_cache": False,
    "ignore_recursion_prevention": False,
    "ignore_filtering": False,
    "priority": 1000,
    "service_spec": {},
    "services": {},
    "ttl": 30
}
