from assemblyline import odm
from assemblyline.common import forge
from assemblyline.odm.models.statistics import Statistics

Classification = forge.get_classification()

DEPLOYED_STATUSES = ['DEPLOYED', 'NOISY', 'DISABLED']
DRAFT_STATUSES = ['STAGING', 'TESTING']
STALE_STATUSES = ['INVALID']

RULE_STATUSES = DEPLOYED_STATUSES + DRAFT_STATUSES + STALE_STATUSES


@odm.model(index=True, store=True, description="""The Signature model within Assemblyline serves as a central framework for defining and managing security signatures, crucial components for the detection and analysis of malware. It provides a structured format that encompasses essential attributes such as a signature's name, classification level, source, and unique identifier. Moreover, it incorporates revision history, last modification timestamps, and statistical data to gauge performance and utility.

The model presents users with a mix of static and dynamic information, ranging from immutable identification details to variable metadata reflecting the signature's current operational status and history of changes. This latter aspect is captured through fields that log the date and user associated with the last status update, offering a view into the signature's lifecycle.

Understanding the Signature model is vital for cybersecurity professionals who are tasked with crafting precise Lucene-based search queries in Assemblyline. Mastery of this model's components will enable users to efficiently search, filter, and analyze signatures based on various parameters, thereby facilitating effective management and deployment in a cybersecurity context.
""")
class Signature(odm.Model):
    classification = odm.Classification(store=True, default=Classification.UNRESTRICTED, description="Indicates the sensitivity level of the signature, which dictates who can access it based on their clearance.")
    data = odm.Text(index=False, store=False, description="Stores the actual signature data or pattern used for malware detection.")
    last_modified = odm.Date(default="NOW", description="Records the timestamp of the most recent update to the signature. Defaults to the current time when the signature is modified.")
    name = odm.Keyword(copyto="__text__", description="A unique and descriptive name for the signature.")
    order = odm.Integer(default=1, store=False, description="**TODO**:Lower number means higher priority?  **Generated**:Determines the processing order of the signature relative to others. A lower number indicates higher priority.")
    revision = odm.Keyword(default="1", description="Tracks the version of the signature, with the default starting value set to \"1\".")
    signature_id = odm.Optional(odm.Keyword(), description="A unique identifier for the signature, which can be used for tracking and referencing purposes.")
    source = odm.Keyword(description="Identifies the origin or the entity that provided the signature.")
    state_change_date = odm.Optional(odm.Date(store=False), description="Captures the date when the signature's status was last updated. ")
    state_change_user = odm.Optional(odm.Keyword(store=False), description="Records the username of the individual who last modified the signature's status.")
    stats = odm.Compound(Statistics, default={}, description="Holds various statistical data related to the signature's performance and usage")
    status = odm.Enum(values=RULE_STATUSES, copyto="__text__", description="Reflects the operational state of the signature, indicating whether it is deployed, in testing, or otherwise.")
    type = odm.Keyword(copyto="__text__", description="Specifies the category or classification of the signature, which can be used for organizing and filtering signatures.")
