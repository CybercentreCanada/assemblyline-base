from assemblyline import odm
from assemblyline.common import forge
from assemblyline.odm.models.statistics import Statistics

Classification = forge.get_classification()

DEPLOYED_STATUSES = ['DEPLOYED', 'NOISY', 'DISABLED']
DRAFT_STATUSES = ['STAGING', 'TESTING']
STALE_STATUSES = ['INVALID']

RULE_STATUSES = DEPLOYED_STATUSES + DRAFT_STATUSES + STALE_STATUSES


@odm.model(index=True, store=True)
class Signature(odm.Model):
    classification = odm.Classification(store=True, default=Classification.UNRESTRICTED, description="Security classification assigned to the signature based on its contents and context.")
    data = odm.Text(copyto="__text__", store=False)
    last_modified = odm.Date(default="NOW", description="Notes the last modification timestamp of the signature.")
    name = odm.Keyword(copyto="__text__", description="Name of the signature.")
    order = odm.Integer(default=1, store=False, deprecation="no longer used in v4")
    revision = odm.Keyword(default="1", description="")
    signature_id = odm.Optional(odm.Keyword(), description="ID associated with the signature.")
    source = odm.Keyword(description="Source or author of the signature.")
    state_change_date = odm.Optional(odm.Date(store=False), description="Date the signature's state was last changed.")
    state_change_user = odm.Optional(odm.Keyword(store=False), description="User who last changed the signature's state.")
    stats = odm.Compound(Statistics, default={}, description="Stats associated with count, average, min, max, and sum of various signature metrics.")
    status = odm.Enum(values=RULE_STATUSES, copyto="__text__", description="The current state of the signature (i.e. NOISY, DISABLED, DEPLOYED, etc.).")
    type = odm.Keyword(copyto="__text__", description="The service type that the signature is associated with.")

