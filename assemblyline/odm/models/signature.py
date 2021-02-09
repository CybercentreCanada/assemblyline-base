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
    classification = odm.Classification(store=True, default=Classification.UNRESTRICTED)
    data = odm.Text(index=False, store=False)
    last_modified = odm.Date(default="NOW")
    name = odm.Keyword(copyto="__text__")
    order = odm.Integer(default=1, store=False)
    revision = odm.Keyword(default="1")
    signature_id = odm.Optional(odm.Keyword())
    source = odm.Keyword()
    state_change_date = odm.Optional(odm.Date(store=False))
    state_change_user = odm.Optional(odm.Keyword(store=False))
    stats = odm.Compound(Statistics, default={})
    status = odm.Enum(values=RULE_STATUSES, copyto="__text__")
    type = odm.Keyword(copyto="__text__")
