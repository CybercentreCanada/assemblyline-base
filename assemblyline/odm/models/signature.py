from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()

DEPLOYED_STATUSES = ['DEPLOYED', 'NOISY', 'DISABLED']
DRAFT_STATUSES = ['STAGING', 'TESTING']
STALE_STATUSES = ['INVALID']

RULE_STATUSES = DEPLOYED_STATUSES + DRAFT_STATUSES + STALE_STATUSES
VALID_TYPES = ['yara', 'suricata', 'tagcheck']

@odm.model(index=True, store=True)
class Signature(odm.Model):
    classification = odm.Classification(store=True, default=Classification.UNRESTRICTED)
    data = odm.Text(index=False, store=False)
    last_modified = odm.Date(default="NOW")
    last_saved_by = odm.Keyword(default="assemblyline_auto_importer")
    name = odm.Keyword(copyto="__text__")
    order = odm.Integer(store=False)
    revision = odm.Integer()
    signature_id = odm.Keyword()
    source = odm.Keyword()
    state_change_date = odm.Optional(odm.Date(store=False))
    state_change_user = odm.Optional(odm.Keyword(store=False))
    status = odm.Enum(values=RULE_STATUSES, copyto="__text__")
    type = odm.Enum(values=VALID_TYPES, copyto="__text__")
