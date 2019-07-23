from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()

DEPLOYED_STATUSES = ['DEPLOYED', 'NOISY', 'DISABLED']
DRAFT_STATUSES = ['STAGING', 'TESTING']
STALE_STATUSES = ['INVALID']

RULE_STATUSES = DEPLOYED_STATUSES + DRAFT_STATUSES + STALE_STATUSES


@odm.model(index=True, store=True)
class Signature(odm.Model):
    classification = odm.Classification(store=True, default=Classification.UNRESTRICTED)  # Classification of the rule
    data = odm.Text(store=False, copyto="__text__")                                       # Data of the signature
    revision = odm.Keyword()                                                              # Revision of the signature
    signature_id = odm.Keyword()                                                          # ID of the signature
    status = odm.Enum(values=RULE_STATUSES)                                               # Type of rule
    type = odm.Keyword()                                                                  # Type of signature
