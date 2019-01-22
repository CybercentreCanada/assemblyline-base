from assemblyline import odm
from assemblyline.common.classification import Classification

DEPLOYED_STATUSES = ['DEPLOYED', 'DISABLED']
DRAFT_STATUSES = ['STAGING', 'TESTING']

SCORES = [
    "OK",      # -1000
    "NULL",    # 0
    "LOW",     # 1
    "MED",     # 10
    "HIGH",    # 100
    "VHIGH",   # 500
    "SURE"     # 1000
]
STATUSES = DEPLOYED_STATUSES + DRAFT_STATUSES


@odm.model(index=True, store=True)
class TCSignature(odm.Model):
    al_score = odm.Enum(values=SCORES, default="HIGH")
    al_status = odm.Enum(values=STATUSES, default="DEPLOYED")
    callback = odm.Keyword(default_set=True)
    classification = odm.Classification(default=Classification.NULL_CLASSIFICATION)
    comment = odm.Keyword(default_set=True)
    implant_family = odm.Keyword(default_set=True)
    threat_actor = odm.Keyword(default_set=True)
    values = odm.List(odm.Keyword(), default=[])
