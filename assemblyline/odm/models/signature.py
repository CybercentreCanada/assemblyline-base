from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()

DEPLOYED_STATUSES = ['DEPLOYED', 'NOISY', 'DISABLED']
DRAFT_STATUSES = ['STAGING', 'TESTING']
STALE_STATUSES = ['INVALID']

RULE_STATUSES = DEPLOYED_STATUSES + DRAFT_STATUSES + STALE_STATUSES
RULE_TYPES = {"rule", "private rule", "global rule", "global private rule"}
VALID_GROUPS = {"technique", "exploit", "implant", "info", "tool"}


@odm.model(index=True, store=True)
class RequiredMeta(odm.Model):
    al_status = odm.Enum(values=RULE_STATUSES,
                         default="TESTING")                     # Status of the rule in Assemblyline
    creation_date = odm.Date(default="NOW")                     # Date at which the signature was created
    description = odm.Text(store=False, copyto="__text__")      # Description of the rule
    organisation = odm.Keyword(store=False, copyto="__text__")  # Organisation acronym which created the rule
    last_modified = odm.Date(default="NOW")                     # Last time signature was modified
    poc = odm.Keyword()                                         # Point of contact for the rule
    rule_group = odm.Enum(values=VALID_GROUPS)                  # Group that the rule is part of
    exploit = odm.Optional(odm.Keyword(copyto="__text__"))      # Exploit that the rule detects
    implant = odm.Optional(odm.Keyword(copyto="__text__"))      # Implant that the rule detects
    info = odm.Optional(odm.Keyword(copyto="__text__"))         # Information gathered from the rule
    technique = odm.Optional(odm.Keyword(copyto="__text__"))    # Technique that the rule detects
    tool = odm.Optional(odm.Keyword(copyto="__text__"))         # Tool that the rule detects
    rule_id = odm.Keyword()                                     # ID of the rule
    rule_version = odm.Integer()                                # Version of the rule
    yara_version = odm.Keyword()                                # Version of Yara the rule was built for


@odm.model(index=True, store=False)
class Signature(odm.Model):
    classification = odm.Classification(store=True,
        default=Classification.UNRESTRICTED)             # Classification of the rule
    comments = odm.List(odm.Keyword(), default=[],
                        copyto="__text__")               # Comments for the signature
    condition = odm.List(odm.Keyword(), default=[])      # List of conditions for the signature
    depends = odm.List(odm.Keyword(), default=[])        # other signature names that the signature depends on
    meta = odm.Compound(RequiredMeta)                    # Required metadata
    meta_extra = odm.Mapping(odm.Keyword(), default={})  # Optional metadata
    modules = odm.List(odm.Keyword(), default=[])        # Modules that the signature needs
    name = odm.Keyword(store=True, copyto="__text__")    # Name of the signature
    strings = odm.List(odm.Keyword(), default=[])        # Search strings for the signature
    tags = odm.List(odm.Keyword(), default=[])           # Tags associated to the signature
    type = odm.Enum(values=RULE_TYPES)                   # Type of rule
    warning = odm.Optional(odm.Keyword())                # Optimization warnings thrown when the rule was tested
