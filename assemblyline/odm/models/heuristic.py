from assemblyline import odm
from assemblyline.common import forge


CATEGORIES = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
    "Effects"
]


Classification = forge.get_classification()


@odm.model(index=True, store=False)
class Namespace(odm.Model):
    collection = odm.Keyword()    # Collection where the ID is stored
    id_field = odm.Keyword()      # Field to lookup as the ID for the namespace


@odm.model(index=True, store=True)
class Heuristic(odm.Model):
    category = odm.Enum(values=CATEGORIES, copyto="__text__")                 # Category of the heuristic
    classification = odm.Classification(default=Classification.UNRESTRICTED)  # Classification of the heuristic
    description = odm.Text(copyto="__text__")                                 # Description of the heuristic
    filetype = odm.Keyword(copyto="__text__")                                 # Type of file targeted by the heuristic
    heur_id = odm.Keyword(copyto="__text__")                                  # Heuristic ID
    name = odm.Keyword(copyto="__text__")                                     # Name of the heuristic
    namespace = odm.Optional(odm.Compound(Namespace))                         # If namespace, the namespace definition
    score = odm.Integer()                                                     # Score of the heuristic
