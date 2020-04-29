from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.attack_map import attack_map

Classification = forge.get_classification()
ATTACK_ID_LIST = list(attack_map.keys())


@odm.model(index=True, store=True)
class Heuristic(odm.Model):
    attack_id = odm.List(odm.Enum(values=ATTACK_ID_LIST, copyto="__text__"),
                         default=[])                                          # List of all associated Att&ck IDs
    classification = odm.Classification(default=Classification.UNRESTRICTED)  # Classification of the heuristic
    description = odm.Text(copyto="__text__")                                 # Description of the heuristic
    filetype = odm.Keyword(copyto="__text__")                                 # Type of file targeted
    heur_id = odm.Keyword(copyto="__text__")                                  # Heuristic ID
    name = odm.Keyword(copyto="__text__")                                     # Name of the heuristic
    score = odm.Integer()                                                     # Default score of the heuristic
    signature_score_map = odm.Mapping(odm.Integer(), default={})              # Score of signatures for this heuristic
    max_score = odm.Optional(odm.Integer())                                   # Maximum score for heuristic
