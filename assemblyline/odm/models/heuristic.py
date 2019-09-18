from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.attack_map import attack_map

Classification = forge.get_classification()
PATTERNS = list(attack_map.keys())

@odm.model(index=True, store=True)
class Heuristic(odm.Model):
    attack_id = odm.Optional(odm.Enum(values=PATTERNS, copyto="__text__"))       # Att&ck matrix pattern
    classification = odm.Classification(default=Classification.UNRESTRICTED)     # Classification of the heuristic
    description = odm.Text(copyto="__text__")                                    # Description of the heuristic
    filetype = odm.Keyword(copyto="__text__")                                    # Type of file targeted
    heur_id = odm.Keyword(copyto="__text__")                                     # Heuristic ID
    name = odm.Keyword(copyto="__text__")                                        # Name of the heuristic
    score = odm.Integer()                                                        # Score of the heuristic
