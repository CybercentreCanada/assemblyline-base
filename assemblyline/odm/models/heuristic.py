from assemblyline import odm
from assemblyline.common import forge
from assemblyline.common.attack_map import attack_map

Classification = forge.get_classification()
PATTERNS = list(attack_map.keys())


@odm.model(index=True, store=False)
class Namespace(odm.Model):
    collection = odm.Keyword()    # Collection where the ID is stored
    id_field = odm.Keyword()      # Field to lookup as the ID for the namespace


@odm.model(index=True, store=True)
class Heuristic(odm.Model):
    attack_id = odm.Optional(odm.Enum(values=PATTERNS, copyto="__text__"))       # Att&ck matrix pattern
    classification = odm.Classification(default=Classification.UNRESTRICTED)     # Classification of the heuristic
    description = odm.Text(copyto="__text__")                                    # Description of the heuristic
    filetype = odm.Keyword(copyto="__text__")                                    # Type of file targeted
    heur_id = odm.Keyword(copyto="__text__")                                     # Heuristic ID
    name = odm.Keyword(copyto="__text__")                                        # Name of the heuristic
    namespace = odm.Optional(odm.Compound(Namespace))                            # Namespace definition if namespace
    score = odm.Integer()                                                        # Score of the heuristic
