from assemblyline import odm
from assemblyline.common import forge
from assemblyline.odm.models.tagging import CATEGORIES

Classification = forge.get_classification()


@odm.model(index=True, store=True)
class Heuristic(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED)  # Classification of the heuristic
    description = odm.Text(copyto="__text__")                                 # Description of the heuristic
    filetype = odm.Keyword(copyto="__text__")                                 # Type of file targeted by the heuristic
    heur_id = odm.Keyword(copyto="__text__")                                  # Heuristic ID
    name = odm.Keyword(copyto="__text__")                                     # Name of the heuristic
    category = odm.Enum(values=CATEGORIES, copyto="__text__")                 # Category of the heuristic
    score = odm.Integer()                                                     # Score of the heuristic
