from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()


@odm.model(index=True, store=True)
class Heuristic(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED)  # Classification of the heuristic
    description = odm.Keyword(copyto="__text__")                              # Description of the heuristic
    filetype = odm.Keyword(copyto="__text__")                                 # Type of file targeted by the heuristic
    heur_id = odm.Integer()                                                   # Heuristic ID
    name = odm.Keyword(copyto="__text__")                                     # Name of the heuristic
