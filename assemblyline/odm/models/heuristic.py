from assemblyline import odm
from assemblyline.common import forge
from assemblyline.odm.models.statistics import Statistics

Classification = forge.get_classification()


@odm.model(index=True, store=True, description="Model of Service Heuristics")
class Heuristic(odm.Model):
    attack_id = odm.List(odm.Keyword(copyto="__text__"), default=[], description="List of all associated ATT&CK IDs")
    classification = odm.Classification(default=Classification.UNRESTRICTED,
                                        description="Classification of the heuristic")
    description = odm.Text(copyto="__text__", description="Description of the heuristic")
    filetype = odm.Keyword(copyto="__text__", description="What type of files does this heuristic target?")
    heur_id = odm.Keyword(copyto="__text__", description="ID of the Heuristic")
    name = odm.Keyword(copyto="__text__", description="Name of the heuristic")
    score = odm.Integer(description="Default score of the heuristic")
    signature_score_map = odm.Mapping(odm.Integer(), default={},
                                      description="Score of signatures for this heuristic")
    stats = odm.Compound(Statistics, default={}, description="Statistics related to the Heuristic")
    max_score = odm.Optional(odm.Integer(), description="Maximum score for heuristic")
