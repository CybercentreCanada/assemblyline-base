from assemblyline import odm
from assemblyline.common import forge
from assemblyline.odm.models.tagging import Tagging

Classification = forge.get_classification()


# Result Metadata
@odm.model(index=False, store=False, description="Service Result Ontology Header")
class ResultOntology(odm.Model):
    class HeuristicDetails(odm.Model):
        name = odm.Text(description="Name of the heuristic raised.")
        tags = odm.Compound(Tagging, description="Tags associated to heuristic")

    # Required metadata
    md5 = odm.MD5(description="MD5 of file")
    sha1 = odm.SHA1(description="SHA1 of file")
    sha256 = odm.SHA256(description="SHA256 of file")
    type = odm.Keyword(description="Type of file as identified by Assemblyline")
    size = odm.Integer(description="Size of the file in bytes")
    filename = odm.Text(description="Name of the file as submitted")
    date = odm.Date(description="Date of analysis")
    classification = odm.Keyword(default=Classification.UNRESTRICTED,
                                 description="Classification of the service result")
    service_name = odm.Keyword(description="Service Name")
    service_version = odm.Keyword(description="Service Version")
    service_tool_version = odm.Optional(odm.Keyword(default=''), description="Service Tool Version")

    # Optional metadata

    parent = odm.Optional(odm.SHA256(), description="Immediate parent of file relative to submission")
    sid = odm.Optional(odm.Keyword(), description="Submission ID associated to file")
    source_system = odm.Optional(odm.Text(), description="Which Assemblyline instance does the result originate from?")
    original_source = odm.Optional(odm.Text(), description="Source as specified by submitter (from metadata)")
    submitted_classification = odm.Keyword(default=Classification.UNRESTRICTED, description="Submitted classification")
    submitter = odm.Optional(odm.Keyword(), description="Submitter")
    retention_id = odm.Optional(odm.Keyword(), description="Reference to knowledge base for long-term data retention.")
    # What tags did the service associate to the result
    tags = odm.Optional(odm.Compound(Tagging), description="Tags raised by service")
    # What tags are related to certain heuristics raised
    # {
    #   "SERVICENAME_1": {
    #       "name": "Bad Things happened"
    #       "tags": {
    #           "network": {
    #               "static": {
    #                   "uri": ["bad.domain", ...]
    #                   ...
    #               }
    #               ...
    #           }
    #           ...
    #       }
    #   }
    # }
    heuristics = odm.Optional(odm.Mapping(odm.Compound(HeuristicDetails)), description="Heuristics raised by service.")
