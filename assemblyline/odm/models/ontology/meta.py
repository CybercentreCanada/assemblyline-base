from assemblyline import odm
from assemblyline.common import forge
from assemblyline.odm.models.tagging import Tagging

Classification = forge.get_classification()


# Result Metadata
@odm.model(index=False, store=False)
class ResultOntology(odm.Model):
    # Required metadata
    md5 = odm.MD5()                                                             # MD5 of file
    sha1 = odm.SHA1()                                                           # SHA1 of file
    sha256 = odm.SHA256()                                                       # SHA256 of file
    type = odm.Keyword()                                                        # Type of file as identified by Assemblyline
    size = odm.Integer()                                                        # Size of the file in bytes
    filename = odm.Text()                                                       # Name of the file as submitted
    date = odm.Date()                                                           # Date of analysis
    classification = odm.Keyword(default=Classification.UNRESTRICTED)           # Classification of the service result
    service_name = odm.Keyword()                                                # Service Name
    service_version = odm.Keyword()                                             # Service Version
    service_tool_version = odm.Optional(odm.Keyword(default=''))                # Service Tool Version

    # Optional metadata

    # Who's the parent of this file, if any.
    parent = odm.Optional(odm.SHA256())
    # Used to link to the submission id in Assemblyline
    sid = odm.Optional(odm.Keyword())
    # Which instance of Assemblyline did this come from?
    source_system = odm.Optional(odm.Text())
    # Source as specified by submitter (from metadata)
    original_source = odm.Optional(odm.Text())
    # What classification did the submitter submit under?
    submitted_classification = odm.Keyword(default=Classification.UNRESTRICTED)
    # Who submitted this file?
    submitter = odm.Optional(odm.Keyword())
    # Used to link to knowledge base retaining long-term data
    retention_id = odm.Optional(odm.Keyword())
    # What tags did the service associate to the result
    tags = odm.Optional(odm.Mapping(odm.List(odm.Compound(Tagging))))
    # What tags are related to certain heuristics raised
    # {
    #   "Bad Things happened": {
    #       "network.static.uri": ["bad.domain", ...],
    #       ...
    #   }
    # }
    heuristics = odm.Optional(odm.Mapping(odm.Mapping(odm.List(odm.Compound(Tagging)))))
