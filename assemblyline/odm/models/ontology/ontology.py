from assemblyline import odm
from assemblyline.common import forge
from assemblyline.odm.models.ontology.results import (
    Antivirus,
    HTTP,
    MalwareConfig,
    NetworkConnection,
    Process,
    Sandbox,
    Signature,
)
from assemblyline.odm.models.ontology.file import File

Classification = forge.get_classification()
ODM_VERSION = "1.10"


@odm.model(index=False, store=False, description="Heuristics raised")
class Heuristics(odm.Model):
    heur_id = odm.Keyword(description="Heuristic ID")
    score = odm.Integer(description="Score associated to heurstic")
    times_raised = odm.Integer(description="The number of times the heuristic was raised")
    name = odm.Text(description="Name of the heuristic raised")
    tags = odm.Mapping(odm.List(odm.Any()),
                       description="Tags associated to heuristic. Refer to [Tagging](../../tagging/)")


@odm.model(index=False, store=False, description="Ontological Results")
class Results(odm.Model):
    antivirus = odm.Optional(odm.List(odm.Compound(Antivirus)), description="List of Antivirus Ontologies")
    http = odm.Optional(odm.List(odm.Compound(HTTP)), description="List of HTTP Ontologies")
    malwareconfig = odm.Optional(odm.List(odm.Compound(MalwareConfig)), description="List of MalwareConfig Ontologies")
    netflow = odm.Optional(odm.List(odm.Compound(NetworkConnection)), description="List of Network Ontologies")
    process = odm.Optional(odm.List(odm.Compound(Process)), description="List of Process Ontologies")
    sandbox = odm.Optional(odm.List(odm.Compound(Sandbox)), description="List of Sandbox Ontologies")
    signature = odm.Optional(odm.List(odm.Compound(Signature)), description="List of Signature Ontologies")
    tags = odm.Optional(odm.Mapping(odm.List(odm.Any())),
                        description="Tags raised during analysis. Refer to [Tagging](../../tagging/)")
    heuristics = odm.Optional(odm.List(odm.Compound(Heuristics)), description="Heuristics raised during analysis")
    score = odm.Optional(odm.Integer(description="The score assigned to the file"))


@odm.model(index=False, store=False, description="Service Details")
class Service(odm.Model):
    name = odm.Keyword(description="Service Name")
    version = odm.Keyword(description="Service Version")
    tool_version = odm.Optional(odm.Keyword(default=''), description="Service Tool Version")


@odm.model(index=False, store=False, description="Submission Details")
class Submission(odm.Model):
    date = odm.Optional(odm.Date(), description="Date of analysis")
    metadata = odm.Mapping(odm.Text(), description="Metadata associated to submission")
    sid = odm.Optional(odm.Keyword(), description="Submission ID associated to file")
    source_system = odm.Optional(odm.Text(), description="Which Assemblyline instance does the result originate from?")
    original_source = odm.Optional(odm.Text(), description="Source as specified by submitter (from metadata)")
    classification = odm.ClassificationString(default=Classification.UNRESTRICTED,
                                              description="Submitted classification")
    submitter = odm.Optional(odm.Keyword(), description="Submitter")
    retention_id = odm.Optional(odm.Keyword(), description="Reference to knowledge base for long-term data retention.")
    max_score = odm.Optional(odm.Integer(description="The highest file score of the submission"))


# ResultOntology
@odm.model(index=False, store=False, description="Assemblyline Result Ontology")
class ResultOntology(odm.Model):
    # Record Identification
    odm_type = odm.Text(default="Assemblyline Result Ontology", description="Type of ODM Model")
    odm_version = odm.Text(default=ODM_VERSION, description="Version of ODM Model")

    # Record Classification
    classification = odm.ClassificationString(description="Classification of Ontological Record")

    # File Characteristics
    file = odm.Compound(File, description="Descriptors about file being analyzed")

    # Service Information
    service = odm.Compound(Service, description="Information about Service")

    # Submission Information
    submission = odm.Optional(odm.Compound(Submission), description="Information about Submission")

    # Results
    results = odm.Optional(odm.Compound(Results), description="Ontological Results")
