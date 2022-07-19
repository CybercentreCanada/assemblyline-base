from assemblyline import odm
from assemblyline.common import forge
from assemblyline.odm.models.tagging import Tagging
from assemblyline.odm.models.ontology.results import Antivirus, Process, Sandbox, NetworkConnection, Signature
from assemblyline.odm.models.ontology.filetypes import PE

Classification = forge.get_classification()
ODM_VERSION = "1.0"


@odm.model(description="File Characteristics")
class File(odm.Model):
    # Common information
    md5 = odm.MD5(description="MD5 of file")
    sha1 = odm.SHA1(description="SHA1 of file")
    sha256 = odm.SHA256(description="SHA256 of file")
    type = odm.Keyword(description="Type of file as identified by Assemblyline")
    size = odm.Integer(description="Size of the file in bytes")
    names = odm.Optional(odm.List(odm.Text()), description="Known filenames associated to file")
    parent = odm.Optional(odm.SHA256(), description="Immediate parent of file relative to submission")

    # Specialized information (List from Tagging.File)
    # apk = odm.Optional(odm.Compound(APK), description="APK File Properties")
    # jar = odm.Optional(odm.Compound(JAR), description="JAR File Properties")
    # img = odm.Optional(odm.Compound(IMG), description="Image File Properties")
    # ole = odm.Optional(odm.Compound(OLE), description="OLE File Properties")
    pe = odm.Optional(odm.Compound(PE), description="Properties related to PE")
    # pdf = odm.Optional(odm.Compound(PDF), description="PDF File Properties")
    # plist = odm.Optional(odm.Compound(PList), description="PList File Properties")
    # powershell = odm.Optional(odm.Compound(PowerShell), description="PowerShell File Properties")
    # shortcut = odm.Optional(odm.Compound(Shortcut), description="Shortcut File Properties")
    # swf = odm.Optional(odm.Compound(SWF), description="SWF File Properties")


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
    netflow = odm.Optional(odm.List(odm.Compound(NetworkConnection)), description="List of Network Ontologies")
    process = odm.Optional(odm.List(odm.Compound(Process)), description="List of Process Ontologies")
    sandbox = odm.Optional(odm.List(odm.Compound(Sandbox)), description="List of Sandbox Ontologies")
    signature = odm.Optional(odm.List(odm.Compound(Signature)), description="List of Signature Ontologies")
    tags = odm.Optional(odm.Mapping(odm.List(odm.Any())),
                        description="Tags raised during analysis. Refer to [Tagging](../../tagging/)")
    heuristics = odm.Optional(odm.List(odm.Compound(Heuristics)), description="Heuristics raised during analysis")


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
