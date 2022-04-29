from assemblyline import odm
from assemblyline.odm.models.result import Attack
from assemblyline.odm.models.ontology.types import Process


@odm.model(description="A signature that was raised during the analysis of the task")
class Signature(odm.Model):

    @odm.model(description="The subject of the signature, aka something interesting that the signature was raised on that is worth reporting")
    class Subject(odm.Model):
        ip = odm.Optional(odm.IP(), description="Subject's IP")
        domain = odm.Optional(odm.Domain(), description="Subject's domain")
        uri = odm.Optional(odm.URI(), description="Subject's URI")
        process = odm.Optional(odm.Compound(Process), description="Subject's process")
        file = odm.Optional(odm.Text(), description="Subject's file")
        registry = odm.Optional(odm.Text(), description="Subject's registry key")

    oid = odm.UUID(description="Unique identifier of ontology")
    oid_parent = odm.Optional(odm.UUID(), description="Parent of this ontology")
    oid_children = odm.Optional(odm.List(odm.UUID()), description="Children of this ontology")

    name = odm.Keyword(description="The name of the signature")
    process = odm.Optional(odm.Compound(Process), description="The process associated with the signature")
    subjects = odm.Optional(odm.List(odm.Compound(Subject)),
                            description="A list of subjects. A signature can have more than one subject.")
    description = odm.Optional(odm.Keyword(), description="The description of the signature")
    attack = odm.Optional(odm.List(odm.Compound(Attack)),
                          description="A list of ATT&CK patterns and categories of the signature")
    signature_type = odm.Enum(values=['CUCKOO', 'YARA', 'SIGMA', 'SURICATA'])
