from assemblyline import odm
from assemblyline.common.dict_utils import get_dict_fingerprint_hash
from assemblyline.odm.models.result import Attack
from assemblyline.odm.models.ontology.results import Process

OID_PARTS = ['name', 'type']


@odm.model(description="Attribute relating to the signature that was raised during the analysis of the task")
class Attribute(odm.Model):
    source_process = odm.Optional(odm.Compound(Process), description="Initiating process")
    target_process = odm.Optional(odm.Compound(Process), description="Final process")
    event_id = odm.Optional(odm.Text(), description="Event ID")
    source_ip = odm.Optional(odm.IP(), description="Source IP Address")
    source_port = odm.Optional(odm.Integer(), description="Source Port")
    destination_ip = odm.Optional(odm.IP(), description="Destination IP Address")
    destination_port = odm.Optional(odm.Integer(), description="Source Port")
    domain = odm.Optional(odm.Domain(), description="Domain")
    uri = odm.Optional(odm.URI(), description="URI")
    file_hash = odm.Optional(odm.SHA256(), description="SHA256 of file")
    registry = odm.Optional(odm.Text(), description="Registry key")


@odm.model(index=False, store=False, description="A signature that was raised during the analysis of the task")
class Signature(odm.Model):
    oid = odm.Keyword(description="Unique identifier of ontology")

    name = odm.Keyword(description="The name of the signature")
    type = odm.Enum(values=['CUCKOO', 'YARA', 'SIGMA', 'SURICATA'], description="Type of signature")
    attributes = odm.Optional(odm.List(odm.Compound(Attribute)), description="Attributes about the signature")
    attacks = odm.Optional(odm.List(odm.Compound(Attack)),
                           description="A list of ATT&CK patterns and categories of the signature")
    actors = odm.Optional(odm.List(odm.Text()), description="List of actors of the signature")
    malware_families = odm.Optional(odm.List(odm.Text()), description="List of malware families of the signature")

    def get_oid(data: dict):
        return f"signature_{get_dict_fingerprint_hash({key: data.get(key) for key in OID_PARTS})}"
