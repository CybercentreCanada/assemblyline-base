from assemblyline import odm
from assemblyline.common.dict_utils import get_dict_fingerprint_hash
from assemblyline.odm.models.result import Attack
from assemblyline.odm.models.ontology.results import Process

OID_PARTS = ['name', 'type']


@odm.model(description="Attributes relating to the signature that was raised during the analysis of the task")
class Attributes(odm.Model):
    source_process = odm.Optional(odm.Compound(Process), description="Initiating process")
    target_process = odm.Optional(odm.Compound(Process), description="Final process")
    event_id = odm.Optional(odm.Text(), description="Event ID")
    ip = odm.Optional(odm.IP(), description="IP Address")
    domain = odm.Optional(odm.Domain(), description="Domain")
    uri = odm.Optional(odm.URI(), description="URI")
    file_hash = odm.Optional(odm.SHA256(), description="SHA256 of file")
    registry = odm.Optional(odm.Text(), description="Registry key")


@odm.model(index=False, store=False, description="A signature that was raised during the analysis of the task")
class Signature(odm.Model):
    oid = odm.Keyword(description="Unique identifier of ontology")

    name = odm.Keyword(description="The name of the signature")
    type = odm.Enum(values=['CUCKOO', 'YARA', 'SIGMA', 'SURICATA'], description="Type of signature")
    attributes = odm.Optional(odm.Compound(Attributes), description="Attributes about the signature")
    attack = odm.Optional(odm.List(odm.Compound(Attack)),
                          description="A list of ATT&CK patterns and categories of the signature")
    actor = odm.Optional(odm.List(odm.Text()), description="List of actors of the signature")
    malware_family = odm.Optional(odm.List(odm.Text()), description="List of malware families of the signature")

    def get_oid(data: dict):
        return f"signature_{get_dict_fingerprint_hash({key: data.get(key) for key in OID_PARTS})}"
