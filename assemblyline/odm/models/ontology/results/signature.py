from assemblyline import odm
from assemblyline.common.dict_utils import get_dict_fingerprint_hash
from assemblyline.odm.models.result import Attack
from assemblyline.odm.models.ontology.results.process import ObjectID

OID_PARTS = ['name', 'type']
TAG_PARTS = ['type', 'name']


@odm.model(description="Attribute relating to the signature that was raised during the analysis of the task")
class Attribute(odm.Model):
    source = odm.Compound(ObjectID, description="Object that the rule triggered on")
    target = odm.Optional(odm.Compound(ObjectID), description="Object targetted by source object")
    meta = odm.Optional(odm.Text(), description="Metadata about the detection")
    event_record_id = odm.Optional(odm.Text(), description="Event Record ID (Event Logs)")
    domain = odm.Optional(odm.Domain(), description="Domain")
    uri = odm.Optional(odm.URI(), description="URI")
    file_hash = odm.Optional(odm.SHA256(), description="SHA256 of file")

@odm.model(index=False, store=False, description="A signature that was raised during the analysis of the task")
class Signature(odm.Model):
    objectid = odm.Compound(ObjectID, description="The object ID of the signature object")

    name = odm.Keyword(description="The name of the signature")
    type = odm.Enum(values=['CUCKOO', 'YARA', 'SIGMA', 'SURICATA'], description="Type of signature")
    attributes = odm.Optional(odm.List(odm.Compound(Attribute)), description="Attributes about the signature")
    attacks = odm.Optional(odm.List(odm.Compound(Attack)),
                           description="A list of ATT&CK patterns and categories of the signature")
    actors = odm.Optional(odm.List(odm.Text()), description="List of actors of the signature")
    malware_families = odm.Optional(odm.List(odm.Text()), description="List of malware families of the signature")

    def get_oid(data: dict):
        return f"signature_{get_dict_fingerprint_hash({key: data.get(key) for key in OID_PARTS})}"

    def get_tag(data: dict):
        return '.'.join([data.get(key) for key in TAG_PARTS])
