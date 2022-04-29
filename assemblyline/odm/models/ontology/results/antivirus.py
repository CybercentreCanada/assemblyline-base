from assemblyline import odm
from assemblyline.common.dict_utils import get_dict_fingerprint_hash

OID_PARTS = ['engine_name', 'virus_name']


@odm.model(description="Antivirus Ontology Model")
class Antivirus(odm.Model):
    oid = odm.UUID(description="Unique identifier of ontology")
    oid_parent = odm.Optional(odm.UUID(), description="Parent of this ontology")
    oid_children = odm.Optional(odm.List(odm.UUID()), description="Children of this ontology")
    engine_name = odm.Keyword(description="Name of antivirus engine")
    engine_version = odm.Optional(odm.Keyword(), description="Version of antivirus engine")
    engine_definition_version = odm.Optional(odm.Keyword(), description="Version of definition set")
    virus_name = odm.Optional(odm.Keyword(), description="The name of the virus")
    # What category does the verdict fall under?
    category = odm.Optional(odm.Enum(['type-unsupported',
                                      'undetected',
                                      'failure',
                                      'suspicious',
                                      'malicious']),
                            description="What category does the verdict fall under?<br><ul>"
                            "<li>`type-unsupported`: File sent to antivirus is unsupported</li>"
                            "<li>`undetected`: File not detected by antivirus</li>"
                            "<li>`failure`: Antivirus failed during detection</li>"
                            "<li>`suspicious`: Antivirus deems suspicious</li>"
                            "<li>`malicious`: Antivirus deems malicious</li></ul>")

    def get_oid(data: dict):
        return f"antivirus_{get_dict_fingerprint_hash({key: data.get(key) for key in OID_PARTS})}"
