from assemblyline import odm
from assemblyline.common.dict_utils import get_dict_fingerprint_hash, flatten
from assemblyline.odm.models.ontology.results.process import ObjectID

OID_PARTS = ['sandbox_name', 'sandbox_version', 'analysis_metadata.start_time', 'analysis_metadata.end_time', 'analysis_metadata.task_id']


@odm.model(description="Sandbox Ontology Model")
class Sandbox(odm.Model):
    @odm.model(description="The metadata of the analysis, per analysis")
    class AnalysisMetadata(odm.Model):
        @odm.model(description="The metadata regarding the machine where the analysis took place")
        class MachineMetadata(odm.Model):
            ip = odm.Optional(odm.IP(), description="The IP of the machine used for analysis")
            hypervisor = odm.Optional(odm.Keyword(), description="The hypervisor of the machine used for analysis")
            hostname = odm.Optional(odm.Keyword(), description="The name of the machine used for analysis")
            platform = odm.Optional(odm.Platform(), description="The platform of the machine used for analysis")
            version = odm.Optional(odm.Keyword(),
                                   description="The version of the operating system of the machine used for analysis")
            architecture = odm.Optional(odm.Processor(),
                                        description="The architecture of the machine used for analysis")

        task_id = odm.Optional(odm.Keyword(), description="The ID used for identifying the analysis task")
        start_time = odm.Date(description="The start time of the analysis")
        end_time = odm.Optional(odm.Date(), description="The end time of the analysis")
        routing = odm.Optional(odm.Keyword(),
                               description="The routing used in the sandbox setup (Spoofed, Internet, Tor, VPN)")
        machine_metadata = odm.Optional(odm.Compound(MachineMetadata), description="The metadata of the analysis")

    objectid = odm.Compound(ObjectID, description="The object ID of the sandbox object")

    analysis_metadata = odm.Compound(AnalysisMetadata, description="Metadata for the analysis")
    sandbox_name = odm.Keyword(description="The name of the sandbox")
    sandbox_version = odm.Optional(odm.Keyword(), description="The version of the sandbox")

    def get_oid(data: dict):
        return f"sandbox_{get_dict_fingerprint_hash({key: flatten(data).get(key) for key in OID_PARTS})}"

    def get_tag(data: dict):
        return f"{data['sandbox_name']} @ {data['analysis_metadata']['start_time']}"
