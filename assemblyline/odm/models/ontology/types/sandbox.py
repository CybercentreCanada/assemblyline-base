from assemblyline import odm
from assemblyline.odm.models.result import Attack
from assemblyline.odm.models.ontology.types.process import Process
from assemblyline.odm.models.ontology.types.network import NetworkConnection, NetworkDNS, NetworkHTTP


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
        end_time = odm.Date(description="The end time of the analysis")
        routing = odm.Optional(odm.Keyword(),
                               description="The routing used in the sandbox setup (Spoofed, Internet, Tor, VPN)")
        machine_metadata = odm.Optional(odm.Compound(MachineMetadata), description="The metadata of the analysis")

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

        name = odm.Keyword(description="The name of the signature")
        process = odm.Optional(odm.Compound(Process), description="The process associated with the signature")
        subjects = odm.Optional(odm.List(odm.Compound(Subject)),
                                description="A list of subjects. A signature can have more than one subject.")
        description = odm.Optional(odm.Keyword(), description="The description of the signature")
        attack = odm.Optional(odm.List(odm.Compound(Attack)),
                              description="A list of Att&ck patterns and categories of the signature")

    analysis_metadata = odm.Compound(AnalysisMetadata, description="Metadata for the analysis")
    processes = odm.List(odm.Compound(Process), default=[], description="A list of processes")
    network_connections = odm.List(odm.Compound(NetworkConnection), default=[],
                                   description="The IP traffic observed during analysis")
    signatures = odm.List(odm.Compound(Signature), default=[], description="Signatures that the file may have")
    network_dns = odm.List(odm.Compound(NetworkDNS), default=[], description="The DNS traffic observed during analysis")
    network_http = odm.List(odm.Compound(NetworkHTTP), default=[],
                            description="The HTTP traffic observed during analysis")
    sandbox_name = odm.Keyword(description="The name of the sandbox")
    sandbox_version = odm.Optional(odm.Keyword(), description="The version of the sandbox")
    odm_version = odm.Text(default="1.0", description="Version of sandbox ontological result")
