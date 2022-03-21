from assemblyline import odm
from assemblyline.odm.models.result import Attack
from assemblyline.odm.models.ontology.types.process import Process
from assemblyline.odm.models.ontology.types.network import NetworkConnection, NetworkDNS, NetworkHTTP


# The result ontology for sandbox output
class Sandbox(odm.Model):

    # The metadata of the analysis, per analysis
    class AnalysisMetadata(odm.Model):

        # The metadata regarding the machine where the analysis took place
        class MachineMetadata(odm.Model):
            # The IP of the machine used for analysis
            ip = odm.Optional(odm.IP())
            # The hypervisor of the machine used for analysis
            hypervisor = odm.Optional(odm.Keyword())
            # The name of the machine used for analysis
            hostname = odm.Optional(odm.Keyword())
            # The platform of the machine used for analysis
            platform = odm.Optional(odm.Platform())
            # The version of the operating system of the machine used for analysis
            version = odm.Optional(odm.Keyword())
            # The architecture of the machine used for analysis
            architecture = odm.Optional(odm.Processor())

        # The ID used for identifying the analysis task
        task_id = odm.Optional(odm.Keyword())
        # The start time of the analysis
        start_time = odm.Date()
        # The end time of the analysis
        end_time = odm.Date()
        # The routing used in the sandbox setup (Spoofed, Internet, Tor, VPN)
        routing = odm.Optional(odm.Keyword())
        # The metadata of the analysis
        machine_metadata = odm.Optional(odm.Compound(MachineMetadata))

    # A signature that was raised during the analysis of the task
    class Signature(odm.Model):

        # The subject of the signature, aka something interesting that the signature was raised on that is worth reporting
        class Subject(odm.Model):
            ip = odm.Optional(odm.IP())
            domain = odm.Optional(odm.Domain())
            uri = odm.Optional(odm.URI())
            uri_path = odm.Optional(odm.URIPath())
            process = odm.Optional(odm.Compound(Process))
            file = odm.Optional(odm.Text())
            registry = odm.Optional(odm.Text())

        # The name of the signature
        name = odm.Keyword()
        # The process associated with the signature
        process = odm.Optional(odm.Compound(Process))
        # A list of subjects. A signature can have more than one subject.
        subjects = odm.Optional(odm.List(odm.Compound(Subject)))
        # The description of the signature
        description = odm.Optional(odm.Keyword())
        # A list of Att&ck patterns and categories of the signature
        attack = odm.Optional(odm.List(odm.Compound(Attack)))

    # Metadata for the analysis
    analysis_metadata = odm.Compound(AnalysisMetadata)
    # A list of processes
    processes = odm.List(odm.Compound(Process), default=[])
    # The IP traffic observed during analysis
    network_connections = odm.List(odm.Compound(NetworkConnection), default=[])
    # Signatures that the file may have
    signatures = odm.List(odm.Compound(Signature), default=[])
    # The DNS traffic observed during analysis
    network_dns = odm.List(odm.Compound(NetworkDNS), default=[])
    # The HTTP traffic observed during analysis
    network_http = odm.List(odm.Compound(NetworkHTTP), default=[])
    # The name of the sandbox
    sandbox_name = odm.Keyword()
    # The version of the sandbox
    sandbox_version = odm.Optional(odm.Keyword())
    # Version of AV ontological result
    odm_version = odm.Text(default="1.0")
