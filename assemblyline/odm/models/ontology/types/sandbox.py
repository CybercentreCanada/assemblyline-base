from assemblyline import odm
from assemblyline.odm.models.alert import Attack
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
            version = odm.Optional(odm.List(odm.Keyword()))
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

        # An indicator of compromise, aka something interesting that the signature was raised on that is worth reporting
        class IOC(odm.Model):
            # An IP that is an indicator of compromise
            ip = odm.Optional(odm.IP())
            # A domain that is an indicator of compromise
            domain = odm.Optional(odm.Domain())
            # An URI that is an indicator of compromise
            uri = odm.Optional(odm.URI())
            # The path of an URI that is an indicator of compromise
            uri_path = odm.Optional(odm.URIPath())
            # A process that is an indicator of compromise
            process = odm.Optional(odm.Compound(Process))

            # TODO: Require ODM models for these values
            # file = odm.Optional(odm.Text())
            # registry = odm.Optional(odm.Text())

        # The process associated with the signature
        process = odm.Optional(odm.Compound(Process))
        # The name of the signature
        name = odm.Keyword()
        # The description of the signature
        description = odm.Optional(odm.Keyword())
        # A list of Att&ck patterns and categories of the signature
        attack = odm.Optional(odm.List(odm.Compound(Attack)))
        # A list of indicators of compromise. A signature can have more than one IOC.
        iocs = odm.Optional(odm.List(odm.Compound(IOC)))

    # Metadata for the analysis
    analysis_metadata = odm.Compound(AnalysisMetadata)
    # Signatures that the file may have
    signatures = odm.Optional(odm.List(odm.Compound(Signature)))
    # The IP traffic observed during analysis
    network_connections = odm.Optional(odm.List(odm.Compound(NetworkConnection)))
    # The DNS traffic observed during analysis
    network_dns = odm.Optional(odm.List(odm.Compound(NetworkDNS)))
    # The HTTP traffic observed during analysis
    network_http = odm.Optional(odm.List(odm.Compound(NetworkHTTP)))
    # A list of processes
    processes = odm.Optional(odm.List(odm.Compound(Process)))
    # The name of the sandbox
    sandbox_name = odm.Keyword()
    # The version of the sandbox
    sandbox_version = odm.Optional(odm.Keyword())
    # Version of AV ontological result
    odm_version = odm.Text(default="1.0")
