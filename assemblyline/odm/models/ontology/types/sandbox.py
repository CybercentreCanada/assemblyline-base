from assemblyline import odm
from assemblyline.odm.models.alert import Attack


class Sandbox(odm.Model):
    class AnalysisMetadata(odm.Model):
        class MachineMetadata(odm.Model):
            # The IP of the machine used for analysis
            ip = odm.Optional(odm.IP())
            # The hypervisor of the machine used for analysis
            hypervisor = odm.Optional(odm.Keyword())
            # The name of the machine used for analysis
            name = odm.Optional(odm.Keyword())
            # The platform of the machine used for analysis (windows, linux)
            platform = odm.Optional(odm.Platform())
            # The processor of the machine used for analysis (x64, x86)
            processor = odm.Optional(odm.Processor())

        # The ID used for identifying the task
        task_id = odm.Optional(odm.Keyword())
        # The start time of the analysis
        start_time = odm.Date()
        # The end time of the analysis
        end_time = odm.Date()
        # The routing used in the sandbox setup (Spoofed, Internet, Tor, VPN)
        routing = odm.Optional(odm.Keyword())
        machine_metadata = odm.Optional(odm.Compound(MachineMetadata))

    class Capability(odm.Model):
        # Capablity == Signature
        class IOC(odm.Model):
            ip = odm.Optional(odm.IP())
            domain = odm.Optional(odm.Domain())
            uri = odm.Optional(odm.URI())
            uri_path = odm.Optional(odm.URIPath())
            file = odm.Optional(odm.Text())

        # The process ID of the process that caused the flagged behaviour
        pid = odm.Optional(odm.Keyword())
        # The process name of the process that caused the flagged behaviour
        image = odm.Optional(odm.Keyword())
        # The name of the capability
        name = odm.Keyword()
        # The description of the capability
        description = odm.Optional(odm.Keyword())
        # The Att&ck pattern and category of the capability
        attack = odm.Optional(odm.Compound(Attack))
        iocs = odm.Optional(odm.List(odm.Compound(IOC)))

    class Process(odm.Model):
        pid = odm.Integer()
        ppid = odm.Integer()
        iamge = odm.Text()
        command_line = odm.Text()
        timestamp = odm.Text()
        guid = odm.Text()
        pguid = odm.Text()

    class IpTraffic(odm.Model):
        pid = odm.Optional(odm.Keyword())
        image = odm.Optional(odm.Keyword())
        destination_ip = odm.IP()
        destination_port = odm.Integer()
        transport_layer_protocol = odm.Keyword()

    class DnsTraffic(odm.Model):
        pid = odm.Optional(odm.Keyword())
        image = odm.Optional(odm.Keyword())
        # The hostname requested
        hostname = odm.IP()
        # A list of IPs returned from the request
        resolved_ips = odm.List(odm.IP())

    class HttpTraffic(odm.Model):
        pid = odm.Optional(odm.Keyword())
        image = odm.Optional(odm.Keyword())
        uri = odm.URI()
        request_headers = odm.TypedMapping(type_p=str)
        request_method = odm.Keyword()
        response_status_code = odm.Optional(odm.Integer())

    # Perceived capabilities that the file may have
    capabilities = odm.Optional(odm.List(odm.Compound(Capability)))
    # The IP traffic observed during analysis
    ip_traffic = odm.Optional(odm.List(odm.Compound(IpTraffic)))
    # The DNS traffic observed during analysis
    dns_traffic = odm.Optional(odm.List(odm.Compound(DnsTraffic)))
    # The HTTP traffic observed during analysis
    http_traffic = odm.Optional(odm.List(odm.Compound(HttpTraffic)))
    # A list of processes
    processes = odm.Optional(odm.List(odm.Compound(Process)))
    # The name of the sandbox
    name = odm.Keyword()
    # The version of the sandbox
    version = odm.Optional(odm.Keyword())
    # Version of AV ontological result
    odm_version = odm.Text(default="1.0")
