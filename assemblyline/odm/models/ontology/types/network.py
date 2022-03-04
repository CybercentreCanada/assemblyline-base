from assemblyline import odm
from assemblyline.odm.models.ontology.types.process import Process


# Details for a low-level network connection by IP
class NetworkConnection(odm.Model):

    # The GUID associated with the connection
    guid = odm.Text()
    # The process that spawned the network connection
    process = odm.Optional(odm.Compound(Process))
    # The source IP of the connection
    source_ip = odm.IP()
    # The source port of the connection
    source_port = odm.Integer()
    # The destination IP of the connection
    destination_ip = odm.IP()
    # The destination IP of the connection
    destination_port = odm.Integer()
    # The transport layer protocol of the connection
    transport_layer_protocol = odm.Enum(["tcp", "udp"])
    # The direction of the network connection
    direction = odm.Enum(["outbound", "inbound", "unknown"])


# Details for a DNS request
class NetworkDNS(odm.Model):

    # The GUID associated with the connection
    guid = odm.Text()
    # The low-level details of the DNS request
    connection_details = odm.Compound(NetworkConnection)
    # The domain requested
    domain = odm.IP()
    # A list of IPs that were resolved
    resolved_ips = odm.List(odm.IP())


# Details for an HTTP request
class NetworkHTTP(odm.Model):

    # The GUID associated with the connection
    guid = odm.Text()
    # The low-level details of the DNS request
    connection_details = odm.Compound(NetworkConnection)
    # The URI requested
    uri = odm.URI()
    # Headers included in the request
    request_headers = odm.Mapping(str)
    # The method of the request
    request_method = odm.Enum(["GET", "POST", "PUT", "DELETE", "HEAD", "CONNECT", "OPTIONS", "TRACE", "PATCH"])
    # The status code of the response
    response_status_code = odm.Optional(odm.Integer())
