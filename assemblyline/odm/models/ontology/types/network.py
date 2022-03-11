from assemblyline import odm
from assemblyline.odm.models.ontology.types.process import Process


# Details for a low-level network connection by IP
class NetworkConnection(odm.Model):

    # The GUID associated with the connection
    guid = odm.Text()
    # The normalized tag of the object
    tag = odm.Optional(odm.Text())

    # The process that spawned the network connection
    process = odm.Optional(odm.Compound(Process))
    # The source IP of the connection
    source_ip = odm.Optional(odm.IP())
    # The source port of the connection
    source_port = odm.Optional(odm.Integer())
    # The destination IP of the connection
    destination_ip = odm.IP()
    # The destination IP of the connection
    destination_port = odm.Integer()
    # The transport layer protocol of the connection
    transport_layer_protocol = odm.Enum(["tcp", "udp"])
    # The direction of the network connection
    direction = odm.Enum(["outbound", "inbound", "unknown"])
    # The time at which the network connection was first observed
    timestamp = odm.Optional(odm.Date())
    # The hash of the tree ID
    tree_id = odm.Optional(odm.Text())


# Details for a DNS request
class NetworkDNS(odm.Model):

    # The low-level details of the DNS request
    connection_details = odm.Compound(NetworkConnection)
    # The domain requested
    domain = odm.Domain()
    # A list of IPs that were resolved
    resolved_ips = odm.List(odm.IP())
    # The type of DNS request
    lookup_type = odm.Text()


# Details for an HTTP request
class NetworkHTTP(odm.Model):

    # The low-level details of the DNS request
    connection_details = odm.Compound(NetworkConnection)
    # The URI requested
    request_uri = odm.URI()
    # Headers included in the request
    request_headers = odm.Mapping(odm.Json())
    # The method of the request
    request_method = odm.Enum(["GET", "POST", "PUT", "DELETE", "HEAD", "CONNECT", "OPTIONS", "TRACE", "PATCH"])
    # The status code of the response
    response_status_code = odm.Optional(odm.Integer())
    # The body of the response
    response_body = odm.Optional(odm.Text())
