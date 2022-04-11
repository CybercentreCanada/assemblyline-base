from assemblyline import odm
from assemblyline.odm.models.ontology.types.process import Process
from assemblyline.odm.models.ontology.types.objectid import ObjectID


@odm.model(description="Details for a low-level network connection by IP")
class NetworkConnection(odm.Model):
    objectid = odm.Compound(ObjectID, description="The object ID of the process object")
    process = odm.Optional(odm.Compound(Process), description="The process that spawned the network connection")
    source_ip = odm.Optional(odm.IP(), description="The source IP of the connection")
    source_port = odm.Optional(odm.Integer(), description="The source port of the connection")
    destination_ip = odm.IP(description="The destination IP of the connection")
    destination_port = odm.Integer(description="The destination port of the connection")
    transport_layer_protocol = odm.Enum(["tcp", "udp"], description="The transport layer protocol of the connection")
    direction = odm.Enum(["outbound", "inbound", "unknown"], description="The direction of the network connection")


@odm.model(description="Details for a DNS request")
class NetworkDNS(odm.Model):
    connection_details = odm.Compound(NetworkConnection, description="The low-level details of the DNS request")
    domain = odm.Domain(description="The domain requested")
    resolved_ips = odm.List(odm.IP(), description="A list of IPs that were resolved")
    lookup_type = odm.Text(description="The type of DNS request")


@odm.model(description="Details for an HTTP request")
class NetworkHTTP(odm.Model):
    connection_details = odm.Compound(NetworkConnection, description="The low-level details of the HTTP request")
    request_uri = odm.URI(description="The URI requested")
    request_headers = odm.Mapping(odm.Json(), description="Headers included in the request")
    request_body = odm.Optional(odm.Text(), description="The body of the request")
    request_method = odm.Enum([
        # Standard HTTP methods
        "GET", "POST", "PUT", "DELETE", "HEAD", "CONNECT", "OPTIONS", "TRACE", "PATCH",
        # WebDAV HTTP methods
        "BCOPY", "BDELETE", "BMOVE", "BPROPFIND", "BPROPPATCH", "COPY", "DELETE", "LOCK", "MKCOL", "MOVE",
        "NOTIFY", "POLL", "PROPFIND", "PROPPATCH", "SEARCH", "SUBSCRIBE", "UNLOCK", "UNSUBSCRIBE", "X-MS-ENUMATTS"
    ], description="The method of the request")
    response_headers = odm.Mapping(odm.Json(), description="Headers included in the response")
    response_status_code = odm.Optional(odm.Integer(), description="The status code of the response")
    response_body = odm.Optional(odm.Text(), description="The body of the response")
