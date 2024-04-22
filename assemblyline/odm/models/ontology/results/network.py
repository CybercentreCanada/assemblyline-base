from assemblyline import odm
from assemblyline.odm.models.ontology.results.antivirus import TAG_PARTS
from assemblyline.odm.models.ontology.results.process import Process, ObjectID
from assemblyline.common.dict_utils import get_dict_fingerprint_hash

OID_PARTS = ['source_ip', 'source_port',
             'destination_ip', 'destination_port',
             'transport_layer_protocol', 'connection_type']


REQUEST_METHODS = [
    # Standard HTTP methods
    "GET", "POST", "PUT", "DELETE", "HEAD", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    # WebDAV HTTP methods
    "BCOPY", "BDELETE", "BMOVE", "BPROPFIND", "BPROPPATCH", "COPY", "DELETE", "LOCK", "MKCOL", "MOVE",
    "NOTIFY", "POLL", "PROPFIND", "PROPPATCH", "SEARCH", "SUBSCRIBE", "UNLOCK", "UNSUBSCRIBE", "X-MS-ENUMATTS"
]

# https://en.wikipedia.org/wiki/List_of_DNS_record_types
LOOKUP_TYPES = ["A", "AAAA", "AFSDB", "APL", "CAA", "CDNSKEY", "CDS", "CERT", "CNAME", "CSYNC", "DHCID", "DLV",
                "DNAME", "DNSKEY", "DS", "EUI48", "EUI64", "HINFO", "HIP", "HTTPS", "IPSECKEY", "KEY", "KX", "LOC",
                "MX", "NAPTR", "NS", "NSEC", "NSEC3", "NSEC3PARAM", "OPENPGPKEY", "PTR", "RRSIG", "RP", "SIG",
                "SMIMEA", "SOA", "SRV", "SSHFP", "SVCB", "TA", "TKEY", "TLSA", "TSIG", "TXT", "URI", "ZONEMD"]

@odm.model(description="Details for a DNS request")
class NetworkDNS(odm.Model):
    domain = odm.Domain(description="The domain requested")
    resolved_ips = odm.List(odm.IP(), description="A list of IPs that were resolved")
    lookup_type = odm.Enum(values=LOOKUP_TYPES, description="The type of DNS request")


@odm.model(description="Details for an HTTP request")
class NetworkHTTP(odm.Model):
    request_uri = odm.URI(description="The URI requested")
    request_headers = odm.Mapping(odm.Json(), description="Headers included in the request")
    request_method = odm.Enum(values=REQUEST_METHODS, description="The method of the request")
    response_headers = odm.Mapping(odm.Json(), description="Headers included in the response")
    request_body = odm.Optional(odm.Text(), description="The body of the request")
    response_status_code = odm.Optional(odm.Integer(), description="The status code of the response")
    response_body = odm.Optional(odm.Text(), description="The body of the response")


@odm.model(description="Details for a low-level network connection by IP")
class NetworkConnection(odm.Model):
    objectid = odm.Compound(ObjectID, description="The object ID of the network object")
    destination_ip = odm.IP(description="The destination IP of the connection")
    destination_port = odm.Integer(description="The destination port of the connection")
    transport_layer_protocol = odm.Enum(values=["tcp", "udp"],
                                        description="The transport layer protocol of the connection")
    direction = odm.Enum(values=["outbound", "inbound", "unknown"],
                         description="The direction of the network connection")
    process = odm.Optional(odm.Compound(Process), description="The process that spawned the network connection")
    source_ip = odm.Optional(odm.IP(), description="The source IP of the connection")
    source_port = odm.Optional(odm.Integer(), description="The source port of the connection")
    http_details = odm.Optional(odm.Compound(NetworkHTTP), description="HTTP-specific details of request")
    dns_details = odm.Optional(odm.Compound(NetworkDNS), description="DNS-specific details of request")
    connection_type = odm.Optional(odm.Enum(values=['http', 'dns', 'tls'], description="Type of connection being made"))

    def get_oid(data: dict):
        connection_type = data.get('connection_type'):
        hash_dict = {key: data.get(key) for key in OID_PARTS}
        oid_prefix = "network"
        if connection_type == "http":
            # Include the requested URI as part of the hash
            oid_prefix = "network_http"
            hash_dict['http_details'] = {'request_uri': data.get('http_details', {}).get('request_uri', None)}
        elif connection_type == "dns":
            # Include the requested domain as part of the hash
            oid_prefix = "network_dns"
            hash_dict['dns_details'] = {'domain': data.get('dns_details', {}).get('domain', None)}

        return f"{oid_prefix}_{get_dict_fingerprint_hash(hash_dict)}"

    def get_tag(data: dict):
        return f"{data.get('destination_ip')}:{data.get('destination_port')}"
