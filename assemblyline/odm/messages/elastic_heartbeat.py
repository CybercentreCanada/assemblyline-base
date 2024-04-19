from assemblyline import odm

MSG_TYPES = {"ElasticHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.elastic_heartbeat.ElasticMessage"


@odm.model(description="Information about an elasticsearch shard")
class IndexData(odm.Model):
    name = odm.keyword()
    shard_size = odm.integer()


@odm.model(description="Heartbeat Model for Elasticsearch")
class Heartbeat(odm.Model):
    instances = odm.Integer(description="Number of Elasticsearch instances with assigned shards")
    unassigned_shards = odm.Integer(description="Number of unassigned shards in the cluster")
    request_time = odm.Float(description="Time to load shard metrics")
    shard_sizes = odm.sequence(odm.compound(IndexData), description="Information about each index")


@odm.model(description="Model of Elasticsearch Heartbeat Message")
class ElasticMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Heartbeat message for elasticsearch")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="ElasticHeartbeat", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
