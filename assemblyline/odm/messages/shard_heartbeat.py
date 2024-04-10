from assemblyline import odm

MSG_TYPES = {"ShardHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.shard_heartbeat.ShardMessage"


@odm.model(description="Heartbeat Model for Elasticsearch shards")
class Heartbeat(odm.Model):
    instances = odm.Integer(description="Number of Elasticsearch instances with assigned shards")
    request_time = odm.Float(description="Time to load shard metrics")
    shard_sizes = odm.Mapping(odm.integer(), description="Maximum shard size for each index")


@odm.model(description="Model of Elasticsearch shard Heartbeat Message")
class ShardMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Heartbeat message for elasticsearch shards")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="ShardHeartbeat", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
