from assemblyline import odm

MSG_TYPES = {"RetrohuntHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.retrohunt_heartbeat.RetrohuntMessage"


@odm.model(description="Heartbeat Model for retrohunt")
class Heartbeat(odm.Model):
    instances = odm.Integer(description="Number of retrohunt workers")
    request_time = odm.Optional(odm.Float(description="Time to load metrics"))
    pending_files = odm.integer(description="Files not yet available for searching")
    ingested_last_minute = odm.integer(description="Files ingested in last minute")
    worker_storage_available = odm.integer(description="Free storage for most depleted worker")
    total_storage_available = odm.integer(description="Free storage across workers")
    active_searches = odm.integer(description="Number of currently running searches")
    last_minute_cpu = odm.Float(description="Last minute cpu load across all workers")
    total_memory_used = odm.Float(description="Estimated current memory use across all workers")


@odm.model(description="Model of retrohunt heartbeat message")
class RetrohuntMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Heartbeat message for retrohunt")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="RetrohuntHeartbeat", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
