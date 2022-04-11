from assemblyline import odm

MSG_TYPES = {"ArchiveHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.archive_heartbeat.ArchiveMessage"


@odm.model(description="Archive Metrics")
class Metrics(odm.Model):
    alert = odm.Integer(description="Number of alerts archived")
    cached_file = odm.Integer(description="Number of cached files archived")
    emptyresult = odm.Integer(description="Number of empty results archived")
    error = odm.Integer(description="Number of errors archived")
    file = odm.Integer(description="Number of files archived")
    filescore = odm.Integer(description="Number of filescores archived")
    result = odm.Integer(description="Number of results archived")
    submission = odm.Integer(description="Number of submissions archived")
    submission_tree = odm.Integer(description="Number of submission trees archived")
    submission_summary = odm.Integer(description="Number of submission summaries archived")


@odm.model(description="Archive Heartbeat Model")
class Heartbeat(odm.Model):
    instances = odm.Integer(description="Number of instances")
    metrics = odm.Compound(Metrics, description="Archive metrics")


@odm.model(description="Model for Archive Heartbeat Messages")
class ArchiveMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Heartbeat message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="ArchiveHeartbeat", description="Message type")
    sender = odm.Keyword(description="Sender of message")
