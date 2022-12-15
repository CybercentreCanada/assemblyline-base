from assemblyline import odm

MSG_TYPES = {"ArchiveHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.archive_heartbeat.ArchiveMessage"


@odm.model(description="Archive Metrics")
class Metrics(odm.Model):
    # Indices metrics
    file = odm.Integer(description="Number of files archived")
    result = odm.Integer(description="Number of results archived")
    submission = odm.Integer(description="Number of submissions archived")
    # Messaging metrics
    received = odm.Integer(description="Number of received archive messages")
    exception = odm.Integer(description="Number of exceptions during archiving")
    invalid = odm.Integer(description="Number of invalid archive type errors during archiving")
    not_found = odm.Integer(description="Number of submission not found failures during archiving")


@odm.model(description="Archive Heartbeat Model")
class Heartbeat(odm.Model):
    instances = odm.Integer(description="Number of instances")
    metrics = odm.Compound(Metrics, description="Archive metrics")
    queued = odm.Integer(description="Number of documents to be archived")


@odm.model(description="Model for Archive Heartbeat Messages")
class ArchiveMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Heartbeat message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="ArchiveHeartbeat", description="Message type")
    sender = odm.Keyword(description="Sender of message")
