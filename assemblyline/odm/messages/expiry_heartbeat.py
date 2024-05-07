from assemblyline import odm

MSG_TYPES = {"ExpiryHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.expiry_heartbeat.ExpiryMessage"


@odm.model(description="Expiry Stats")
class Metrics(odm.Model):
    alert = odm.Integer(description="Number of alerts")
    badlist = odm.Integer(description="Number of badlisted items")
    cached_file = odm.Integer(description="Number of cached files")
    emptyresult = odm.Integer(description="Number of empty results")
    error = odm.Integer(description="Number of errors")
    file = odm.Integer(description="Number of files")
    filescore = odm.Integer(description="Number of filscores")
    result = odm.Integer(description="Number of results")
    safelist = odm.Integer(description="Number of safelisted items")
    submission = odm.Integer(description="Number of submissions")
    submission_tree = odm.Integer(description="Number of submission trees")
    submission_summary = odm.Integer(description="Number of submission summaries")


@odm.model(description="Heartbeat Model")
class Heartbeat(odm.Model):
    instances = odm.Integer(description="Number of instances")
    metrics = odm.Compound(Metrics, description="Expiry metrics")
    queues = odm.Compound(Metrics, description="Expiry queues")


@odm.model(description="Model of Expiry Heartbeat Message")
class ExpiryMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Hearbeat message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="ExpiryHeartbeat", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
