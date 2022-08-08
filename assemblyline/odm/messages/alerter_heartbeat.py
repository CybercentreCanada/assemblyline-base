from assemblyline import odm

MSG_TYPES = {"AlerterHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.alerter_heartbeat.AlerterMessage"


@odm.model(description="Alerter Queues")
class Queues(odm.Model):
    alert = odm.Integer(description="Number of alerts in queue")


@odm.model(description="Alerter Metrics")
class Metrics(odm.Model):
    created = odm.Integer(description="Number of alerts created")
    error = odm.Integer(description="Number of alerts with errors")
    received = odm.Integer(description="Number of alerts received")
    updated = odm.Integer(description="Number of alerts updated")
    wait = odm.Integer(description="Number of alerts waiting for submission to complete")


@odm.model(description="Heartbeat Model for Alerter")
class Heartbeat(odm.Model):
    instances = odm.Integer(description="Number of Alerter instances")
    metrics = odm.Compound(Metrics, description="Alert metrics")
    queues = odm.Compound(Queues, description="Alert queues")


@odm.model(description="Model of Alerter Heartbeat Message")
class AlerterMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Heartbeat message from Alerter")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="AlerterHeartbeat", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
