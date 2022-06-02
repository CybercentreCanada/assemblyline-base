from assemblyline import odm

MSG_TYPES = {"VacuumHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.vacuum_heartbeat.VacuumMessage"


@odm.model(description="Vacuum Stats")
class Metrics(odm.Model):
    ingested = odm.Integer(description="Files ingested")
    # protocol = odm.Mapping(odm.Integer())
    safelist = odm.Integer(description="Files safelisted")
    errors = odm.Integer()
    skipped = odm.Integer()


@odm.model(description="Heartbeat Model")
class Heartbeat(odm.Model):
    # instances = odm.Integer(description="Number of instances")
    metrics = odm.Compound(Metrics, description="Vacuum metrics")
    # queues = odm.Compound(Metrics, description="Vacuum queues")


@odm.model(description="Model of Vacuum Heartbeat Message")
class VacuumMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Hearbeat message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="VacuumHeartbeat", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
