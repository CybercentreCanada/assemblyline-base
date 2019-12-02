from assemblyline import odm

MSG_TYPES = {"ArchiveHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.archive_heartbeat.ArchiveMessage"


@odm.model()
class Metrics(odm.Model):
    alert = odm.Integer()
    cached_file = odm.Integer()
    emptyresult = odm.Integer()
    error = odm.Integer()
    file = odm.Integer()
    filescore = odm.Integer()
    result = odm.Integer()
    submission = odm.Integer()
    submission_tree = odm.Integer()
    submission_summary = odm.Integer()

@odm.model()
class Heartbeat(odm.Model):
    instances = odm.Integer()
    metrics = odm.Compound(Metrics)


@odm.model()
class ArchiveMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="ArchiveHeartbeat")
    sender = odm.Keyword()
