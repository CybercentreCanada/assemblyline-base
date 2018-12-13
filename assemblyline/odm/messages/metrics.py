from assemblyline import odm

MSG_TYPES = {"PublishCounters"}
LOADER_CLASS = "assemblyline.odm.messages.metrics.MetricsMessage"


@odm.model()
class Metrics(odm.Model):
    host = odm.Keyword()
    type = odm.Keyword()
    name = odm.Keyword()
    metrics = odm.Mapping(odm.Integer())


@odm.model()
class MetricsMessage(odm.Model):
    body = odm.Compound(Metrics)
    obj_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="PublishCounters")
    sender = odm.Keyword()
