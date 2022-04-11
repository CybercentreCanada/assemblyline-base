from assemblyline import odm

MSG_TYPES = {"MetricsCounter"}
LOADER_CLASS = "assemblyline.odm.messages.metrics.MetricsMessage"


@odm.model(description="Metrics Model")
class Metrics(odm.Model):
    host = odm.Keyword(description="Host that generated metric")
    type = odm.Keyword(description="Type of metric")
    name = odm.Keyword(description="Metric name")
    metrics = odm.Mapping(odm.Integer(), description="Metric value")


@odm.model(description="Model of Metric Message")
class MetricsMessage(odm.Model):
    msg = odm.Compound(Metrics, description="Metrics message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="MetricsCounter", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
