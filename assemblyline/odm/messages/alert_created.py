from assemblyline import odm
from assemblyline.odm.models.alert import Alert


@odm.model()
class AlertCreatedMessage(odm.Model):
    body = odm.Compound(Alert)
    msg_type = odm.Enum(values={"AlertCreated"}, default="AlertCreated")
    reply_to = odm.Keyword()
    sender = odm.Keyword()
    succeeded = odm.Boolean()
    to = odm.Keyword()

