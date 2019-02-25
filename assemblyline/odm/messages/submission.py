from assemblyline import odm
from assemblyline.odm.models.submission import SubmissionParams, File

MSG_TYPES = {"SubmissionReceived", "SubmissionQueued", "SubmissionStarted"}
LOADER_CLASS = "assemblyline.odm.messages.submission.SubmissionMessage"


@odm.model(index=True, store=True)
class Notification(odm.Model):
    queue = odm.Keyword(default_set=True)      # Queue to publish the completion message
    threshold = odm.Integer(default_set=True)  # Notify only if this score threshold is met


@odm.model()
class Submission(odm.Model):
    sid = odm.UUID(default_set=True)                             # Submission ID to use
    files = odm.List(odm.Compound(File), default=[])             # File block
    metadata = odm.Mapping(odm.Keyword(), default={})            # Metadata submitted with the file
    notification = odm.Compound(Notification, default={})        # Notification queue parameters
    params = odm.Compound(SubmissionParams)                      # Parameters of the submission


@odm.model()
class SubmissionMessage(odm.Model):
    msg = odm.Compound(Submission)                                       # Body of the message
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)   # Class to use to load the message as an object
    msg_type = odm.Enum(values=MSG_TYPES, default="SubmissionReceived")  # Type of message
    sender = odm.Keyword()                                               # Sender of the message
