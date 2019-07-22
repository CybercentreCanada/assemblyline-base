from typing import List, Dict
from assemblyline import odm
from assemblyline.odm.models.submission import SubmissionParams, File

MSG_TYPES = {"SubmissionIngested", "SubmissionReceived", "SubmissionQueued", "SubmissionStarted"}
LOADER_CLASS = "assemblyline.odm.messages.submission.SubmissionMessage"


@odm.model(index=True, store=True)
class Notification(odm.Model):
    queue = odm.Optional(odm.Keyword())      # Queue to publish the completion message
    threshold = odm.Optional(odm.Integer())  # Notify only if this score threshold is met


@odm.model()
class Submission(odm.Model):
    sid = odm.UUID()                                                     # Submission ID to use
    time = odm.Date(default="NOW")
    files: List[File] = odm.List(odm.Compound(File), default=[])         # File block
    metadata: Dict[str, str] = odm.Mapping(odm.Keyword(), default={})    # Metadata submitted with the file
    notification: Notification = odm.Compound(Notification, default={})  # Notification queue parameters
    params: SubmissionParams = odm.Compound(SubmissionParams)            # Parameters of the submission


@odm.model()
class SubmissionMessage(odm.Model):
    msg = odm.Compound(Submission)                                       # Body of the message
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)   # Class to use to load the message as an object
    msg_type = odm.Enum(values=MSG_TYPES, default="SubmissionReceived")  # Type of message
    sender = odm.Keyword()                                               # Sender of the message
