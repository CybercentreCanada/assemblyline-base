from typing import List, Dict, Optional as Opt
from assemblyline import odm
from assemblyline.odm.models.submission import SubmissionParams, File, Submission as DatabaseSubmission

MSG_TYPES = {"SubmissionIngested", "SubmissionReceived", "SubmissionStarted", "SubmissionCompleted"}
LOADER_CLASS = "assemblyline.odm.messages.submission.SubmissionMessage"


@odm.model(index=True, store=True, description="Notification Model")
class Notification(odm.Model):
    queue = odm.Optional(odm.Keyword(), description="Queue to publish the completion message")
    threshold = odm.Optional(odm.Integer(), description="Notify only if this score threshold is met")


@odm.model(description="Submission Model")
class Submission(odm.Model):
    sid = odm.UUID(description="Submission ID to use")
    time = odm.Date(default="NOW", description="Message time")
    files: List[File] = odm.List(odm.Compound(File), default=[], description="File block")
    metadata: Dict[str, str] = odm.FlattenedObject(default={}, description="Metadata submitted with the file")
    notification: Notification = odm.Compound(Notification, default={}, description="Notification queue parameters")
    params: SubmissionParams = odm.Compound(SubmissionParams, description="Parameters of the submission")
    scan_key: Opt[str] = odm.Optional(odm.Keyword())


def from_datastore_submission(submission: DatabaseSubmission):
    """
    A helper to convert between database model version of Submission
    and the message version of Submission.
    """
    return Submission({
        'sid': submission.sid,
        'files': submission.files,
        'metadata': submission.metadata,
        'params': submission.params,
        'scan_key': submission.scan_key
    })


@odm.model(description="Model of Submission Message")
class SubmissionMessage(odm.Model):
    msg = odm.Compound(Submission, description="Body of the message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS,
                          description="Class to use to load the message as an object")   #
    msg_type = odm.Enum(values=MSG_TYPES, description="Type of message")
    sender = odm.Keyword(description="Sender of the message")
