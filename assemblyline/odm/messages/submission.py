from assemblyline import odm
from assemblyline.odm.models.submission import SubmissionParams

MSG_TYPES = {"SubmissionQueued", "SubmissionStarted"}
LOADER_CLASS = "assemblyline.odm.messages.submission.SubmissionMessage"


@odm.model(index=True, store=True)
class File(odm.Model):
    md5 = odm.Keyword()     # MD5 of the top level file
    name = odm.Keyword()    # Name of the file
    sha1 = odm.Keyword()    # SHA1 hash of the file
    sha256 = odm.Keyword()  # SHA256 hash of the file
    size = odm.Integer()    # Size of the file


@odm.model(index=True, store=True)
class Notification(odm.Model):
    queue = odm.Keyword()               # Queue to publish the completion message
    threshold = odm.Integer(default=0)  # Notify only if this score threshold is met


@odm.model()
class Submission(odm.Model):
    cache_key = odm.Keyword()                              # Key used for filescore cache
    files = odm.List(odm.Compound(File))                   # File block
    metadata = odm.Mapping(odm.Keyword())                  # Metadata submitted with the file
    notification = odm.Compound(Notification, default={})  # Notification queue parameters
    params = odm.Compound(SubmissionParams)                # Parameters of the submission


@odm.model()
class SubmissionMessage(odm.Model):
    msg = odm.Compound(Submission)                                      # Body of the message
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)  # Class to use to load the message as an object
    msg_type = odm.Enum(values=MSG_TYPES, default="SubmissionQueued")   # Type of message
    sender = odm.Keyword()                                              # Sender of the message
