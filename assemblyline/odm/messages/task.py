from assemblyline import odm

MSG_TYPES = {"Task"}
LOADER_CLASS = "assemblyline.odm.messages.task.TaskMessage"


@odm.model()
class FileInfo(odm.Model):
    magic = odm.Keyword()   # The output from libmagic which was used to determine the tag
    md5 = odm.Keyword()     # MD5 of the file
    mime = odm.Keyword()    # The libmagic mime type
    sha1 = odm.Keyword()    # SHA1 hash of the file
    sha256 = odm.Keyword()  # SHA256 hash of the file
    size = odm.Integer()    # Size of the file
    type = odm.Keyword()    # The file type


@odm.model()
class Task(odm.Model):
    sid = odm.Keyword()
    fileinfo: FileInfo = odm.Compound(FileInfo)   # File info block
    service_name = odm.Keyword()
    service_config = odm.Keyword()      # Service specific parameters
    config_key = odm.Keyword()
    depth = odm.Integer(default=0)


@odm.model()
class TaskMessage(odm.Model):
    msg = odm.Compound(Task)                                            # Body of the message
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)  # Class to use to load the message as an object
    msg_type = odm.Enum(values=MSG_TYPES, default="Task")               # Type of message
    sender = odm.Keyword()                                              # Sender of the message
