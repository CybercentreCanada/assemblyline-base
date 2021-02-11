from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()

MSG_TYPES = {"Task"}
LOADER_CLASS = "assemblyline.odm.messages.task.TaskMessage"


@odm.model()
class FileInfo(odm.Model):
    magic = odm.Keyword()  # The output from libmagic which was used to determine the tag
    md5 = odm.MD5()        # MD5 of the file
    mime = odm.Optional(odm.Keyword())  # The libmagic mime type
    sha1 = odm.SHA1()      # SHA1 hash of the file
    sha256 = odm.SHA256()  # SHA256 hash of the file
    size = odm.Integer()   # Size of the file
    type = odm.Keyword()   # The file type


@odm.model()
class TagItem(odm.Model):
    type = odm.Keyword()
    value = odm.Keyword()
    short_type = odm.Keyword()


@odm.model()
class DataItem(odm.Model):
    name = odm.Keyword()
    value = odm.Any()


@odm.model()
class Task(odm.Model):
    sid = odm.UUID()
    metadata = odm.FlattenedObject()  # Metadata associated to the submission
    min_classification = odm.Classification()  # Minimum classification of the file being scanned
    fileinfo: FileInfo = odm.Compound(FileInfo)          # File info block
    filename = odm.Keyword()
    service_name = odm.Keyword()
    service_config = odm.Mapping(odm.Any(), default={})  # Service specific parameters
    depth = odm.Integer(default=0)
    max_files = odm.Integer()
    ttl = odm.Integer(default=0)

    tags = odm.List(odm.Compound(TagItem), default=[])
    temporary_submission_data = odm.List(odm.Compound(DataItem), default=[])

    deep_scan = odm.Boolean(default=False)

    # Whether the service cache should be ignored during the processing of this task
    ignore_cache = odm.Boolean(default=False)

    # Whether the service should ignore the dynamic recursion prevention or not
    ignore_dynamic_recursion_prevention = odm.Boolean(default=False)

    # Priority for processing order
    priority = odm.Integer(default=0)

    @staticmethod
    def make_key(sid, service_name, sha):
        return f"{sid}_{service_name}_{sha}"

    def key(self):
        return Task.make_key(self.sid, self.service_name, self.fileinfo.sha256)


@odm.model()
class TaskMessage(odm.Model):
    msg = odm.Compound(Task)                                            # Body of the message
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)  # Class to use to load the message as an object
    msg_type = odm.Enum(values=MSG_TYPES, default="Task")               # Type of message
    sender = odm.Keyword()                                              # Sender of the message
