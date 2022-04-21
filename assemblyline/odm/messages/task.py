from assemblyline import odm
from assemblyline.common import forge
from assemblyline.odm.models.config import ServiceSafelist
Classification = forge.get_classification()

MSG_TYPES = {"Task"}
LOADER_CLASS = "assemblyline.odm.messages.task.TaskMessage"


@odm.model(description="File Information")
class FileInfo(odm.Model):
    magic = odm.Keyword(description="The output from libmagic which was used to determine the tag")
    md5 = odm.MD5(description="MD5 of the file")
    mime = odm.Optional(odm.Keyword(), description="The libmagic mime type")
    sha1 = odm.SHA1(description="SHA1 hash of the file")
    sha256 = odm.SHA256(description="SHA256 hash of the file")
    size = odm.Integer(description="Size of the file in bytes")
    type = odm.Keyword(description="Type of file as identified by Assemblyline")


@odm.model(description="Tag Item")
class TagItem(odm.Model):
    type = odm.Keyword()
    value = odm.Keyword()
    short_type = odm.Keyword()


@odm.model(description="Data Item")
class DataItem(odm.Model):
    name = odm.Keyword()
    value = odm.Any()


@odm.model(description="Service Task Model")
class Task(odm.Model):
    sid = odm.UUID(description="Submission ID")
    metadata = odm.FlattenedObject(description="Metadata associated to the submission")
    min_classification = odm.Classification(description="Minimum classification of the file being scanned")
    fileinfo: FileInfo = odm.Compound(FileInfo, description="File info block")
    filename = odm.Keyword(description="File name")
    service_name = odm.Keyword(description="Service name")
    service_config = odm.Mapping(odm.Any(), default={}, description="Service specific parameters")
    depth = odm.Integer(default=0, description="File depth relative to initital submitted file")
    max_files = odm.Integer(description="Maximum number of files that submission can have")
    ttl = odm.Integer(default=0, description="Task TTL")

    tags = odm.List(odm.Compound(TagItem), default=[], description="List of tags")
    temporary_submission_data = odm.List(odm.Compound(DataItem), default=[], description="Temporary submission data")

    deep_scan = odm.Boolean(default=False, description="Perform deep scanning")

    ignore_cache = odm.Boolean(
        default=False, description="Whether the service cache should be ignored during the processing of this task")

    ignore_dynamic_recursion_prevention = odm.Boolean(
        default=False,
        description="Whether the service should ignore the dynamic recursion prevention or not")

    ignore_filtering = odm.Boolean(default=False, description="Should the service filter it's output?")

    priority = odm.Integer(default=0, description="Priority for processing order")
    safelist_config = odm.Compound(ServiceSafelist,
                                   description="Safelisting configuration (as defined in global configuration)")

    @staticmethod
    def make_key(sid, service_name, sha):
        return f"{sid}_{service_name}_{sha}"

    def key(self):
        return Task.make_key(self.sid, self.service_name, self.fileinfo.sha256)


@odm.model(description="Model for Service Task Message")
class TaskMessage(odm.Model):
    msg = odm.Compound(Task, description="Body of the message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS,
                          description="Class to use to load the message as an object")
    msg_type = odm.Enum(values=MSG_TYPES, default="Task", description="Type of message")
    sender = odm.Keyword(description="Sender of the message")
