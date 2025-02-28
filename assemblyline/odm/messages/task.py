from assemblyline import odm
from assemblyline.common import forge, constants
from assemblyline.odm.models.config import ServiceSafelist
from assemblyline.odm.models.file import URIInfo
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
    ssdeep = odm.Optional(odm.SSDeepHash(description="SSDEEP hash of the file"))
    tlsh = odm.Optional(odm.Keyword(description="TLSH hash of the file"))
    type = odm.Keyword(description="Type of file as identified by Assemblyline")
    uri_info = odm.Optional(odm.Compound(URIInfo), description="URI structure to speed up specialty file searching")


@odm.model(description="Tag Item")
class TagItem(odm.Model):
    type = odm.Keyword(description="Type of tag item")
    value = odm.Keyword(description="Value of tag item")
    short_type = odm.Keyword(description="Short version of tag type")
    score = odm.Optional(odm.Integer(), description="Score of tag item")


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

    ignore_recursion_prevention = odm.Boolean(
        default=False,
        description="Whether the service should ignore recursion prevention or not")

    # TODO: The following three lines can be removed after assemblyline upgrade to version 4.6+
    ignore_dynamic_recursion_prevention = odm.Boolean(
        default=False,
        description="Whether the service should ignore dynamic recursion prevention or not")

    ignore_filtering = odm.Boolean(default=False, description="Should the service filter it's output?")

    priority = odm.Integer(default=1, description="Priority for processing order",
                           min=constants.DROP_PRIORITY, max=constants.MAX_PRIORITY)
    safelist_config = odm.Compound(ServiceSafelist,
                                   description="Safelisting configuration (as defined in global configuration)",
                                   default={'enabled': False})

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
