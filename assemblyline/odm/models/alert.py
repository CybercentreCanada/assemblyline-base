from assemblyline import odm
from assemblyline.odm.models.workflow import PRIORITIES, STATUSES

EXTENDED_SCAN_VALUES = {"submitted", "skipped", "incomplete", "completed"}


@odm.model(index=True, store=False, description="Assemblyline Results Block")
class ALResults(odm.Model):                                      #
    attrib = odm.List(odm.Keyword(), default=[], store=True, copyto="__text__", description="List of attribution")
    av = odm.List(odm.Keyword(), default=[], store=True, copyto="__text__", description="List of AV hits")
    behavior = odm.List(odm.Keyword(), default=[], copyto="__text__", description="List of behaviors for the alert")
    domain = odm.List(odm.Domain(), default=[], copyto="__text__", description="List of all domains")
    domain_dynamic = odm.List(odm.Domain(), default=[], description="List of domains found during Dynamic Analysis")
    domain_static = odm.List(odm.Domain(), default=[], description="List of domains found during Static Analysis")
    ip = odm.List(odm.IP(), default=[], copyto="__text__", description="List of all IPs")
    ip_dynamic = odm.List(odm.IP(), default=[], description="List of IPs found during Dynamic Analysis")
    ip_static = odm.List(odm.IP(), default=[], description="List of IPs found during Static Analysis")
    request_end_time = odm.Date(index=False, description="Finish time of the Assemblyline submission")
    score = odm.Integer(store=True, description="Maximum score found in the submission")
    yara = odm.List(odm.Keyword(), default=[], copyto="__text__", description="List of YARA rule hits")


@odm.model(index=True, store=True, description="File Block Associated to the Top-Level/Root File of Submission")
class File(odm.Model):
    md5 = odm.MD5(copyto="__text__", description="MD5 hash of file")
    name = odm.Keyword(copyto="__text__", description="Name of the file")
    sha1 = odm.SHA1(copyto="__text__", description="SHA1 hash of the file")
    sha256 = odm.SHA256(copyto="__text__", description="SHA256 hash of the file")
    size = odm.Integer(store=False, description="Size of the file in bytes")
    type = odm.Keyword(copyto="__text__", description="Type of file as identified by Assemblyline")


@odm.model(index=True, store=False, description="Verdict Block of Submission")
class Verdict(odm.Model):
    malicious = odm.List(odm.Keyword(), default=[], description="List of users that claim submission as malicious")
    non_malicious = odm.List(odm.Keyword(), default=[],
                             description="List of users that claim submission as non-malicious")


@odm.model(index=True, store=False, description="Heuristic Block")
class Heuristic(odm.Model):
    name = odm.List(odm.Keyword(), default=[], description="List of related Heuristic names")


@odm.model(index=True, store=False, description="ATT&CK Block")
class Attack(odm.Model):
    pattern = odm.List(odm.Keyword(), default=[], description="List of related ATT&CK patterns")
    category = odm.List(odm.Keyword(), default=[], description="List of related ATT&CK categories")


@odm.model(index=True, store=True, description="Model for Alerts")
class Alert(odm.Model):

    alert_id = odm.Keyword(copyto="__text__", description="ID of the alert")
    al = odm.Compound(ALResults, description="Assemblyline Result Block")
    archive_ts = odm.Date(store=False, description="Archiving timestamp")
    attack = odm.Compound(Attack, description="ATT&CK Block")
    classification = odm.Classification(description="Classification of the alert")
    expiry_ts = odm.Optional(odm.Date(store=False), description="Expiry timestamp")
    extended_scan = odm.Enum(values=EXTENDED_SCAN_VALUES, description="Status of the extended scan")
    file = odm.Compound(File, description="File Block")
    filtered = odm.Boolean(default=False, description="Are the alert results filtered?")
    heuristic = odm.Compound(Heuristic, description="Heuristic Block")
    label = odm.List(odm.Keyword(), copyto="__text__", default=[], description="List of labels applied to the alert")
    metadata = odm.FlattenedObject(default={}, store=False, description="Metadata submitted with the file")
    owner = odm.Optional(odm.Keyword(), description="Owner of the alert")
    priority = odm.Optional(odm.Enum(values=PRIORITIES), description="Priority applied to the alert")
    reporting_ts = odm.Date(description="Alert creation timestamp")
    sid = odm.UUID(description="Submission ID related to this alert")
    status = odm.Optional(odm.Enum(values=STATUSES), description="Status applied to the alert")
    ts = odm.Date(description="File submission timestamp")
    type = odm.Keyword(description="Type of alert")
    verdict = odm.Compound(Verdict, default={}, description="Verdict Block")
    workflows_completed = odm.Boolean(default=False, description="Have all workflows ran on this alert?")
