from assemblyline import odm
from assemblyline.odm.models.workflow import PRIORITIES, STATUSES
from typing import List

EXTENDED_SCAN_VALUES = {"submitted", "skipped", "incomplete", "completed"}


@odm.model(index=True, store=False, description="Assemblyline Results Block")
class DetailedItem(odm.Model):
    type = odm.Keyword(description="Type of data that generated this item")
    value = odm.Keyword(description="Value of the item")
    verdict = odm.Enum(['safe', 'info', 'suspicious', 'malicious'], description="Verdict of the item")
    subtype = odm.Optional(odm.Enum(['EXP', 'CFG', 'OB', 'IMP', 'CFG', 'TA'], description="Sub-type of the item"))


@odm.model(index=True, store=False, description="Assemblyline Screenshot Block")
class Screenshot(odm.Model):
    name = odm.Keyword(description="Name of the screenshot")
    description = odm.Keyword(description="Description of the screenshot")
    img = odm.SHA256(description="SHA256 hash of the image")
    thumb = odm.SHA256(description="SHA256 hash of the thumbnail")


@odm.model(index=True, store=False, description="Assemblyline Detailed result block")
class DetailedResults(odm.Model):
    attack_pattern = odm.List(odm.Compound(DetailedItem), default=[], description="List of detailed Att&ck patterns")
    attack_category = odm.List(odm.Compound(DetailedItem), default=[], description="List of detailed Att&ck categories")
    attrib = odm.List(odm.Compound(DetailedItem), default=[], description="List of detailed attribution")
    av = odm.List(odm.Compound(DetailedItem), default=[], description="List of detailed AV hits")
    behavior = odm.List(odm.Compound(DetailedItem), default=[], description="List of detailed behaviors for the alert")
    domain = odm.List(odm.Compound(DetailedItem), default=[], description="List of detailed domains")
    heuristic = odm.List(odm.Compound(DetailedItem), default=[], description="List of detailed heuristics")
    ip = odm.List(odm.Compound(DetailedItem), default=[], description="List of detailed IPs")
    uri = odm.List(odm.Compound(DetailedItem), default=[], description="List of detailed URIs")
    yara = odm.List(odm.Compound(DetailedItem), default=[], description="List of detailed YARA rule hits")


@odm.model(index=True, store=False, description="Assemblyline Results Block")
class ALResults(odm.Model):
    attrib = odm.List(odm.Keyword(), default=[], store=True, copyto="__text__", description="List of attribution")
    av = odm.List(odm.Keyword(), default=[], store=True, copyto="__text__", description="List of AV hits")
    behavior = odm.List(odm.Keyword(), default=[], copyto="__text__", description="List of behaviors for the alert")
    detailed = odm.Compound(DetailedResults, description="Assemblyline Detailed result block")
    domain = odm.List(odm.Domain(), default=[], copyto="__text__", description="List of all domains")
    domain_dynamic = odm.List(odm.Domain(), default=[], description="List of domains found during Dynamic Analysis")
    domain_static = odm.List(odm.Domain(), default=[], description="List of domains found during Static Analysis")
    ip = odm.List(odm.IP(), default=[], copyto="__text__", description="List of all IPs")
    ip_dynamic = odm.List(odm.IP(), default=[], description="List of IPs found during Dynamic Analysis")
    ip_static = odm.List(odm.IP(), default=[], description="List of IPs found during Static Analysis")
    request_end_time = odm.Date(index=False, description="Finish time of the Assemblyline submission")
    score = odm.Integer(store=True, description="Maximum score found in the submission")
    uri = odm.List(odm.URI(), default=[], copyto="__text__", description="List of all URIs")
    uri_dynamic = odm.List(odm.URI(), default=[], description="List of URIs found during Dynamic Analysis")
    uri_static = odm.List(odm.URI(), default=[], description="List of URIs found during Static Analysis")
    yara = odm.List(odm.Keyword(), default=[], copyto="__text__", description="List of YARA rule hits")


@odm.model(index=True, store=True, description="File Block Associated to the Top-Level/Root File of Submission")
class File(odm.Model):
    md5 = odm.MD5(copyto="__text__", description="MD5 hash of file")
    name = odm.Keyword(copyto="__text__", description="Name of the file")
    sha1 = odm.SHA1(copyto="__text__", description="SHA1 hash of the file")
    sha256 = odm.SHA256(copyto="__text__", description="SHA256 hash of the file")
    size = odm.Integer(store=False, description="Size of the file in bytes")
    type = odm.Keyword(copyto="__text__", description="Type of file as identified by Assemblyline")
    screenshots = odm.List(odm.Compound(Screenshot), default=[], description="Screenshots of the file")


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


@odm.model(index=True, store=False, description="Model of Workflow Event")
class Event(odm.Model):
    entity_type: str = odm.Enum(values=['user', 'workflow'], description="Type of entity associated to event")
    entity_id: str = odm.Keyword(description="ID of entity associated to event")
    entity_name: str = odm.Keyword(description="Name of entity")
    ts: str = odm.Date(default="NOW", description="Timestamp of event")
    labels: List[str] = odm.Optional(odm.List(odm.Keyword()), description="Labels added during event")
    status: str = odm.Optional(odm.Enum(values=STATUSES), description="Status applied during event")
    priority: str = odm.Optional(odm.Enum(values=PRIORITIES), description="Priority applied during event")


@odm.model(index=True, store=True, description="Model for Alerts")
class Alert(odm.Model):
    alert_id = odm.Keyword(copyto="__text__", description="ID of the alert")
    al = odm.Compound(ALResults, description="Assemblyline Result Block")
    archive_ts = odm.Optional(odm.Date(store=False, description="Archiving timestamp (Deprecated)"))
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
    events = odm.List(odm.Compound(Event), default=[], description="An audit of events applied to alert")
    workflows_completed = odm.Boolean(default=False, description="Have all workflows ran on this alert?")
