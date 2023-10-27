from __future__ import annotations
from assemblyline import odm
from assemblyline.odm.models.workflow import PRIORITIES, STATUSES
from typing import List

ES_SUBMITTED = "submitted"
EXTENDED_SCAN_VALUES = {ES_SUBMITTED, "skipped", "incomplete", "completed"}


@odm.model(index=True, store=False, description="Assemblyline Results Block")
class DetailedItem(odm.Model):
    type = odm.Keyword(description="Type of data that generated this item")
    value = odm.Keyword(description="Value of the item")
    verdict = odm.Enum(['safe', 'info', 'suspicious', 'malicious'], description="Verdict of the item")
    subtype = odm.Optional(odm.Enum(['EXP', 'CFG', 'OB', 'IMP', 'CFG', 'TA'], description="Sub-type of the item"))

    def __hash__(self) -> int:
        return hash(tuple(sorted(self.as_primitives().items())))

    def __lt__(self, other: DetailedItem) -> bool:
        if self.type != other.type:
            return self.type < other.type
        if self.value != other.value:
            return self.value < other.value
        if self.verdict != other.verdict:
            return self.verdict < other.verdict
        return self.subtype < other.subtype


@odm.model(index=True, store=False, description="Assemblyline Screenshot Block")
class Screenshot(odm.Model):
    name = odm.Keyword(description="Name of the screenshot")
    description = odm.Keyword(description="Description of the screenshot")
    img = odm.SHA256(description="SHA256 hash of the image")
    thumb = odm.SHA256(description="SHA256 hash of the thumbnail")

    def __hash__(self) -> int:
        return hash(tuple(sorted(self.as_primitives().items())))


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

    def update(self, other: DetailedResults) -> None:
        for field in self.fields().keys():
            setattr(self, field, list(set(getattr(self, field) + getattr(other, field))))


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

    def update(self, other: ALResults) -> None:
        # Handle the fields that require special treatment
        fields = list(self.fields().keys())
        fields.remove('detailed')
        self.detailed.update(other.detailed)
        fields.remove('request_end_time')
        self.request_end_time = max(self.request_end_time, other.request_end_time)
        fields.remove('score')
        self.score = max(self.score, other.score)

        # All of the rest can simply be merged
        for field in fields:
            setattr(self, field, list(set(getattr(self, field) + getattr(other, field))))


@odm.model(index=True, store=True, description="File Block Associated to the Top-Level/Root File of Submission")
class File(odm.Model):
    md5 = odm.MD5(copyto="__text__", description="MD5 hash of file")
    name = odm.Keyword(copyto="__text__", description="Name of the file")
    sha1 = odm.SHA1(copyto="__text__", description="SHA1 hash of the file")
    sha256 = odm.SHA256(copyto="__text__", description="SHA256 hash of the file")
    size = odm.Integer(store=False, description="Size of the file in bytes")
    type = odm.Keyword(copyto="__text__", description="Type of file as identified by Assemblyline")
    screenshots = odm.List(odm.Compound(Screenshot), default=[], description="Screenshots of the file")

    def update(self, other: File) -> None:
        if self.sha256 != other.sha256:
            raise ValueError(f"Only alerts on the same file may be merged {self.sha256} != {other.sha256}")
        self.screenshots = list(set(self.screenshots + other.screenshots))


@odm.model(index=True, store=False, description="Verdict Block of Submission")
class Verdict(odm.Model):
    malicious = odm.List(odm.Keyword(), default=[], description="List of users that claim submission as malicious")
    non_malicious = odm.List(odm.Keyword(), default=[],
                             description="List of users that claim submission as non-malicious")

    def update(self, other: Verdict) -> None:
        self.malicious = list(set(self.malicious + other.malicious))
        self.non_malicious = list(set(self.non_malicious + other.non_malicious))


@odm.model(index=True, store=False, description="Heuristic Block")
class Heuristic(odm.Model):
    name = odm.List(odm.Keyword(), default=[], description="List of related Heuristic names")

    def update(self, other: Heuristic) -> None:
        self.name = list(set(self.name + other.name))


@odm.model(index=True, store=False, description="ATT&CK Block")
class Attack(odm.Model):
    pattern = odm.List(odm.Keyword(), default=[], description="List of related ATT&CK patterns")
    category = odm.List(odm.Keyword(), default=[], description="List of related ATT&CK categories")

    def update(self, other: Attack) -> None:
        self.pattern = list(set(self.pattern + other.pattern))
        self.category = list(set(self.category + other.category))


@odm.model(index=True, store=False, description="Model of Workflow Event")
class Event(odm.Model):
    entity_type: str = odm.Enum(values=['user', 'workflow'], description="Type of entity associated to event")
    entity_id: str = odm.Keyword(description="ID of entity associated to event")
    entity_name: str = odm.Keyword(description="Name of entity")
    ts: str = odm.Date(default="NOW", description="Timestamp of event")
    labels: List[str] = odm.Optional(odm.List(odm.Keyword()), description="Labels added during event")
    status: str = odm.Optional(odm.Enum(values=STATUSES), description="Status applied during event")
    priority: str = odm.Optional(odm.Enum(values=PRIORITIES), description="Priority applied during event")

    def __hash__(self) -> int:
        return hash(tuple(sorted(self.as_primitives().items())))


@odm.model(index=True, store=True, description="Model for Alerts")
class Alert(odm.Model):
    alert_id = odm.Keyword(copyto="__text__", description="ID of the alert")
    al = odm.compound(ALResults, description="Assemblyline Result Block")
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

    def update(self, other: Alert) -> None:
        """Update the current object given the content of a second alert."""

        # Make sure we are merging compatible alerts
        if self.alert_id != other.alert_id:
            raise ValueError(f"Only versions of the same alert may be merged id {self.alert_id} != {other.alert_id}")
        if self.ts != other.ts:
            raise ValueError("Time drift in alerting detected. Possible alert ID collision.")

        # Merge simple compounds using their own logic
        self.al.update(other.al)
        self.attack.update(other.attack)
        self.file.update(other.file)
        self.heuristic.update(other.heuristic)
        self.verdict.update(other.verdict)

        # Merge by reasonable simple operations on some fields
        self.classification = self.classification.max(other.classification)

        # If both are set to expire go with the furthest expiry,
        # otherwise if either is permanent make the product permanent
        if self.expiry_ts and other.expiry_ts:
            self.expiry_ts = max(self.expiry_ts, other.expiry_ts)
        else:
            self.expiry_ts = None

        # Prefer anything that isn't submitted
        if self.extended_scan == ES_SUBMITTED:
            self.extended_scan = other.extended_scan

        # If either is filtered, the content should be considered filtered
        self.filtered |= other.filtered
        # Keep all unique labels and metadata, where metadata doesn't match take one more or less at random
        self.label = list(set(self.label + other.label))
        self.metadata.update(other.metadata)

        # Prefer the current owner/priority/status, but take the other if the current isn't defined
        self.owner = self.owner or other.owner
        self.priority = self.priority or other.priority
        self.reporting_ts = max(self.reporting_ts, other.reporting_ts)
        self.status = self.status or other.status

        # self.type is fine

        # Merge the events then sort them by time
        self.events = list(sorted(set(self.events + other.events), key=lambda e: e.ts))

        # Always consider the updated alert a new one WRT workflows
        self.workflows_completed = False
