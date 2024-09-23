from __future__ import annotations

from typing import List, Optional

from assemblyline import odm
from assemblyline.odm.models.workflow import PRIORITIES, STATUSES

ES_SUBMITTED = "submitted"
ES_SKIPPED = "skipped"
ES_INCOMPLETE = "incomplete"
ES_COMPLETED = "completed"
EXTENDED_SCAN_VALUES = {ES_SUBMITTED, ES_SKIPPED, ES_INCOMPLETE, ES_COMPLETED}
EXTENDED_SCAN_PRIORITY = [ES_COMPLETED, ES_INCOMPLETE, ES_SKIPPED, ES_SUBMITTED]


def merge_extended_scan(a: str, b: str) -> str:
    # Select the prefered value
    for value in EXTENDED_SCAN_PRIORITY:
        if a == value or b == value:
            return value
    raise ValueError(f"Invalid program state. scan state {a} {b}")


@odm.model(index=True, store=False, description="""Represents a granular element within the detailed analysis results, providing specific insights into the analysis findings.
""")
class DetailedItem(odm.Model):
    type = odm.Keyword(description="Defines the specific attribute or aspect of the analysis that this detailed item pertains to.")
    value = odm.Keyword(description="The specific value or identifier for the detail item.")
    verdict = odm.Enum(['safe', 'info', 'suspicious', 'malicious'], description="Represents the security assessment or classification of the detailed item, indicating its potential threat level.")
    subtype = odm.Optional(odm.Enum(['EXP', 'CFG', 'OB', 'IMP', 'CFG', 'TA']), description="Adds further specificity to the detailed item, elaborating on its role or nature within the broader type category.  Supported subtypes include configuration blocks (CFG), exploits (EXP), implants (IMP), obfuscation methods (OB), and threat actors (TA).")

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


@odm.model(index=True, store=False, description="""Stores information about screenshots taken during the analysis of the file. Each screenshot has a name, description, and the hashes of the image and its thumbnail, offering a visual reference that can aid in manual review processes.
""")
class Screenshot(odm.Model):
    name = odm.Keyword(description="The name or title of the screenshot.")
    description = odm.Keyword(description="A brief description of the screenshot's content.")
    img = odm.SHA256(description="The SHA256 hash of the full-size screenshot image.")
    thumb = odm.SHA256(description="The SHA256 hash of the thumbnail version of the screenshot.")

    def __hash__(self) -> int:
        return hash(tuple(sorted(self.as_primitives().items())))


@odm.model(index=True, store=False, description="""Provides a comprehensive breakdown of specific attributes and their associated analysis results.
""")
class DetailedResults(odm.Model):
    attack_pattern = odm.List(odm.Compound(DetailedItem), default=[], description="Detailed information on MITRE ATT&CK® framework patterns identified in the analysis.")
    attack_category = odm.List(odm.Compound(DetailedItem), default=[], description="Detailed information on MITRE ATT&CK® framework categories associated with the alert.")
    attrib = odm.List(odm.Compound(DetailedItem), default=[], description="Detailed attribution information that provides context by suggesting associations with known malware families, suspected threat actors, or ongoing campaigns.")
    av = odm.List(odm.Compound(DetailedItem), default=[], description="Detailed information on antivirus signature matches.")
    behavior = odm.List(odm.Compound(DetailedItem), default=[], description="Detailed descriptions of the behaviors exhibited by the analyzed file or artifact that led to the alert.")
    domain = odm.List(odm.Compound(DetailedItem), default=[], description="Detailed domain information related to the alert.")
    heuristic = odm.List(odm.Compound(DetailedItem), default=[], description="Detailed heuristic information that triggered the alert.")
    ip = odm.List(odm.Compound(DetailedItem), default=[], description="Detailed IP address information related to the alert.")
    uri = odm.List(odm.Compound(DetailedItem), default=[], description="Detailed URI information related to the alert.")
    yara = odm.List(odm.Compound(DetailedItem), default=[], description="Detailed information on YARA rule matches that contributed to the alert.")

    def update(self, other: DetailedResults) -> None:
        for field in self.fields().keys():
            setattr(self, field, list(set(getattr(self, field) + getattr(other, field))))


@odm.model(index=True, store=False, description="""Contains the aggregated results of the analysis performed by Assemblyline. It includes information such as attribution, behaviors observed, domains and IPs related to the threat, and the overall score indicating the severity of the findings.
""")
class ALResults(odm.Model):
    attrib = odm.List(odm.Keyword(), default=[], store=True, copyto="__text__", description="A list of attribution tags that provide context by suggesting associations with known malware families, suspected threat actors, or ongoing campaigns.")
    av = odm.List(odm.Keyword(), default=[], store=True, copyto="__text__", description="List of antivirus signatures that matched the file associated with the alert.")
    behavior = odm.List(odm.Keyword(), default=[], copyto="__text__", description="Descriptions of behaviors exhibited by the analyzed file or artifact that led to the alert.")
    detailed = odm.Compound(DetailedResults, description="Provides a more detailed breakdown of the analysis results.")
    domain = odm.List(odm.Domain(), default=[], copyto="__text__", description="Aggregate list of domains related to the alert, derived from both static and dynamic analysis.")
    domain_dynamic = odm.List(odm.Domain(), default=[], description="List of domains observed during dynamic analysis of the artifact.")
    domain_static = odm.List(odm.Domain(), default=[], description="List of domains extracted from static analysis of the artifact.")
    ip = odm.List(odm.IP(), default=[], copyto="__text__", description="Aggregate list of IP addresses related to the alert, derived from both static and dynamic analysis.")
    ip_dynamic = odm.List(odm.IP(), default=[], description="List of IP addresses observed during dynamic analysis of the artifact.")
    ip_static = odm.List(odm.IP(), default=[], description="List of IP addresses extracted from static analysis of the artifact.")
    request_end_time = odm.Date(index=False, description="The timestamp indicating when the processing of the submission completed.")
    score = odm.Integer(store=True, description="The highest score assigned to any part of the submission based on the analysis results.")
    uri = odm.List(odm.URI(), default=[], copyto="__text__", description="Aggregate list of URIs related to the alert, derived from both static and dynamic analysis.")
    uri_dynamic = odm.List(odm.URI(), default=[], description="List of URIs observed during dynamic analysis of the artifact.")
    uri_static = odm.List(odm.URI(), default=[], description="List of URIs extracted from static analysis of the artifact.")
    yara = odm.List(odm.Keyword(), default=[], copyto="__text__", description="List of YARA rule matches that contributed to the alert.")

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


@odm.model(index=True, store=True, description="""Captures comprehensive metadata and unique identifiers for the original file submitted for analysis, which is central to the generation of the alert.
""")
class File(odm.Model):
    md5 = odm.MD5(copyto="__text__", description="The MD5 hash of the file.")
    name = odm.Keyword(copyto="__text__", description="The original name of the file as submitted.")
    sha1 = odm.SHA1(copyto="__text__", description="The SHA1 hash of the file.")
    sha256 = odm.SHA256(copyto="__text__", description="The SHA256 hash of the file.")
    size = odm.Integer(store=False, description="The size of the file in bytes.")
    type = odm.Keyword(copyto="__text__", description="	The file type as identified by Assemblyline's analysis.")
    screenshots = odm.List(odm.Compound(Screenshot), default=[], description="Screenshots taken of the file during analysis, if applicable.")

    def update(self, other: File) -> None:
        if self.sha256 != other.sha256:
            raise ValueError(f"Only alerts on the same file may be merged {self.sha256} != {other.sha256}")
        self.screenshots = list(set(self.screenshots + other.screenshots))


@odm.model(index=True, store=False, description="""The Verdict submodel captures the conclusions drawn by users regarding the nature of a submission. It lists user identifiers for those who have deemed the submission as either malicious or non-malicious, representing a collective assessment of the threat.
""")
class Verdict(odm.Model):
    malicious = odm.List(odm.Keyword(), default=[], description="User identifiers of those who have marked the submission as malicious.")
    non_malicious = odm.List(odm.Keyword(), default=[],
                             description="User identifiers of those who have marked the submission as non-malicious.")

    def update(self, other: Verdict) -> None:
        self.malicious = list(set(self.malicious + other.malicious))
        self.non_malicious = list(set(self.non_malicious + other.non_malicious))


@odm.model(index=True, store=False, description="""Summarizes the heuristic rules triggered during the analysis. These rules are part of the detection logic used by Assemblyline to identify suspicious or malicious behavior in the analyzed file.
""")
class Heuristic(odm.Model):
    name = odm.List(odm.Keyword(), default=[], description="Names of the heuristics that have been matched in the analysis.")

    def update(self, other: Heuristic) -> None:
        self.name = list(set(self.name + other.name))


@odm.model(index=True, store=False, description="""The Attack submodel is a component of the Alert model that records information aligned with the MITRE ATT&CK framework. It lists the ATT&CK patterns and categories that have been identified in the analysis, helping to map the threat to known adversary tactics and techniques.
""")
class Attack(odm.Model):
    pattern = odm.List(odm.Keyword(), default=[], description="List of MITRE ATT&CK® framework patterns that are relevant to the alert.")
    category = odm.List(odm.Keyword(), default=[], description="List of MITRE ATT&CK® framework categories that are relevant to the alert.")

    def update(self, other: Attack) -> None:
        self.pattern = list(set(self.pattern + other.pattern))
        self.category = list(set(self.category + other.category))


@odm.model(index=True, store=False, description="Describes an event or action that has occurred during the lifecycle of the alert, capturing changes in status, priority, or labels.")
class Event(odm.Model):
    entity_type: str = odm.Enum(values=['user', 'workflow'], description="The type of entity associated with the event.")
    entity_id: str = odm.Keyword(description="The unique identifier of the entity associated with the event.")
    entity_name: str = odm.Keyword(description="The name of the entity associated with the event.")
    ts: str = odm.Date(default="NOW", description="The timestamp when the event occurred.")
    labels: List[str] = odm.sequence(odm.keyword(), default=[], description="Labels that were added to the alert during the event.")
    labels_removed: List[str] = odm.sequence(odm.keyword(), default=[], description="Labels that were removed from the alert during the event.")
    status: str = odm.Optional(odm.Enum(values=STATUSES), description="The status of the alert after the event took place.")
    priority: str = odm.Optional(odm.Enum(values=PRIORITIES), description="The priority level assigned to the alert during the event.")

    def __hash__(self) -> int:
        data = self.as_primitives()
        data['labels'] = tuple(sorted(self.labels))
        data['labels_removed'] = tuple(sorted(self.labels_removed))
        return hash(tuple(sorted(data.items())))


@odm.model(index=True, store=True, description="Describes the relationship between different submissions that are linked to the formation of the alert, highlighting parent-child connections.")
class Relationship(odm.Model):
    child: str = odm.UUID(description="The identifier of the child submission in the relationship.")
    parent: Optional[str] = odm.optional(odm.UUID(), description="The identifier of the parent submission, if applicable.")

    def __hash__(self) -> int:
        return hash(tuple(sorted(self.as_primitives().items())))


@odm.model(index=True, store=True, description="""The Alert object model, as defined in this documentation, specifies the structured representation of alert data within the Assemblyline application's Alert index. Each field delineated in the schema is an attribute of the Alert document, characterized by its data type, semantic definition, mandatory status, and default instantiation value.

Comprehension of this schema is pivotal for the construction of targeted Lucene search queries, which are instrumental in the interrogation and retrieval of alert-specific data from Assemblyline's analytical output. The schema's fields provide the analytical lexicon necessary to query and dissect alert data, facilitating the isolation of alerts based on defined parameters such as threat identifiers, heuristic evaluations, and temporal metadata.

This schema serves as a technical blueprint for cybersecurity professionals to navigate Assemblyline's alerting system, enabling refined query strategies and data extraction methodologies that align with operational cybersecurity imperatives and threat intelligence workflows.
""")
class Alert(odm.Model):
    alert_id = odm.Keyword(copyto="__text__", description="Unique identifier for the alert.")
    al = odm.compound(ALResults, description="Contains the results of the Assemblyline analysis for the alert.")
    archive_ts = odm.Optional(odm.Date(), description="Timestamp indicating when the alert was archived in the system.")
    attack = odm.Compound(Attack, description="Structured data representing MITRE ATT&CK information associated with the alert.")
    classification = odm.Classification(description="Security classification level of the alert.")
    expiry_ts = odm.Optional(odm.Date(store=False), description="Timestamp indicating when the alert is scheduled to expire from the system.")
    extended_scan = odm.Enum(values=EXTENDED_SCAN_VALUES, description="Indicates the status of an extended scan, if applicable. Extended scans are additional analyses performed after the initial analysis.")
    file = odm.Compound(File, description="Information about the file associated with the alert.")
    filtered = odm.Boolean(default=False, description="Indicates whether portions of the submission's analysis results have been omitted due to the user's classification level not meeting the required threshold for viewing certain data.")
    heuristic = odm.Compound(Heuristic, description="Data regarding the heuristics that triggered the alert.")
    label = odm.List(odm.Keyword(), copyto="__text__", default=[], description="Labels assigned to the alert for categorization and filtering.")
    metadata = odm.FlattenedObject(default={}, store=False, description="Additional metadata provided with the file at the time of submission.")
    owner = odm.Optional(odm.Keyword(), description="Specifies the user or system component that has taken ownership of the alert. If no user has claimed the alert, it remains under system ownership with no specific user associated, indicated by a value of `None`.")
    priority = odm.Optional(odm.Enum(values=PRIORITIES), description="Indicates the importance level assigned to the alert.")
    reporting_ts = odm.Date(description="Timestamp when the alert was created.")
    submission_relations = odm.sequence(odm.compound(Relationship), description="Describes the hierarchical relationships between submissions that contributed to this alert.")
    sid = odm.UUID(description="Identifier for the submission associated with this alert.")
    status = odm.Optional(odm.Enum(values=STATUSES), description="Reflects the current state of the alert throughout its lifecycle. This status is subject to change as a result of user actions, automated processes, or the execution of workflows within Assemblyline. The status provides insight into the current phase of analysis or response.")
    ts = odm.Date(description="Timestamp of when the file submission occurred that led to the generation of this alert.")
    type = odm.Keyword(description="The type or category of the alert as specified at submission time by the user.")
    verdict = odm.Compound(Verdict, default={}, description="Consolidates user assessments of the submission's nature. It records the user identifiers of those who have evaluated the submission, categorizing it as either malicious or non-malicious.")
    events = odm.sequence(odm.compound(Event), default=[], description="An audit trail of events and actions taken on the alert.")
    workflows_completed = odm.Boolean(default=False, description="Flag indicating whether all configured workflows have been executed for this alert.")

    def update(self, other: Alert) -> None:
        """Update the current object given the content of a second alert."""

        # Make sure we are merging compatible alerts
        if self.alert_id != other.alert_id:
            raise ValueError(f"Only versions of the same alert may be merged id {self.alert_id} != {other.alert_id}")

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
        self.extended_scan = merge_extended_scan(self.extended_scan, other.extended_scan)

        # If either is filtered, the content should be considered filtered
        self.filtered |= other.filtered
        # Keep all unique labels and metadata, where metadata doesn't match take one more or less at random
        self.label = list(set(self.label + other.label))
        self.metadata.update(other.metadata)

        # Prefer the current owner/priority/status, but take the other if the current isn't defined
        self.owner = self.owner or other.owner
        self.priority = self.priority or other.priority
        self.reporting_ts = max(self.reporting_ts, other.reporting_ts)
        self.ts = min(self.ts, other.ts)
        self.status = self.status or other.status

        # self.type is fine

        # Merge the submission list and update sid to a value that isn't a parent
        self.submission_relations = list(set(self.submission_relations + other.submission_relations))
        parents = set(relation.parent for relation in self.submission_relations if relation.parent)
        for relation in self.submission_relations:
            if relation.child not in parents and relation.parent:
                self.sid = relation.child

        # Merge the events then sort them by time
        self.events = list(sorted(set(self.events + other.events), key=lambda e: e.ts))

        # Always consider the updated alert a new one WRT workflows
        self.workflows_completed = False
