from __future__ import annotations

import hashlib

from assemblyline import odm
from assemblyline.common import constants, forge

Classification = forge.get_classification()

SUBMISSION_STATES = ['failed', 'submitted', 'completed']
DEFAULT_SRV_SEL = ["Filtering", "Antivirus", "Static Analysis", "Extraction", "Networking"]
DEFAULT_RESUBMIT = []


@odm.model(index=True, store=False, description="File Model of Submission.")
class File(odm.Model):
    name = odm.Keyword(copyto="__text__", description="Name of the submission.")
    size = odm.Optional(odm.long(), description="Size of the submitted file in bytes.")
    sha256 = odm.SHA256(copyto="__text__", description="SHA256 hash of the submitted file.")


@odm.model(index=False, store=False, description="Service Selection Scheme.")
class ServiceSelection(odm.Model):
    selected = odm.List(odm.Keyword(), default=DEFAULT_SRV_SEL, description="List of selected services.")
    excluded = odm.List(odm.Keyword(), default=[], description="List of excluded services.")
    rescan = odm.List(
        odm.Keyword(),
        default=[],
        description="List of services to rescan when initial run scores as malicious.")
    resubmit = odm.List(odm.Keyword(), default=DEFAULT_RESUBMIT,
                        description="Add to service selection when resubmitting.")

# Fields in the parameters used to calculate hashes used for result caching
_KEY_HASHED_FIELDS = {
    'classification',
    'deep_scan',
    'ignore_cache',
    'ignore_recursion_prevention',
    'ignore_filtering',
    'ignore_size',
    'max_extracted',
    'max_supplementary',
}


@odm.model(index=True, store=False, description="Submission Parameters")
class SubmissionParams(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED,
                                        description="Original classification of the submission.")
    deep_scan = odm.Boolean(default=False, description="Select to perform a deep scan.")
    description = odm.Text(store=True, copyto="__text__", description="User-supplied information applied to Submission Details.")
    generate_alert = odm.Boolean(default=False, description="Generate alert upon completion of analysis.")
    groups = odm.List(odm.Keyword(), default=[], description="List relevant group or organization related to this scan.")
    ignore_cache = odm.Boolean(default=False, description="Ignore cached service results.")
    ignore_recursion_prevention = odm.Boolean(default=False, description="Ignore recursions prevention to avoid performance issues.")
    ignore_filtering = odm.Boolean(default=False, description="Ignore services in the FILTER category (i.e. Safelist).")
    ignore_size = odm.Boolean(default=False, description="Ignore the file size limits.")
    never_drop = odm.Boolean(default=False, description="Ingestion of submission will not be dropped as a result of ingestion queue volume.")
    malicious = odm.Boolean(default=False, description="User confirmation that the submission is known to be malicious.")
    max_extracted = odm.Integer(default=500, description="Max number of extracted files.")
    max_supplementary = odm.Integer(default=500, description="Max number of supplementary files.")
    priority = odm.Integer(default=1000, description="Determines order in which submission is analyzed relative to the queue.", min=1, max=constants.MAX_PRIORITY)
    psid = odm.Optional(odm.UUID(), description="Submission ID of 'parent' submission that has not been resubmitted for extended scan.")
    quota_item = odm.Boolean(default=False, description="Does this submission count against quota?")
    services = odm.Compound(ServiceSelection, default={}, description="Identify which services will run in the relevant submission.")
    service_spec = odm.Mapping(odm.Mapping(odm.Any()), default={}, index=False, store=False,
                               description="Service-specific parameters for the relevant submission.")
    submitter = odm.Keyword(store=True, copyto="__text__", description="User who submitted the file.")
    trace = odm.boolean(default=False, description="Collect debug information about the processing of a submission.")
    ttl = odm.Integer(default=0, description="Time, in days, to live for this submission.")
    type = odm.Keyword(default="USER", description="Source of submission (i.e. 'USER' or a particular sensor).")
    initial_data = odm.Optional(odm.Text(index=False), description="Initialization for temporary submission data.")
    auto_archive = odm.Boolean(default=False,
                               description="Send submission to the archive upon completion of analysis.")
    delete_after_archive = odm.Boolean(
        default=False,
        description="When the submission is archived, immediately delete from hot storage.")
    use_archive_alternate_dtl = odm.Boolean(default=False,
                                            description="use alternating dtl when archiving.")

    def get_hashing_keys(self):
        """Get the sections of the submission parameters that should be used in result hashes."""
        data = self.as_primitives()
        return {k: v for k, v in data.items() if k in _KEY_HASHED_FIELDS}

    def create_filescore_key(self, sha256, services: dict = None):
        """This is the key used to store the final score of a submission for fast lookup.

        This lookup is one of the methods used to check for duplication in ingestion process,
        so this key is fairly sensitive.
        """
        # TODO do we need this version thing still be here?
        # One up this if the cache is ever messed up and we
        # need to quickly invalidate all old cache entries.
        version = 0

        if services is None:
            services = self.services.as_primitives()

        data = self.get_hashing_keys()
        data['service_spec'] = sorted((key, sorted(values.items())) for key, values in self.service_spec.items())
        data['sha256'] = sha256
        data['services'] = sorted((key, sorted(values)) for key, values in services.items())

        s = ', '.join([f"{k}: {data[k]}" for k in sorted(data.keys())])

        return 'v'.join([str(hashlib.md5(s.encode()).hexdigest()), str(version)])


@odm.model(index=True, store=True, description="Submission-Relevant Times.")
class Times(odm.Model):
    completed = odm.Optional(odm.Date(store=False), description="Date at which the submission finished scanning.")
    submitted = odm.Date(default="NOW", description="Date at which the submission started scanning.")


@odm.model(index=True, store=False, description="Submission Verdict")
class Verdict(odm.Model):
    malicious = odm.List(odm.Keyword(), default=[], description="List all submissions that were labelled malicious by a specific user.")
    non_malicious = odm.List(
        odm.Keyword(),
        default=[],
        description="List all submissions that were labelled non-malicious by a specific user.")


@odm.model(index=False, store=False, description="A logging event describing the processing of a submission.")
class TraceEvent(odm.Model):
    timestamp = odm.Date(default="NOW")
    event_type = odm.keyword()
    service = odm.optional(odm.keyword())
    file = odm.optional(odm.SHA256())
    message = odm.optional(odm.keyword())


@odm.model(index=True, store=True, description="Model of Submission")
class Submission(odm.Model):
    archive_ts = odm.Optional(odm.Date(description="Timestamp at which the submission was archived.", ai=False))
    archived = odm.Boolean(default=False, description="Submission is present in the malware archive.", ai=False)
    classification = odm.Classification(description="Overall security classification of the submission.")
    tracing_events = odm.sequence(odm.compound(TraceEvent), default=[], index=False, store=False)
    error_count = odm.Integer(description="Total number of errors in the submission.", ai=False)
    errors: list[str] = odm.List(odm.Keyword(), store=False, description="List of error keys present in the submission.", ai=False)
    expiry_ts = odm.Optional(odm.Date(store=False), description="Timestamp for when the submission record expires.", ai=False)
    file_count = odm.Integer(description="Total number of files in the submission.", ai=False)
    files: list[File] = odm.List(odm.Compound(File), description="List of files that were originally submitted.")
    max_score = odm.Integer(description="The highest score across all files within a submission.")
    metadata: dict[str, str] = odm.FlatMapping(odm.MetadataValue(), default={}, store=False, copyto="__text__", description="Metadata associated with the submission.")
    params: SubmissionParams = odm.Compound(SubmissionParams, description="Submission parameter details.", ai=False)
    results: list[str] = odm.List(odm.wildcard(), store=False, description="List of result keys from the submission.", ai=False)
    sid: str = odm.UUID(copyto="__text__", description="The ID associated with a submission.")
    state = odm.Enum(values=SUBMISSION_STATES, description="State of the submission (ie. completed).", ai=False)
    to_be_deleted = odm.Boolean(
        default=False, description="This submission is going to be deleted as soon as it finishes.", ai=False)
    times = odm.Compound(Times, default={}, description="Submission-specific times.")
    verdict = odm.Compound(Verdict, default={}, description="Relates to the verdict of the submission (i.e. Malicious or Non-Malicious).", ai=False)
    from_archive = odm.Boolean(index=False, default=False, description="Was loaded from the archive.", ai=False)

    # the filescore key, used in deduplication. This is a non-unique key, that is
    # shared by submissions that may be processed as duplicates.
    scan_key = odm.Optional(odm.Keyword(store=False, index=False, ai=False))

    def is_submit(self):
        return self.state == 'submitted'

    def is_complete(self):
        return self.state == 'completed'

    def is_initial(self):
        return self.is_submit() and not self.params.psid
