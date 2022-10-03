from __future__ import annotations
import hashlib
from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()

SUBMISSION_STATES = ['failed', 'submitted', 'completed']
DEFAULT_SRV_SEL = ["Filtering", "Antivirus", "Static Analysis", "Extraction", "Networking"]
DEFAULT_RESUBMIT = []


@odm.model(index=True, store=False, description="File Model of Submission")
class File(odm.Model):
    name = odm.Keyword(copyto="__text__", description="Name of the file")
    size = odm.Optional(odm.Integer(), description="Size of the file in bytes")
    sha256 = odm.SHA256(copyto="__text__", description="SHA256 hash of the file")


@odm.model(index=False, store=False, description="Service Selection Scheme")
class ServiceSelection(odm.Model):
    selected = odm.List(odm.Keyword(), default=DEFAULT_SRV_SEL, description="List of selected services")
    excluded = odm.List(odm.Keyword(), default=[], description="List of excluded services")
    rescan = odm.List(
        odm.Keyword(),
        default=[],
        description="List of services to rescan when initial run scores as malicious")
    resubmit = odm.List(odm.Keyword(), default=DEFAULT_RESUBMIT,
                        description="Add to service selection when resubmitting")
    runtime_excluded = odm.List(odm.Keyword(), default=[], description="List of runtime excluded services")


# Fields in the parameters used to calculate hashes used for result caching
_KEY_HASHED_FIELDS = {
    'classification',
    'deep_scan',
    'ignore_cache',
    'ignore_dynamic_recursion_prevention',
    'ignore_filtering',
    'ignore_size',
    'max_extracted',
    'max_supplementary',
}


@odm.model(index=True, store=False, description="Submission Parameters")
class SubmissionParams(odm.Model):
    classification = odm.Classification(default=Classification.UNRESTRICTED,
                                        description="Original classification of the submission")
    deep_scan = odm.Boolean(default=False, description="Should a deep scan be performed?")
    description = odm.Text(store=True, copyto="__text__", description="Description of the submission")
    generate_alert = odm.Boolean(default=False, description="Should this submission generate an alert?")
    groups = odm.List(odm.Keyword(), default=["USERS"], description="List of groups related to this scan")
    ignore_cache = odm.Boolean(default=False, description="Ignore the cached service results?")
    ignore_dynamic_recursion_prevention = odm.Boolean(
        default=False, description="Should we ignore dynamic recursion prevention?")
    ignore_filtering = odm.Boolean(default=False, description="Should we ignore filtering services?")
    ignore_size = odm.Boolean(default=False, description="Ignore the file size limits?")
    never_drop = odm.Boolean(default=False, description="Exempt from being dropped by ingester?")
    malicious = odm.Boolean(default=False, description="Is the file submitted already known to be malicious?")
    max_extracted = odm.Integer(default=500, description="Max number of extracted files")
    max_supplementary = odm.Integer(default=500, description="Max number of supplementary files")
    priority = odm.Integer(default=1000, description="Priority of the scan")
    profile = odm.Boolean(default=False, description="Should the submission do extra profiling?")
    psid = odm.Optional(odm.UUID(), description="Parent submission ID")
    quota_item = odm.Boolean(default=False, description="Does this submission count against quota?")
    services = odm.Compound(ServiceSelection, default={}, description="Service selection")
    service_spec = odm.Mapping(odm.Mapping(odm.Any()), default={}, index=False, store=False,
                               description="Service-specific parameters")
    submitter = odm.Keyword(store=True, copyto="__text__", description="User who submitted the file")
    ttl = odm.Integer(default=0, description="Time, in days, to live for this submission")
    type = odm.Keyword(default="USER", description="Type of submission")
    initial_data = odm.Optional(odm.Text(index=False), description="Initialization for temporary submission data")

    def get_hashing_keys(self):
        """Get the sections of the submission parameters that should be used in result hashes."""
        data = self.as_primitives()
        return {k: v for k, v in data.items() if k in _KEY_HASHED_FIELDS}

    def create_filescore_key(self, sha256, services: list = None):
        """This is the key used to store the final score of a submission for fast lookup.

        This lookup is one of the methods used to check for duplication in ingestion process,
        so this key is fairly sensitive.
        """
        # TODO do we need this version thing still be here?
        # One up this if the cache is ever messed up and we
        # need to quickly invalidate all old cache entries.
        version = 0

        if services is None:
            services = self.services.selected

        data = self.get_hashing_keys()
        data['service_spec'] = sorted((key, sorted(values.items())) for key, values in self.service_spec.items())
        data['sha256'] = sha256
        data['services'] = [str(x) for x in services]

        s = ', '.join([f"{k}: {data[k]}" for k in sorted(data.keys())])

        return 'v'.join([str(hashlib.md5(s.encode()).hexdigest()), str(version)])


@odm.model(index=True, store=True, description="Submission-Relevant Times")
class Times(odm.Model):
    completed = odm.Optional(odm.Date(store=False), description="Date at which the submission finished scanning")
    submitted = odm.Date(default="NOW", description="Date at which the submission started scanning")


@odm.model(index=True, store=False, description="Submission Verdict")
class Verdict(odm.Model):
    malicious = odm.List(odm.Keyword(), default=[], description="List of user that thinks this submission is malicious")
    non_malicious = odm.List(
        odm.Keyword(),
        default=[],
        description="List of user that thinks this submission is non-malicious")


@odm.model(index=True, store=True, description="Model of Submission")
class Submission(odm.Model):
    archive_ts = odm.Optional(odm.Date(store=False, description="Archiving timestamp (Deprecated)"))
    classification = odm.Classification(description="Classification of the submission")
    error_count = odm.Integer(description="Total number of errors in the submission")
    errors: list[str] = odm.List(odm.Keyword(), store=False, description="List of error keys")
    expiry_ts = odm.Optional(odm.Date(store=False), description="Expiry timestamp")
    file_count = odm.Integer(description="Total number of files in the submission")
    files: list[File] = odm.List(odm.Compound(File), description="List of files that were originally submitted")
    max_score = odm.Integer(description="Maximum score of all the files in the scan")
    metadata = odm.FlattenedObject(store=False, description="Metadata associated to the submission")
    params: SubmissionParams = odm.Compound(SubmissionParams, description="Submission parameter details")
    results: list[str] = odm.List(odm.Keyword(), store=False, description="List of result keys")
    sid = odm.UUID(copyto="__text__", description="Submission ID")
    state = odm.Enum(values=SUBMISSION_STATES, description="Status of the submission")
    times = odm.Compound(Times, default={}, description="Submission-specific times")
    verdict = odm.Compound(Verdict, default={}, description="Malicious verdict details")

    # the filescore key, used in deduplication. This is a non-unique key, that is
    # shared by submissions that may be processed as duplicates.
    scan_key = odm.Optional(odm.Keyword(store=False, index=False))

    def is_submit(self):
        return self.state == 'submitted'

    def is_complete(self):
        return self.state == 'completed'

    def is_initial(self):
        return self.is_submit() and not self.params.psid
