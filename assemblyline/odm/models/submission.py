from typing import List
import hashlib
from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()

SUBMISSION_STATES = ['failed', 'submitted', 'completed']
DEFAULT_SRV_SEL = ["Filtering", "Antivirus", "Static Analysis", "Extraction", "Networking"]
DEFAULT_RESUBMIT = ["Dynamic Analysis"]


@odm.model(index=True, store=False)
class File(odm.Model):
    name = odm.Keyword(copyto="__text__")    # Name of the file
    size = odm.Optional(odm.Integer())       # Size of the file
    sha256 = odm.SHA256(copyto="__text__")   # SHA256 hash of the file


@odm.model(index=False, store=False)
class ServiceSelection(odm.Model):
    selected = odm.List(odm.Keyword(), default=DEFAULT_SRV_SEL)   # List of selected services
    excluded = odm.List(odm.Keyword(), default=[])                # List of excluded services
    resubmit = odm.List(odm.Keyword(), default=DEFAULT_RESUBMIT)  # Add to service selection when resubmitting
    runtime_excluded = odm.List(odm.Keyword(), default=[])        # List of runtime excluded services


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


@odm.model(index=True, store=False)
class SubmissionParams(odm.Model):
    classification = odm.Classification(
        default=Classification.UNRESTRICTED)                            # Original classification of the submission
    deep_scan = odm.Boolean(default=False)                              # Should a deep scan be performed?
    description = odm.Text(store=True, copyto="__text__")               # Description of the submission
    generate_alert = odm.Boolean(default=False)                         # Should this submission generate an alert
    groups = odm.List(odm.Keyword(), default=["USERS"])                 # List of groups related to this scan
    ignore_cache = odm.Boolean(default=False)                           # ignore the service caching or not
    ignore_dynamic_recursion_prevention = odm.Boolean(default=False)    # Should we ignore dynamic recursion prevention
    ignore_filtering = odm.Boolean(default=False)                       # Should we ignore filtering services
    ignore_size = odm.Boolean(default=False)                            # ignore the file size limits
    never_drop = odm.Boolean(default=False)                             # Exempt from being dropped by ingester
    max_extracted = odm.Integer(default=500)                            # Max number of extracted files
    max_supplementary = odm.Integer(default=500)                        # Max number of supplementary files
    priority = odm.Integer(default=1000)                                # Priority of the scan
    profile = odm.Boolean(default=False)                                # Should the submission do extra profiling
    psid = odm.Optional(odm.UUID())                                     # Parent submission ID
    quota_item = odm.Boolean(default=False)                             # Does this submission count against quota
    services = odm.Compound(ServiceSelection, default={})               # Service selection bloc
    service_spec = odm.Mapping(odm.Mapping(odm.Keyword()),
                               default={}, index=False, store=False)    # Service specific parameters
    submitter = odm.Keyword(store=True, copyto="__text__")              # User who submitted the file
    ttl = odm.Integer(default=0)                                        # Time to live for this submission in days
    type = odm.Keyword(default="USER")                                  # Type of submission
    initial_data = odm.Mapping(odm.Any(), index=False, default={})      # Initialization for auxiliary 'temporary_data'

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


@odm.model(index=True, store=True)
class Times(odm.Model):
    completed = odm.Optional(odm.Date(store=False))  # Date at which the submission finished scanning
    submitted = odm.Date(default="NOW")              # Date at which the submission started scanning


@odm.model(index=True, store=False)
class Verdict(odm.Model):
    malicious = odm.List(odm.Keyword(), default=[])      # List of user that thinks this submission is malicious
    non_malicious = odm.List(odm.Keyword(), default=[])  # List of user that thinks this submission is non-malicious


@odm.model(index=True, store=True)
class Submission(odm.Model):
    archive_ts = odm.Date(store=False)                          # Archiving timestamp
    classification = odm.Classification()                       # Classification of the submission
    error_count = odm.Integer()                                 # Total number of errors in the submission
    errors = odm.List(odm.Keyword(), store=False)               # List of error keys
    expiry_ts = odm.Optional(odm.Date(store=False))             # Expiry timestamp
    file_count = odm.Integer()                                  # Total number of files in the submission
    files: List[File] = odm.List(odm.Compound(File))            # List of files that were originally submitted
    max_score = odm.Integer()                                   # Maximum score of all the files in the scan
    metadata = odm.FlattenedObject(store=False)                 # Metadata associated to the submission
    params: SubmissionParams = odm.Compound(SubmissionParams)   # Submission detail blocs
    results: List[str] = odm.List(odm.Keyword(), store=False)   # List of result keys
    sid = odm.UUID(copyto="__text__")                           # Submission ID
    state = odm.Enum(values=SUBMISSION_STATES)                  # Status of the submission
    times = odm.Compound(Times, default={})                     # Timing bloc
    verdict = odm.Compound(Verdict, default={})                 # Verdict timing

    def is_submit(self):
        return self.state == 'submitted'

    def is_complete(self):
        return self.state == 'completed'

    def is_initial(self):
        return self.is_submit() and not self.params.psid
