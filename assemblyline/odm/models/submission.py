import hashlib
from assemblyline import odm
from assemblyline.common import forge
Classification = forge.get_classification()

INGEST_SUBMISSION_DEFAULTS = {
    # Alternative defaults to the submission params used by the middleman client
    'generate_alert': True,
    'groups': [],    # TODO: Ideally this should not be empty
    'priority': -1,  # -1 tells middleman to figure out priority on its own
    'type': "BULK",
}
SUBMISSION_STATES = ['serviced', 'submitted', 'completed']
DEFAULT_SRV_SEL = ["Filtering", "Antivirus", "Static Analysis", "Extraction"]


@odm.model(index=True, store=False)
class File(odm.Model):
    name = odm.Keyword(copyto="__text__")    # Name of the file
    sha256 = odm.Keyword(copyto="__text__")  # SHA256 hash of the file


@odm.model(index=False, store=False)
class ServiceSelection(odm.Model):
    selected = odm.List(odm.Keyword(), default=DEFAULT_SRV_SEL)  # List of selected services for the submission
    excluded = odm.List(odm.Keyword(), default=[])               # List of excluded services for the submission
    resubmit = odm.List(odm.Keyword(), default=[])               # Add to service selection when resubmitting


# Fields in the parameters used to calculate hashes used for result caching
_KEY_HASHED_FIELDS = {
    'deep_scan',
    'eligible_parents',
    'ignore_filtering',
    'ignore_size',
    'max_extracted',
    'max_supplementary',
    'classification',
    'ignore_cache',
}


@odm.model(index=True, store=False)
class SubmissionParams(odm.Model):
    classification = odm.Classification(
        default=Classification.UNRESTRICTED)                            # Original classification of the submission
    deep_scan = odm.Boolean(default=False)                              # Should a deep scan be performed?
    description = odm.Text(default="", store=True, copyto="__text__")   # Description of the submission
    generate_alert = odm.Boolean(default=False)                         # Should this submission generate an alert
    groups = odm.List(odm.Keyword(), default=["USERS"])                 # List of groups related to this scan
    ignore_cache = odm.Boolean(default=False)                           # ignore the service caching or not
    ignore_dynamic_recursion_prevention = odm.Boolean(default=False)    # Should we ignore dynamic recursion prevention
    ignore_filtering = odm.Boolean(default=False)                       # Should we ignore filtering services
    ignore_size = odm.Boolean(default=False)                            # ignore the file size limits
    never_drop = odm.Boolean(default=False)                             # Exempt from being dropped by middleman
    max_extracted = odm.Integer(default=500)                            # Max number of extracted files
    max_supplementary = odm.Integer(default=500)                        # Max number of supplementary files
    priority = odm.Integer(default=1000)                                # Priority of the scan
    profile = odm.Boolean(default=False)                                # Should the submission do extra profiling
    psid = odm.Keyword(default_set=True)                                # Parent submission ID
    quota_item = odm.Boolean(default=False)                             # Does this submission count against quota
    services = odm.Compound(ServiceSelection, default={})               # Service selection bloc
    service_spec = odm.Mapping(odm.Mapping(odm.Keyword()), default={})  # Service specific parameters
    submitter = odm.Keyword(store=True)                                 # User who submitted the file
    ttl = odm.Integer(default=15)                                       # Time to live for this submission in days
    type = odm.Keyword(default="USER")                                  # Type of submission

    def get_hashing_keys(self):
        """Get the sections of the submission parameters that should be used in result hashes."""
        data = self.as_primitives()
        return {k: v for k, v in data.items() if k in _KEY_HASHED_FIELDS}

    def create_filescore_key(self, sha256, services: list=None):
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
    completed = odm.Date(store=False, default_set=True)  # Date at which the submission finished scanning
    submitted = odm.Date()                               # Date at which the submission started scanning


@odm.model(index=True, store=True)
class Submission(odm.Model):
    classification = odm.Classification()               # Classification of the submission
    error_count = odm.Integer()                         # Total number of errors in the submission
    errors = odm.List(odm.Keyword(), store=False)       # List of error keys
    expiry_ts = odm.Date(store=False)                   # Expiry time stamp
    file_count = odm.Integer()                          # Total number of files in the submission
    files = odm.List(odm.Compound(File))                # List of files that were originally submitted
    max_score = odm.Integer()                           # Maximum score of all the files in the scan
    metadata = odm.Mapping(odm.Keyword(), store=False)  # Metadata associated to the submission
    params = odm.Compound(SubmissionParams)             # Submission detail blocs
    results = odm.List(odm.Keyword(), store=False)      # List of result keys
    sid = odm.Keyword(copyto="__text__")                # Submission ID
    state = odm.Enum(values=SUBMISSION_STATES)          # Status of the submission
    times = odm.Compound(Times)                         # Timing bloc

    def is_submit(self):
        return self.state == 'submitted'

    def is_complete(self):
        return self.state == 'completed'

    def is_initial(self):
        return self.is_submit() and not self.params.psid
