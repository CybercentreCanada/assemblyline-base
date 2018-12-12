from assemblyline import odm


@odm.model(index=True, store=True)
class File(odm.Model):
    name = odm.Keyword()                   # Name of the file
    sha256 = odm.Keyword()                 # SHA256 hash of the file


@odm.model(index=True, store=True)
class ServiceSelection(odm.Model):
    excluded = odm.List(odm.Keyword())  # List of excluded services for the submission
    selected = odm.List(odm.Keyword())  # List of selected services for the submission


@odm.model(index=True, store=True)
class SubmissionParams(odm.Model):
    classification = odm.Classification()                               # Original classification of the submission
    deep_scan = odm.Boolean(default=False)                              # Should a deep scan be performed?
    description = odm.Text(default="")                                  # Description of the submission
    generate_alert = odm.Boolean(default=False)                         # Should this submission generate an alert
    groups = odm.List(odm.Keyword(), default=["USERS"])                 # List of groups related to this scan
    ignore_cache = odm.Boolean(default=False)                           # ignore the service caching or not
    ignore_dynamic_recursion_prevention = odm.Boolean(default=False)    # Should we ignore dynamic recursion prevention
    ignore_filtering = odm.Boolean(default=False)                       # Should we ignore filtering services
    max_extracted = odm.Integer(default=500)                            # Max number of extracted files
    max_supplementary = odm.Integer(default=500)                        # Max number of supplementary files
    priority = odm.Integer(default=1000)                                # Priority of the scan
    profile = odm.Boolean(default=False)                                # Should the submission do extra profiling
    psid = odm.Keyword(default="")                                      # Parent submission ID
    resubmit_to = odm.List(odm.Keyword(), default=[])                   # Add to service selection when resubmitting
    service_spec = odm.Mapping(odm.Mapping(odm.Keyword()), default={})  # Service specific parameters
    services = odm.Compound(ServiceSelection)                           # Service selection bloc
    submitter = odm.Keyword()                                           # User who submitted the file
    ttl = odm.Integer(default=15)                                       # Time to live for this submission in days
    type = odm.Keyword(default="USER")                                  # Type of submission


@odm.model(index=True, store=True)
class Times(odm.Model):
    completed = odm.Date()  # Date at which the submission finished scanning
    submitted = odm.Date()  # Date at which the submission started scanning


@odm.model(index=True, store=True)
class Submission(odm.Model):
    classification = odm.Classification()           # Classification of the submission
    error_count = odm.Integer()                     # Total number of errors in the submission
    errors = odm.List(odm.Keyword())                # List of error keys
    expiry_ts = odm.Date()                          # Expiry time stamp
    file_count = odm.Integer()                      # Total number of files in the submission
    files = odm.List(odm.Compound(File))            # List of files that were originally submitted
    max_score = odm.Integer()                       # Maximum score of all the files in the scan
    metadata = odm.Mapping(odm.Keyword())           # Metadata associated to the submission
    params = odm.Compound(SubmissionParams)         # Submission detail blocs
    results = odm.List(odm.Keyword())               # List of result keys
    sid = odm.Keyword()                             # Submission ID
    state = odm.Keyword()                           # Status of the submission
    times = odm.Compound(Times)                     # Timing bloc
