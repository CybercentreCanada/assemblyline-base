from assemblyline import odm


@odm.model(index=True, store=True)
class File(odm.Model):
    name = odm.Keyword()                   # Name of the file
    sha256 = odm.Keyword()                 # SHA256 hash of the file


@odm.model(index=True, store=True)
class SubmissionDetail(odm.Model):
    scan_key = odm.Keyword()                             # Key of the cached results TODO: Needed?
    sid = odm.Keyword()                                  # Submission ID
    description = odm.Text()                             # Description of the submission
    ignore_dynamic_recursion_prevention = odm.Boolean()  # Should we ignore dynamic recursion prevention
    ignore_filtering = odm.Boolean()                     # Should we ignore filtering services
    deep_scan = odm.Boolean()                            # Should a deep scan be performed?
    priority = odm.Integer()                             # Priority of the scan
    original_selected = odm.List(odm.Keyword())          # original service selection
    params = odm.Mapping(odm.Keyword())                  # Service specific parameters
    ignore_cache = odm.Boolean()                         # ignore the service caching or not
    groups = odm.List(odm.Keyword())                     # List of groups related to this scan
    ttl = odm.Integer()                                  # Time to live for this submission in days
    submitter = odm.Keyword()                            # User who submitted the file
    max_score = odm.Integer()                            # Maximum score of all the files in the scan
    resubmit_to = odm.List(odm.Keyword())                # Add these service when the submission is resubmitted
    metadata = odm.Mapping(odm.Keyword())                # Metadata associated to the submission


@odm.model(index=True, store=True)
class Times(odm.Model):
    completed = odm.Date()  # Date at which the submission finished scanning
    submitted = odm.Date()  # Date at which the submission started scanning


@odm.model(index=True, store=True)
class ServiceSelection(odm.Model):
    selected = odm.List(odm.Keyword())  # List of selected services for the submission
    excluded = odm.List(odm.Keyword())  # List of excluded services for the submission


@odm.model(index=True, store=True)
class Submission(odm.Model):
    expiry_ts = odm.Date()                          # Expiry time stamp
    files = odm.List(odm.Compound(File))            # List of files that were originally submitted
    classification = odm.Classification()           # Classification of the submission
    submission = odm.Compound(SubmissionDetail)     # Submission detail blocs
    state = odm.Keyword()                           # Status of the submission
    results = odm.List(odm.Keyword())               # List of result keys
    times = odm.Compound(Times)                     # Timing bloc
    errors = odm.List(odm.Keyword())                # List of error keys
    file_count = odm.Integer()                      # Total number of files in the submission
    error_count = odm.Integer()                     # Total number of errors in the submission
    services = odm.Compound(ServiceSelection)       # Service selection bloc
    original_classification = odm.Classification()  # Original classification of the submission
