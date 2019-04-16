from assemblyline import odm
from assemblyline.odm.models.workflow import PRIORITIES, STATUSES

EXTENDED_SCAN_VALUES = {"submitted", "skipped", "incomplete", "completed"}


@odm.model(index=True, store=True)
class ALResults(odm.Model):                 # Assemblyline result block
    attrib = odm.List(odm.Keyword(), store=False, copyto="__text__")   # List of attribution
    av = odm.List(odm.Keyword(), copyto="__text__")                    # List of AV hits
    domain = odm.List(odm.Keyword(), store=False, copyto="__text__")   # List of all domains
    domain_dynamic = odm.List(odm.Keyword(), store=False)              # List of domains found during dynamic analysis
    domain_static = odm.List(odm.Keyword(), store=False)               # List of domains foudn during static analysis
    ip = odm.List(odm.Keyword(), store=False, copyto="__text__")       # List of all IPs
    ip_dynamic = odm.List(odm.Keyword(), store=False)                  # List of IPs found during dynamic analysis
    ip_static = odm.List(odm.Keyword(), store=False)                   # List of IPs found during static analysis
    request_end_time = odm.Date(index=False, store=False)              # End time of the Assemblyline submission
    score = odm.Integer()                                              # Maximum score found in the submission
    summary = odm.List(odm.Keyword(), store=False, copyto="__text__")  # List of executive summary for the alert
    yara = odm.List(odm.Keyword(), store=False, copyto="__text__")     # List of yara hits


@odm.model(index=True, store=True)
class File(odm.Model):    # File block
    md5 = odm.Keyword(copyto="__text__")                # MD5 of the top level file
    name = odm.Keyword(store=False, copyto="__text__")  # Name of the file
    sha1 = odm.Keyword(copyto="__text__")               # SHA1 hash of the file
    sha256 = odm.Keyword(copyto="__text__")             # SHA256 hash of the file
    size = odm.Integer(store=False)                     # Size of the file
    type = odm.Keyword(copyto="__text__")               # Type of file as identified by Assemblyline


@odm.model(index=True, store=True)
class Alert(odm.Model):
    alert_id = odm.Keyword(copyto="__text__")                           # ID of the alert
    al = odm.Compound(ALResults)                                        # Assemblyline result block
    classification = odm.Classification()                               # Classification of the alert
    expiry_ts = odm.Date(store=False)                                   # Expiry timestamp
    extended_scan = odm.Enum(values=EXTENDED_SCAN_VALUES, store=False)  # Status of the extended scan
    file = odm.Compound(File)                                           # File block
    label = odm.List(odm.Keyword(), copyto="__text__", default=[])      # List of labels applied to the alert
    metadata = odm.Mapping(odm.Keyword(), store=False)                  # Metadata submitted with the file
    owner = odm.Keyword(default_set=True)                               # Owner of the alert
    priority = odm.Enum(values=PRIORITIES, default_set=True)            # Priority applied to the alert
    reporting_ts = odm.Date()                                           # Time at which the alert was created
    sid = odm.Keyword(index=False, store=False)                         # ID of the submission related to this alert
    status = odm.Enum(values=STATUSES, default_set=True)                # Status applied to the alert
    ts = odm.Date()                                                     # Timestamp at which the file was submitted
    type = odm.Keyword()                                                # Type of alert
