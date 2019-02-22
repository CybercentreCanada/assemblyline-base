from assemblyline import odm
from assemblyline.odm.common import HostInfo

MSG_TYPES = {"IngestHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.ingest.IngestMessage"


@odm.model()
class Queues(odm.Model):
    critical = odm.Integer()  # Size of the critical priority queue
    high = odm.Integer()      # Size of the high priority queue
    ingest = odm.Integer()    # Size of the ingest queue
    low = odm.Integer()       # Size of the low priority queue
    medium = odm.Integer()    # Size of the medium priority queue


@odm.model()
class Metrics(odm.Model):
    byted_completed = odm.Integer()        # Number of bytes completed
    bytes_ingested = odm.Integer()         # Number of bytes ingested
    duplicates = odm.Integer()             # Number of duplicate submissions
    files_completed = odm.Integer()        # Number of completed files
    inflight = odm.Integer()               # Number of inflight submissions
    skipped = odm.Integer()                # Number of skipped files
    submissions_completed = odm.Integer()  # Number of completed submissions
    submissions_ingested = odm.Integer()   # Number of ingested submissions
    timed_out = odm.Integer()              # Number of timed_out submissions
    waiting = odm.Integer()                # Number of submissions waiting to start processing
    whitelisted = odm.Integer()            # Number of whitelisted submissions


@odm.model()
class Heartbeat(odm.Model):
    hostinfo = odm.Compound(HostInfo)  # Host Information block
    metrics = odm.Compound(Metrics)  # Ingesting metrics
    queues = odm.Compound(Queues)      # Queue lengths block
    shard = odm.Integer()              # Shard number
    up_hours = odm.Float()             # Number of hours ingester has been running


@odm.model()
class IngestMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="IngestHeartbeat")
    sender = odm.Keyword()
