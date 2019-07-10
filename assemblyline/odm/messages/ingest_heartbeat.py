from assemblyline import odm
from . import PerformanceTimer

MSG_TYPES = {"IngestHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.ingest_heartbeat.IngestMessage"


@odm.model()
class Queues(odm.Model):
    critical = odm.Integer()  # Size of the critical priority queue
    high = odm.Integer()      # Size of the high priority queue
    ingest = odm.Integer()    # Size of the ingest queue
    low = odm.Integer()       # Size of the low priority queue
    medium = odm.Integer()    # Size of the medium priority queue


@odm.model()
class Metrics(odm.Model):
    cache_miss = odm.Integer()
    cache_expired = odm.Integer()
    cache_stale = odm.Integer()
    cache_hit_local = odm.Integer()
    cache_hit = odm.Integer()
    bytes_completed = odm.Integer()        # Number of bytes completed
    bytes_ingested = odm.Integer()         # Number of bytes ingested
    duplicates = odm.Integer()             # Number of duplicate submissions
    error = odm.Integer()
    files_completed = odm.Integer()        # Number of completed files
    skipped = odm.Integer()                # Number of skipped files
    submissions_completed = odm.Integer()  # Number of completed submissions
    submissions_ingested = odm.Integer()   # Number of ingested submissions
    timed_out = odm.Integer()              # Number of timed_out submissions
    whitelisted = odm.Integer()            # Number of whitelisted submissions
    cpu_seconds = PerformanceTimer()
    cpu_seconds_count = odm.Integer()
    busy_seconds = PerformanceTimer()
    busy_seconds_count = odm.Integer()


@odm.model()
class Processing(odm.Model):
    inflight = odm.Integer()               # Number of inflight submissions


@odm.model()
class ProcessingChance(odm.Model):
    critical = odm.Integer()  # Chance of processing critical items
    high = odm.Integer()      # Chance of processing high items
    low = odm.Integer()       # Chance of processing low items
    medium = odm.Integer()    # Chance of processing medium items


@odm.model()
class Heartbeat(odm.Model):
    instances = odm.Integer()                           # Number of ingest processes
    metrics = odm.Compound(Metrics)                     # Metrics
    processing = odm.Compound(Processing)               # Inflight queue sizes
    processing_chance = odm.Compound(ProcessingChance)  # Chance of processing items
    queues = odm.Compound(Queues)                       # Queue lengths block


@odm.model()
class IngestMessage(odm.Model):
    msg = odm.Compound(Heartbeat)
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS)
    msg_type = odm.Enum(values=MSG_TYPES, default="IngestHeartbeat")
    sender = odm.Keyword()
