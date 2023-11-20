from assemblyline import odm
from assemblyline.odm.messages import PerformanceTimer

MSG_TYPES = {"IngestHeartbeat"}
LOADER_CLASS = "assemblyline.odm.messages.ingest_heartbeat.IngestMessage"


@odm.model(description="Queues")
class Queues(odm.Model):
    critical = odm.Integer(description="Size of the critical priority queue")
    high = odm.Integer(description="Size of the high priority queue")
    ingest = odm.Integer(description="Size of the ingest queue")
    complete = odm.Integer(description="Size of the complete queue")
    low = odm.Integer(description="Size of the low priority queue")
    medium = odm.Integer(description="Size of the medium priority queue")


@odm.model(description="Metrics")
class Metrics(odm.Model):
    cache_miss = odm.Integer(description="Number of cache misses")
    cache_expired = odm.Integer(description="Number of cache expires")
    cache_stale = odm.Integer(description="Number of cache stales")
    cache_hit_local = odm.Integer(description="Number of cache local hits")
    cache_hit = odm.Integer(description="Number of cache hits")
    bytes_completed = odm.Integer(description="Number of bytes completed")
    bytes_ingested = odm.Integer(description="Number of bytes ingested")
    duplicates = odm.Integer(description="Number of duplicate submissions")
    error = odm.Integer(description="Number of errors")
    files_completed = odm.Integer(description="Number of completed files")
    skipped = odm.Integer(description="Number of skipped files")
    submissions_completed = odm.Integer(description="Number of completed submissions")
    submissions_ingested = odm.Integer(description="Number of ingested submissions")
    timed_out = odm.Integer(description="Number of timed_out submissions")
    whitelisted = odm.Integer(description="Number of safelisted submissions")
    cpu_seconds = PerformanceTimer()
    cpu_seconds_count = odm.Integer()
    busy_seconds = PerformanceTimer()
    busy_seconds_count = odm.Integer()


@odm.model(description="Processing")
class Processing(odm.Model):
    inflight = odm.Integer(description="Number of inflight submissions")


@odm.model(description="Chance of Processing")
class ProcessingChance(odm.Model):
    critical = odm.Float(description="Chance of processing critical items")
    high = odm.Float(description="Chance of processing high items")
    low = odm.Float(description="Chance of processing low items")
    medium = odm.Float(description="Chance of processing medium items")


@odm.model(description="Heartbeat Model")
class Heartbeat(odm.Model):
    instances = odm.Integer(description="Number of ingest processes")
    metrics = odm.Compound(Metrics, description="Metrics")
    processing = odm.Compound(Processing, description="Inflight queue sizes")
    processing_chance = odm.Compound(ProcessingChance, description="Chance of processing items")
    queues = odm.Compound(Queues, description="Queue lengths block")


@odm.model(description="Model of Ingester Heartbeat Message")
class IngestMessage(odm.Model):
    msg = odm.Compound(Heartbeat, description="Heartbeat message")
    msg_loader = odm.Enum(values={LOADER_CLASS}, default=LOADER_CLASS, description="Loader class for message")
    msg_type = odm.Enum(values=MSG_TYPES, default="IngestHeartbeat", description="Type of message")
    sender = odm.Keyword(description="Sender of message")
