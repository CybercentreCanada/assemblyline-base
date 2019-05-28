from assemblyline.common import forge
from assemblyline.remote.datatypes import get_client
from assemblyline.remote.datatypes.exporting_counter import AutoExportingCounters

ALERT_METRICS = [
    'created',
    'error',
    'received',
    'updated']

DISPATCH_METRICS = [
    'files_completed',
    'submissions_completed'
]

EXPIRY_METRICS = [
    'alert',
    'cached_file',
    'emptyresult',
    'error',
    'file',
    'filescore',
    'result',
    'submission',
    'submission_tree',
    'submission_tags'
]

INGEST_METRICS = [
    'cache_miss',
    'cache_expired',
    'cache_stale',
    'cache_hit_local',
    'cache_hit',
    'bytes_completed',
    'bytes_ingested',
    'duplicates',
    'error',
    'files_completed',
    'skipped',
    'submissions_ingested',
    'submissions_completed',
    'timed_out',
    'whitelisted']

SRV_METRICS = [
    'cache_hit',
    'cache_miss',
    'cache_skipped',
    'execute',
    'fail_recoverable',
    'fail_nonrecoverable',
    'scored',
    'not_scored'
]

SRV_TIMING_METRICS = [
    'execution',
    'idle'
]

DATASTORE_METRICS = [
    'commit',
    'get',
    'mget',
    'save',
    'search',
]

FILESTORE_METRICS = [
    'delete',
    'download',
    'exist',
    'upload',
]

# Types of metrics
METRIC_TYPES = {
    'alerter': ALERT_METRICS,
    # 'datastore': DATASTORE_METRICS,
    'dispatcher': DISPATCH_METRICS,
    'expiry': EXPIRY_METRICS,
    # 'filestore': FILESTORE_METRICS,
    'ingester': INGEST_METRICS,
    'service': SRV_METRICS,
    'service_timing': SRV_TIMING_METRICS,
}

TIMED_METRICS = [
    # 'datastore',
    # 'filestore',
    'service_timing',
]


class MetricsFactory(object):
    """A wrapper around what was once, multiple metrics methods.

    Left in place until we decide we are absolutely not switching methods again.
    """
    def __init__(self, metrics_type, name=None, redis=None, config=None):
        self.config = config or forge.get_config()
        self.redis = redis or get_client(
            self.config.core.metrics.redis.host,
            self.config.core.metrics.redis.port,
            self.config.core.metrics.redis.db,
            False
        )

        self.type = metrics_type
        self.name = name or metrics_type

        # Initialize legacy metrics
        self.metrics_handler = AutoExportingCounters(
            self.name,
            redis=self.redis,
            config=self.config,
            counter_type=metrics_type)
        self.metrics_handler.start()

    def stop(self):
        self.metrics_handler.stop()

    def increment(self, name, increment_by=1):
        self.metrics_handler.increment(name, increment_by=increment_by)

    def increment_execution_time(self, name, execution_time):
        self.metrics_handler.increment_execution_time(name, execution_time)
