from assemblyline.common import forge
from assemblyline.remote.datatypes import get_client
from assemblyline.remote.datatypes.exporting_counter import AutoExportingCounters
from assemblyline.odm.messages import PerformanceTimer

# Which datastore tables have an expiry and we want to monitor how many files are due
# for expiry but still exist.
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
    'submission_summary'
]


class MetricsFactory(object):
    """A wrapper around what was once, multiple metrics methods.

    Left in place until we decide we are absolutely not switching methods again.
    """
    def __init__(self, metrics_type, schema, name=None, redis=None, config=None):
        self.config = config or forge.get_config()
        self.redis = redis or get_client(
            self.config.core.metrics.redis.host,
            self.config.core.metrics.redis.port,
            self.config.core.metrics.redis.db,
            False
        )

        # Separate out the timers and normal counters
        timer_schema = set()
        counter_schema = set()

        for _k, field_type in schema.fields().items():
            if isinstance(field_type, PerformanceTimer):
                timer_schema.add(_k)
            else:
                counter_schema.add(_k)

        for _k in timer_schema:
            counter_schema.discard(_k + '_count')

        self.type = metrics_type
        self.name = name or metrics_type

        # Initialize legacy metrics
        self.metrics_handler = AutoExportingCounters(
            self.name,
            redis=self.redis,
            config=self.config,
            counter_type=metrics_type,
            timer_names=timer_schema,
            counter_names=counter_schema
        )
        self.metrics_handler.start()

    def stop(self):
        self.metrics_handler.stop()

    def increment(self, name, increment_by=1):
        self.metrics_handler.increment(name, increment_by=increment_by)

    def increment_execution_time(self, name, execution_time):
        self.metrics_handler.increment_execution_time(name, execution_time)
