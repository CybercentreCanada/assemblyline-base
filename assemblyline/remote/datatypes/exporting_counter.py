import collections
import logging
import pprint
import threading

# use pytz (as demanded by apschedular) to ensure the timezone is set,
# boxes with weird/new/different default timezone values can break things
# if a value APS likes isn't set explicitly
import pytz

from assemblyline.common import forge
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages import PerformanceTimer
from assemblyline.remote.datatypes import get_client

log = logging.getLogger('assemblyline.counters')


# noinspection PyAbstractClass
class Counters(collections.Counter):
    pass


# noinspection PyBroadException
class AutoExportingCounters(object):
    """
    A wrapper around collections.Counter that adds periodic backup.

    NOTE: Not to be confused with remote_datatypes. Counter which wraps a live
          redis counter. This counter is save only, and only offers weak durability.
          This is appropriate for monitoring and performance measurements, not
          for operational counters that require strict semantics.

    At the specified interval and program exit, the value in the counters will be
    sent to the provided channel.
    """

    def __init__(self,
                 name,
                 host=None,
                 export_interval_secs=None,
                 counter_type=None,
                 config=None,
                 redis=None,
                 counter_names=None,
                 timer_names=None,
                 export_zero=True):
        config = config or forge.get_config()
        self.channel = forge.get_metrics_sink(redis)
        self.export_interval = export_interval_secs or config.core.metrics.export_interval
        self.name = name
        self.host = host or get_random_id()
        self.type = counter_type or name
        self.export_zero = export_zero

        self.counter_schema = set(counter_names)
        self.timer_schema = set(timer_names)

        self.counts = None
        self.lock = threading.Lock()
        self.scheduler = None
        self.reset()

        assert self.channel
        assert(self.export_interval > 0)

    # noinspection PyUnresolvedReferences
    def start(self):
        from apscheduler.schedulers.background import BackgroundScheduler
        import atexit

        self.scheduler = BackgroundScheduler(daemon=True, timezone=pytz.utc)
        self.scheduler.add_job(self.export, 'interval', seconds=self.export_interval)
        self.scheduler.start()

        atexit.register(lambda: self.stop())

    def reset(self):
        with self.lock:
            old, self.counts = self.counts, Counters({key: 0 for key in self.counter_schema})
            self.counts.update({key + '.t': 0 for key in self.timer_schema})
            self.counts.update({key + '.c': 0 for key in self.timer_schema})
            self.counts['type'] = self.type
            self.counts['name'] = self.name
            self.counts['host'] = self.host

        return old

    def stop(self):
        if self.scheduler:
            self.scheduler.shutdown(wait=False)
            self.scheduler = None
        self.export()

    def export(self):
        try:
            # To avoid blocking increments on the redis operation
            # we only hold the long to do a copy.
            thread_copy = dict(self.reset().items())
            log.debug(f"{pprint.pformat(thread_copy)}")

            # Only export if needs be
            if self.export_zero or any(thread_copy.values()):
                self.channel.publish(thread_copy)

            return thread_copy
        except Exception:
            log.exception("Exporting counters")

    def increment(self, name, increment_by=1):
        try:
            if name not in self.counter_schema:
                raise ValueError(f"{name} is not an accepted counter for this module: f{self.counter_schema}")
            with self.lock:
                self.counts[name] += increment_by
                return increment_by
        except Exception:  # Don't let increment fail anything.
            log.exception("Incrementing counter")
            return 0

    def increment_execution_time(self, name, execution_time):
        try:
            if name not in self.timer_schema:
                raise ValueError(f"{name} is not an accepted counter for this module: f{self.timer_schema}")
            with self.lock:
                self.counts[name + ".c"] += 1
                self.counts[name + ".t"] += execution_time
                return execution_time
        except Exception:  # Don't let increment fail anything.
            log.exception("Incrementing counter")
            return 0


def export_metrics_once(name, schema, metrics, host=None, counter_type=None, config=None, redis=None):
    """Manually publish metric counts to the metrics system.

    This was built for when the service server is reporting metrics for execution and caching
    on behalf of many services. At the moment the metrics system uses the hosts to count the number
    of instances of each service. This could be done with a single auto exporting counter for
    the service server, but that may require significant downstream changes in the metrics system.
    """
    config = config or forge.get_config()
    redis = redis or forge.get_pubsub_redis()

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

    channel = forge.get_metrics_sink(redis)

    counts = Counters({key: 0 for key in counter_schema})
    counts.update({key + '.t': 0 for key in timer_schema})
    counts.update({key + '.c': 0 for key in timer_schema})

    for metric, value in metrics.items():
        if metric in counter_schema:
            counts[metric] += value
        elif metric in timer_schema:
            counts[metric + ".c"] += 1
            counts[metric + ".t"] += value
        else:
            raise ValueError(f"{metric} is not an accepted counter")

    counts['type'] = counter_type or name
    counts['name'] = name
    counts['host'] = host

    channel.publish(dict(counts.items()))
