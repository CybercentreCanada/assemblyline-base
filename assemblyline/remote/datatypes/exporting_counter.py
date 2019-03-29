import collections
import copy
import logging
import pprint
import threading
import uuid

from assemblyline.common import forge

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
                 redis=None):
        config = config or forge.get_config()
        self.channel = forge.get_metrics_sink(redis)
        self.export_interval = export_interval_secs or config.core.metrics.export_interval
        self.name = name
        self.host = host or uuid.uuid4().hex
        self.type = counter_type or name

        self.counts = Counters()
        self.counts['type'] = counter_type or name
        self.counts['name'] = name
        self.counts['host'] = host

        self.lock = threading.Lock()
        self.scheduler = None
        assert self.channel
        assert(self.export_interval > 0)

    # noinspection PyUnresolvedReferences
    def start(self):
        from apscheduler.schedulers.background import BackgroundScheduler
        import atexit

        self.scheduler = BackgroundScheduler(daemon=True)
        self.scheduler.add_job(self.export, 'interval', seconds=self.export_interval)
        self.scheduler.start()

        atexit.register(lambda: self.stop())

    def stop(self):
        if self.scheduler:
            self.scheduler.shutdown(wait=False)
            self.scheduler = None
        self.export()

    def export(self):
        try:
            # To avoid blocking increments on the redis operation
            # we only hold the long to do a copy.
            with self.lock:
                thread_copy = dict(copy.deepcopy(self.counts).items())
                self.counts = Counters()
                self.counts['type'] = self.type
                self.counts['name'] = self.name
                self.counts['host'] = self.host

            self.channel.publish(thread_copy)
            log.debug(f"{pprint.pformat(thread_copy)}")

            return thread_copy
        except Exception:
            log.exception("Exporting counters")

    def increment(self, name, increment_by=1):
        try:
            with self.lock:
                self.counts[name] += increment_by
                return increment_by
        except Exception:  # Don't let increment fail anything.
            log.exception("Incrementing counter")
            return 0

    def increment_execution_time(self, name, execution_time):
        try:
            with self.lock:
                self.counts[name + ".c"] += 1
                self.counts[name + ".t"] += execution_time
                return execution_time
        except Exception:  # Don't let increment fail anything.
            log.exception("Incrementing counter")
            return 0