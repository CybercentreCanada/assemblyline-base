"""
TODO: Should this counter be rebuilt? does apscheduler exit the way we expect?
      Even if it isn't changed, apscheduler should be moved to the latest version

"""
import collections
import copy
import logging
import pprint
import threading

log = logging.getLogger('assemblyline.counters')


# noinspection PyAbstractClass
class Counters(collections.Counter):
    pass


# noinspection PyBroadException
class AutoExportingCounters(object):
    """
    A wrapper around collections.Counter that adds periodic backup.

    NOTE: Not to be confused with remote_datatypes.Counter which wraps a live
          redis counter. This counter is save only, and only offers weak durability.
          This is appropriate for monitoring and performance measurements, not
          for operational counters that require strict semantics.

    At the specified interval and program exit, the value in the counters will be
    sent to the provided channel.
    """

    def __init__(self,
                 name,
                 host,
                 export_interval_secs,
                 channel,
                 auto_log=True,
                 auto_flush=False,
                 counter_type=None):
        self.channel = channel
        self.export_interval = export_interval_secs
        self.counts = Counters()
        self.name = name
        self.host = host
        self.type = counter_type or name
        self.counts['type'] = counter_type or name
        self.counts['name'] = name
        self.counts['host'] = host
        self.auto_log = auto_log
        self.auto_flush = auto_flush
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
                thread_copy = copy.deepcopy(self.counts)
                if self.auto_flush:
                    self.counts = Counters()
                    self.counts['type'] = self.type
                    self.counts['name'] = self.name
                    self.counts['host'] = self.host

            self.channel.publish(thread_copy)
            if self.auto_log:
                log.info("%s", pprint.pformat(thread_copy))

            return thread_copy
        except Exception:
            log.exception("Exporting counters")

    def set(self, name, value):
        try:
            with self.lock:
                self.counts[name] = value
        except Exception:  # Don't let increment fail anything.
            log.exception("Setting counter")

    def increment(self, name, increment_by=1):
        try:
            with self.lock:
                self.counts[name] += increment_by
        except Exception:  # Don't let increment fail anything.
            log.exception("Incrementing counter")

    def increment_execution_time(self, name, execution_time):
        try:
            with self.lock:
                self.counts[name + ".c"] += 1
                self.counts[name + ".t"] += execution_time
        except Exception:  # Don't let increment fail anything.
            log.exception("Incrementing counter")
