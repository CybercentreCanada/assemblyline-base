from assemblyline.remote.datatypes import get_client, retry_call, now_as_iso
from assemblyline.remote.datatypes.hash import Hash


class Counters(object):
    def __init__(self, prefix="counter", host=None, port=None, db=None, track_counters=False):
        self.c = get_client(host, port, db, False)
        self.prefix = prefix
        if track_counters:
            self.tracker = Hash("c-tracker-%s" % prefix, host=host, port=port, db=db)
        else:
            self.tracker = None

    def inc(self, name, value=1, track_id=None):
        if self.tracker:
            self.tracker.add(track_id, now_as_iso())
        return retry_call(self.c.incr, "%s-%s" % (self.prefix, name), value)

    def dec(self, name, value=1, track_id=None):
        if self.tracker:
            self.tracker.pop(str(track_id))
        return retry_call(self.c.decr, "%s-%s" % (self.prefix, name), value)

    def get_queues_sizes(self):
        out = {}
        for queue in retry_call(self.c.keys, "%s-*" % self.prefix):
            queue_size = int(retry_call(self.c.get, queue))
            if queue_size != 0:
                out[queue] = queue_size

        return out

    def get_queues(self):
        return retry_call(self.c.keys, "%s-*" % self.prefix)

    # noinspection PyBroadException
    def ready(self):
        try:
            self.c.ping()
        except Exception:  # pylint: disable=W0702
            return False

        return True

    def reset_queues(self):
        self.c.delete("c-tracker-%s" % self.prefix)
        for queue in retry_call(self.c.keys, "%s-*" % self.prefix):
            retry_call(self.c.set, queue, "0")
