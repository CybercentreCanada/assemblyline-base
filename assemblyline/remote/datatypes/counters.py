
from redis.exceptions import ConnectionError

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

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.delete()

    def inc(self, name, value=1, track_id=None):
        if self.tracker:
            self.tracker.add(track_id or name, now_as_iso())
        return retry_call(self.c.incr, "%s-%s" % (self.prefix, name), value)

    def dec(self, name, value=1, track_id=None):
        if self.tracker:
            self.tracker.pop(str(track_id or name))
        return retry_call(self.c.decr, "%s-%s" % (self.prefix, name), value)

    def get_queues_sizes(self):
        out = {}
        for queue in retry_call(self.c.keys, "%s-*" % self.prefix):
            queue_size = int(retry_call(self.c.get, queue))
            out[queue] = queue_size

        return {k.decode('utf-8'): v for k, v in out.items()}

    def get_queues(self):
        return [k.decode('utf-8') for k in retry_call(self.c.keys, "%s-*" % self.prefix)]

    def ready(self):
        try:
            self.c.ping()
        except ConnectionError:
            return False

        return True

    def reset_queues(self):
        if self.tracker:
            self.tracker.delete()
        for queue in retry_call(self.c.keys, "%s-*" % self.prefix):
            retry_call(self.c.set, queue, "0")

    def delete(self):
        if self.tracker:
            self.tracker.delete()
        for queue in retry_call(self.c.keys, "%s-*" % self.prefix):
            retry_call(self.c.delete, queue)

