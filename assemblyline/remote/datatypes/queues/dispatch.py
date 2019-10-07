import functools

from assemblyline.remote.datatypes.queues.priority import PriorityQueue


def determine_dispatcher(sid, shards):
    n = functools.reduce(lambda x, y: x ^ y, [int(y, 16) for y in sid[-12:]])
    return n % shards


class DispatchQueue(object):
    def __init__(self, host=None, port=None, shards=None):
        self.host = host or '127.0.0.1'
        self.port = int(port or 6379)
        self.shards = int(shards or 1)

        self.queues = {}

    def _get_queue(self, name):
        q = self.queues.get(name, None)
        if not q:
            self.queues[name] = q = PriorityQueue(name, self.host, self.port)
        return q

    def length(self, name):
        return self._get_queue(name).length()

    def pop(self, name, num=1):
        return self._get_queue(name).pop(num)

    def send(self, message_id, message, shards, priority, dispatch_queue=None):
        if priority is None:
            priority = 0

        n = determine_dispatcher(message_id, shards)
        if not dispatch_queue:
            dispatch_queue = 'ingest-queue-' + str(n)
        self._get_queue(dispatch_queue).push(priority, message)
