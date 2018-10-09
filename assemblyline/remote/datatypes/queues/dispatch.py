from assemblyline.remote.datatypes.queues.priority import PriorityQueue


# TODO: This class needs to be decoupled from forge and Task
class DispatchQueue(object):
    def __init__(self, host=None, port=None, db=None):
        config = forge.get_config()
        self.host = host or config.core.redis.nonpersistent.host
        self.port = port or config.core.redis.nonpersistent.port
        self.db = db or config.core.redis.nonpersistent.db
        self.q = {}

    def _get_queue(self, n):
        q = self.q.get(n, None)
        if not q:
            self.q[n] = q = PriorityQueue(n, self.host, self.port, self.db)
        return q

    def length(self, name):
        return self._get_queue(name).length()

    def pop(self, name, num=1):
        return self._get_queue(name).pop(num)

    def send(self, task, shards=None, queue_name=None):
        if queue_name is None:
            queue_name = {}

        if not shards:
            config = forge.get_config()
            shards = config.core.dispatcher.shards

        if not task.dispatch_queue:
            n = forge.determine_dispatcher(task.sid, shards)
            name = queue_name.get(n, None)
            if not name:
                queue_name[n] = name = 'ingest-queue-' + str(n)
            task.dispatch_queue = name
        if not task.priority:
            task.priority = 0
        self._get_queue(task.dispatch_queue).push(task.priority, task.raw)

    def send_raw(self, raw, shards=None):
        if not shards:
            config = forge.get_config()
            shards = config.core.dispatcher.shards

        task = Task(raw)
        self.send(task, shards)

    def submit(self, task, shards=None):
        if not shards:
            config = forge.get_config()
            shards = config.core.dispatcher.shards
        task.dispatch_queue = None
        self.send(task, shards)
