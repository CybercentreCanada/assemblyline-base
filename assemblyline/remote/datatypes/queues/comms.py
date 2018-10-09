import json
import redis

from assemblyline.common.exceptions import get_stacktrace_info
from assemblyline.remote.datatypes import get_client, retry_call, log


class CommsQueue(object):
    def __init__(self, names, host=None, port=None, db=None, private=False):
        self.c = get_client(host, port, db, private)
        self.p = retry_call(self.c.pubsub)
        if not isinstance(names, list):
            names = [names]
        self.names = names
        self._connected = False

    def _connect(self):
        if not self._connected:
            retry_call(self.p.subscribe, self.names)
            self._connected = True

    def close(self):
        retry_call(self.p.close)

    def listen(self):
        while True:
            self._connect()
            try:
                i = self.p.listen()
                v = next(i)
                if isinstance(v, dict) and v.get('type', '') != 'subscribe':
                    yield (v)
            except redis.ConnectionError as ex:
                trace = get_stacktrace_info(ex)
                log.warning('Redis connection error (1): %s', trace)
                self._connected = False

    def publish(self, message):
        for name in self.names:
            retry_call(self.c.publish, name, json.dumps(message))
