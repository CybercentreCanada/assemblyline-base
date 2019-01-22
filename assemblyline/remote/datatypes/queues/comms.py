import json
import redis

from assemblyline.remote.datatypes import get_client, retry_call, log, decode


class CommsQueue(object):
    def __init__(self, names, host=None, port=None, db=None, private=False):
        self.c = host if isinstance(host, redis.Redis) else get_client(host, port, db, private)
        self.p = retry_call(self.c.pubsub)
        if not isinstance(names, list):
            names = [names]
        self.names = names
        self._connected = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        retry_call(self.p.unsubscribe)

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
                if isinstance(v, dict) and v.get('type', None) == 'message':
                    data = decode(v.get('data', 'null'))
                    yield (data)
            except redis.ConnectionError:
                log.warning('No connection to Redis, reconnecting...')
                self._connected = False

    def publish(self, message):
        for name in self.names:
            retry_call(self.c.publish, name, json.dumps(message))
