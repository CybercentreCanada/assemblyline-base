import json
import redis

from assemblyline.common.forge import get_pubsub_redis
from assemblyline.remote.datatypes import retry_call, log, decode


class CommsQueue:
    def __init__(self, names, host=None, port=None, private=False):
        self.c = get_pubsub_redis(host, port, private)
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

    def listen(self, blocking=True):
        retried = False
        while True:
            self._connect()
            try:
                if blocking:
                    i = self.p.listen()
                    v = next(i)
                else:
                    v = self.p.get_message()
                    if v is None:
                        yield None
                        continue

                if isinstance(v, dict) and v.get('type', None) == 'message':
                    data = decode(v.get('data', 'null'))
                    yield data
            except redis.ConnectionError:
                log.warning('No connection to Redis, reconnecting...')
                self._connected = False
                retried = True
            finally:
                if self._connected and retried:
                    log.info('Reconnected to Redis!')
                    retried = False

    def publish(self, message):
        for name in self.names:
            retry_call(self.c.publish, name, json.dumps(message))
