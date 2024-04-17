import json
from assemblyline.common.uid import get_id_from_data

from redis.exceptions import ConnectionError

from assemblyline.remote.datatypes import get_client, retry_call

DEFAULT_TTL = 60 * 60  # 1 Hour


class Cache(object):
    def __init__(self, prefix="al_cache", host=None, port=None, ttl=DEFAULT_TTL):
        self.c = get_client(host, port, False)
        self.prefix = prefix
        self.ttl = DEFAULT_TTL

    def __enter__(self):
        return self

    def _get_key(self, name):
        return f"{self.prefix}-{name}"

    def clear(self):
        # Clear all items belonging to this cahce
        for queue in retry_call(self.c.keys, "%s-*" % self.prefix):
            retry_call(self.c.delete, queue)

    def create_key(self, *args):
        key_str = "-".join([str(x) for x in args])
        return get_id_from_data(key_str)

    def get(self, key, ttl=None, reset=True):
        # Get the key name
        cache_name = self._get_key(key)

        # Get the value from the cache
        item = retry_call(self.c.get, cache_name)
        if not item:
            return item

        if reset:
            # Reset the cache while we're still using it
            retry_call(self.c.expire, cache_name, ttl or self.ttl)

        return json.loads(item)

    def ready(self):
        try:
            self.c.ping()
        except ConnectionError:
            return False

        return True

    def set(self, key, value, ttl=None):
        # Get the key name
        cache_name = self._get_key(key)

        # Set the value and the expiry for the name
        retry_call(self.c.set, cache_name, json.dumps(value))
        retry_call(self.c.expire, cache_name, ttl or self.ttl)
