import redis
import json

from assemblyline.remote.datatypes import get_client, retry_call

h_pop_script = """
local result = redis.call('hget', ARGV[1], ARGV[2])
if result then redis.call('hdel', ARGV[1], ARGV[2]) end
return result
"""


_limited_add = """
local set_name = KEYS[1]
local key = ARGV[1]
local value = ARGV[2]
local limit = tonumber(ARGV[3])

if redis.call('hlen', set_name) < limit then
    return redis.call('hsetnx', set_name, key, value)
end
return nil
"""


class Hash(object):
    def __init__(self, name, host=None, port=None, db=None):
        if isinstance(host, redis.Redis):
            self.c = host
        else:
            self.c = get_client(host, port, db, False)
        self.name = name
        self._pop = self.c.register_script(h_pop_script)
        self._limited_add = self.c.register_script(_limited_add)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.delete()

    def add(self, key: str, value):
        """Add the (key, value) pair to the hash for new keys.

        If a key already exists this operation doesn't add it.

        Returns:
            True if key has been added to the table, False otherwise.
        """
        if isinstance(key, bytes):
            raise ValueError("Cannot use bytes for hashmap keys")
        return retry_call(self.c.hsetnx, self.name, key, json.dumps(value))

    def increment(self, key, increment=1):
        return int(retry_call(self.c.hincrby, self.name, key, increment))

    def limited_add(self, key, value, size_limit):
        """Add a single value to the set, but only if that wouldn't make the set grow past a given size."""
        return retry_call(self._limited_add, keys=[self.name], args=[key, json.dumps(value), size_limit])

    def exists(self, key):
        return retry_call(self.c.hexists, self.name, key)

    def get(self, key):
        item = retry_call(self.c.hget, self.name, key)
        if not item:
            return item
        return json.loads(item)

    def keys(self):
        return [k.decode('utf-8') for k in retry_call(self.c.hkeys, self.name)]

    def length(self):
        return retry_call(self.c.hlen, self.name)

    def items(self):
        items = retry_call(self.c.hgetall, self.name)
        if not isinstance(items, dict):
            return {}
        for k in items.keys():
            items[k] = json.loads(items[k])
        return {k.decode('utf-8'): v for k, v in items.items()}

    def pop(self, key):
        item = retry_call(self._pop, args=[self.name, key])
        if not item:
            return item
        return json.loads(item)

    def set(self, key, value):
        if isinstance(key, bytes):
            raise ValueError("Cannot use bytes for hashmap keys")
        return retry_call(self.c.hset, self.name, key, json.dumps(value))

    def delete(self):
        retry_call(self.c.delete, self.name)


class ExpiringHash(Hash):
    def __init__(self, name, ttl=86400, host=None, port=None, db=None):
        super(ExpiringHash, self).__init__(name, host, port, db)
        self.ttl = ttl

    def add(self, key, value):
        rval = super(ExpiringHash, self).add(key, value)
        retry_call(self.c.expire, self.name, self.ttl)
        return rval

    def set(self, key, value):
        rval = super(ExpiringHash, self).set(key, value)
        retry_call(self.c.expire, self.name, self.ttl)
        return rval

    def increment(self, key, increment=1):
        rval = super(ExpiringHash, self).increment(key, increment)
        retry_call(self.c.expire, self.name, self.ttl)
        return rval

    def limited_add(self, key, value, size_limit):
        rval = super(ExpiringHash, self).limited_add(key, value, size_limit)
        retry_call(self.c.expire, self.name, self.ttl)
        return rval
