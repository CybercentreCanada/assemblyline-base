import json

from assemblyline.remote.datatypes import get_client, retry_call

_drop_card_script = """
local set_name = ARGV[1]
local key = ARGV[2]

redis.call('srem', set_name, key)
return redis.call('scard', set_name)
"""

_limited_add = """
local set_name = KEYS[1]
local key = ARGV[1]
local limit = tonumber(ARGV[2])

if redis.call('scard', set_name) < limit then
    redis.call('sadd', set_name, key)
    return true
end
return false
"""


class Set(object):
    def __init__(self, name, host=None, port=None, db=None):
        self.c = get_client(host, port, db, False)
        self.name = name
        self._drop_card = self.c.register_script(_drop_card_script)
        self._limited_add = self.c.register_script(_limited_add)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.delete()

    def add(self, *values):
        return retry_call(self.c.sadd, self.name,
                          *[json.dumps(v) for v in values])

    def limited_add(self, value, size_limit):
        """Add a single value to the set, but only if that wouldn't make the set grow past a given size."""
        return retry_call(self._limited_add, keys=[self.name], args=[json.dumps(value), size_limit])

    def exist(self, value):
        return retry_call(self.c.sismember, self.name, json.dumps(value))

    def length(self):
        return retry_call(self.c.scard, self.name)

    def members(self):
        return [json.loads(s) for s in retry_call(self.c.smembers, self.name)]

    def remove(self, *values):
        return retry_call(self.c.srem, self.name,
                          *[json.dumps(v) for v in values])

    def drop(self, value):
        return retry_call(self._drop_card, args=[value])

    def random(self, num=None):
        ret_val = retry_call(self.c.srandmember, self.name, num)
        if isinstance(ret_val, list):
            return [json.loads(s) for s in ret_val]
        else:
            return json.loads(ret_val)

    def pop(self):
        return json.loads(retry_call(self.c.spop, self.name))

    def delete(self):
        retry_call(self.c.delete, self.name)


class ExpiringSet(Set):
    def __init__(self, name, ttl=86400, host=None, port=None, db=None):
        super(ExpiringSet, self).__init__(name, host, port, db)
        self.ttl = ttl

    def add(self, *values):
        rval = super(ExpiringSet, self).add(*values)
        retry_call(self.c.expire, self.name, self.ttl)
        return rval
