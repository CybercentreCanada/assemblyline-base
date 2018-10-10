import json

from assemblyline.remote.datatypes import get_client, retry_call


class Set(object):
    def __init__(self, name, host=None, port=None, db=None):
        self.c = get_client(host, port, db, False)
        self.name = name

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.delete()

    def add(self, *values):
        return retry_call(self.c.sadd, self.name,
                          *[json.dumps(v) for v in values])

    def exist(self, value):
        return retry_call(self.c.sismember, self.name, json.dumps(value))

    def length(self):
        return retry_call(self.c.scard, self.name)

    def members(self):
        return [json.loads(s) for s in retry_call(self.c.smembers, self.name)]

    def remove(self, *values):
        return retry_call(self.c.srem, self.name,
                          *[json.dumps(v) for v in values])

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
