import json

from assemblyline.remote.datatypes import get_client, retry_call


class ExpiringSet(object):
    def __init__(self, name, ttl=86400, host=None, port=None, db=None):
        self.c = get_client(host, port, db, False)
        self.name = name
        self.ttl = ttl

    def add(self, *values):
        rval = retry_call(self.c.sadd, self.name,
                          *[json.dumps(v) for v in values])
        retry_call(self.c.expire, self.name, self.ttl)
        return rval

    def length(self):
        return retry_call(self.c.scard, self.name)

    def members(self):
        return [json.loads(s) for s in retry_call(self.c.smembers, self.name)]

    def delete(self):
        retry_call(self.c.delete, self.name)
