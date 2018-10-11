import json

from assemblyline.remote.datatypes import get_client, retry_call, decode

# ARGV[1]: <queue name>, ARGV[2]: <max items to pop minus one>.
pq_pop_script = """
local result = redis.call('zrange', ARGV[1], 0, ARGV[2])
if result then redis.call('zremrangebyrank', ARGV[1], 0, ARGV[2]) end
return result
"""

# ARGV[1]: <queue name>, ARGV[2]: <priority>, ARGV[3]: <vip>,
# ARGV[4]: <item (string) to push>.
pq_push_script = """
local seq = string.format('%020d', redis.call('incr', 'global-sequence'))
local vip = string.format('%1d', ARGV[3])
redis.call('zadd', ARGV[1], 0 - ARGV[2], vip..seq..ARGV[4])
"""

# ARGV[1]: <queue name>, ARGV[2]: <max items to unpush>.
pq_unpush_script = """
local result = redis.call('zrange', ARGV[1], 0 - ARGV[2], 0 - 1)
if result then redis.call('zremrangebyrank', ARGV[1], 0 - ARGV[2], 0 - 1) end
return result
"""


class PriorityQueue(object):
    def __init__(self, name, host=None, port=None, db=None, private=False):
        self.c = get_client(host, port, db, private)
        self.r = self.c.register_script(pq_pop_script)
        self.s = self.c.register_script(pq_push_script)
        self.t = self.c.register_script(pq_unpush_script)
        self.name = name

    def count(self, lowest, highest):
        return retry_call(self.c.zcount, self.name, -highest, -lowest)

    def delete(self):
        retry_call(self.c.delete, self.name)

    def length(self):
        return retry_call(self.c.zcard, self.name)

    def pop(self, num=None):
        if num is not None and num <= 0:
            return []

        if num:
            return [decode(s[21:]) for s in retry_call(self.r, args=[self.name, num-1])]
        else:
            ret_val = retry_call(self.r, args=[self.name, 0])
            if ret_val:
                return decode(ret_val[0][21:])
            return None

    def push(self, priority, data, vip=None):
        vip = 0 if vip else 9
        retry_call(self.s, args=[self.name, priority, vip, json.dumps(data)])

    def unpush(self, num=None):
        if num is not None and num <= 0:
            return []

        if num:
            return [decode(s[21:]) for s in retry_call(self.t, args=[self.name, num])]
        else:
            ret_val = retry_call(self.t, args=[self.name, 1])
            if ret_val:
                return decode(ret_val[0][21:])
            return None
