
from assemblyline.remote.datatypes import get_client, retry_call

begin_script = """
local t = redis.call('time')
local key = tonumber(t[1] .. string.format("%06d", t[2]))

local name = ARGV[1]
local max = tonumber(ARGV[2])
local timeout = tonumber(ARGV[3] .. "000000")

redis.call('zremrangebyscore', name, 0, key - timeout)
if redis.call('zcard', name) < max then
    redis.call('zadd', name, key, key)
    return true
else
    return false
end
"""


class UserQuotaTracker(object):
    def __init__(self, prefix, timeout=120, redis=None, host=None, port=None, private=False):
        self.c = redis or get_client(host, port, private)
        self.bs = self.c.register_script(begin_script)
        self.prefix = prefix
        self.timeout = timeout

    def _queue_name(self, user):
        return f"{self.prefix}-{user}"

    def begin(self, user, max_quota):
        return retry_call(self.bs, args=[self._queue_name(user), max_quota, self.timeout]) == 1

    def end(self, user):
        """When only one item is requested, blocking is is possible."""
        retry_call(self.c.zpopmin, self._queue_name(user))
