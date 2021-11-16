
from assemblyline.common.uid import get_random_id
from assemblyline.remote.datatypes import get_client, retry_call

lock_acquire_script = """
local lock_holder = KEYS[1]
local uuid = ARGV[1]
local timeout = ARGV[2]
if redis.call('setnx', lock_holder, uuid) == 1 then
    redis.call('expire', lock_holder, timeout)
    return true
end
return false
"""

lock_release_script = """
local lock_holder = KEYS[1]
local lock_release = KEYS[2]
local uuid = ARGV[1]
if redis.call('get', lock_holder) == uuid then
    redis.call('del', lock_holder)
    redis.call('rpush', lock_release, uuid)
    redis.call('expire', lock_release, 1)
end
"""


class Lock(object):
    def __init__(self, name, timeout, host=None, port=None):
        self.uuid = get_random_id()
        self.c = get_client(host, port, False)
        self.lock_release = f'{{lock-{str(timeout)}-{name}}}-released'
        self.lock_holder = f'{{lock-{str(timeout)}-{name}}}-holder'
        self.timeout = timeout
        self._acquire = self.c.register_script(lock_acquire_script)
        self._release = self.c.register_script(lock_release_script)

    def __enter__(self):
        while not retry_call(self._acquire, keys=[self.lock_holder], args=[self.uuid, self.timeout]):
            retry_call(self.c.blpop, self.lock_release, 1)

    def __exit__(self, unused1, unused2, unused3):
        retry_call(self._release, keys=[self.lock_holder, self.lock_release], args=[self.uuid])
