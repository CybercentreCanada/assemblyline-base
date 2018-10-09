from random import shuffle
from uuid import uuid4

from assemblyline.remote.datatypes import get_client, retry_call

e_enter_script = """
local release_name = ARGV[1]
local waiting_queue = ARGV[2]
local window_holder = ARGV[3]
local timeout = ARGV[4]
if redis.call('setnx', window_holder, release_name) == 1 then
    redis.call('expire', window_holder, timeout)
    return true
end
redis.pcall('rpush', waiting_queue, release_name)
return false
"""

e_exit_script = """
local release_name = ARGV[1]
local waiting_queue = ARGV[2]
local window_holder = ARGV[3]
if redis.call('get', window_holder) ~= release_name then
    return
end
redis.call('del', window_holder)
local waiting_release_names = redis.call('lrange', waiting_queue, 0, -1)
redis.call('del', waiting_queue)
return waiting_release_names
"""


class ExclusionWindow(object):
    def __init__(self, name, seconds, host=None, port=None, db=None):
        uuid = uuid4().get_hex()
        self.c = get_client(host, port, db, False)
        self.release_name = '-'.join(('ew', str(seconds), name, uuid))
        self.waiting_queue = '-'.join(('ew', str(seconds), name, 'waiting'))
        self.window_holder = '-'.join(('ew', str(seconds), name, 'holder'))
        self.seconds = seconds
        self._aquire = self.c.register_script(e_enter_script)
        self._release = self.c.register_script(e_exit_script)

    def __enter__(self):
        while not retry_call(self._aquire, args=[
            self.release_name, self.waiting_queue, self.window_holder,
            self.seconds,
        ]):
            retry_call(self.c.blpop, self.release_name, self.seconds)

    def __exit__(self, unused1, unused2, unused3):
        queue_names = retry_call(self._release, args=[
            self.release_name, self.waiting_queue, self.window_holder
        ])
        if not queue_names:
            return
        shuffle(queue_names)
        for queue_name in queue_names:
            retry_call(self.c.rpush, queue_name, True)
