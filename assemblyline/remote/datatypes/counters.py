from typing import Dict

from redis.exceptions import ConnectionError

from assemblyline.remote.datatypes import get_client, retry_call, now_as_iso
from assemblyline.remote.datatypes.hash import Hash


class Counters(object):
    def __init__(self, prefix="counter", host=None, port=None, db=None, track_counters=False):
        self.c = get_client(host, port, db, False)
        self.prefix = prefix
        if track_counters:
            self.tracker = Hash("c-tracker-%s" % prefix, host=host, port=port, db=db)
        else:
            self.tracker = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.delete()

    def inc(self, name, value=1, track_id=None):
        if self.tracker:
            self.tracker.add(track_id or name, now_as_iso())
        return retry_call(self.c.incr, "%s-%s" % (self.prefix, name), value)

    def dec(self, name, value=1, track_id=None):
        if self.tracker:
            self.tracker.pop(str(track_id or name))
        return retry_call(self.c.decr, "%s-%s" % (self.prefix, name), value)

    def get_queues_sizes(self):
        out = {}
        for queue in retry_call(self.c.keys, "%s-*" % self.prefix):
            queue_size = int(retry_call(self.c.get, queue))
            out[queue] = queue_size

        return {k.decode('utf-8'): v for k, v in out.items()}

    def get_queues(self):
        return [k.decode('utf-8') for k in retry_call(self.c.keys, "%s-*" % self.prefix)]

    def ready(self):
        try:
            self.c.ping()
        except ConnectionError:
            return False

        return True

    def reset_queues(self):
        if self.tracker:
            self.tracker.delete()
        for queue in retry_call(self.c.keys, "%s-*" % self.prefix):
            retry_call(self.c.set, queue, "0")

    def delete(self):
        if self.tracker:
            self.tracker.delete()
        for queue in retry_call(self.c.keys, "%s-*" % self.prefix):
            retry_call(self.c.delete, queue)


# Flush out any values past a certain age
_M_COUNTER_FLUSH = f"""
-- Calculate the first second of the current minute, and previous minute
-- By starting the buffer at the first second of the previous minute, 
-- the buffer should always have 60-120 seconds of data at any given time,
-- letting us take a rolling minute value on demand
local now = redis.call("time")[1]
local current_minute_start = math.floor(now / 60) * 60 
local buffer_start = current_minute_start - 60  

-- Get the full list of data in the table, sort it
local keys = redis.call("hkeys", KEYS[1])
table.sort(keys)

-- Build up the  
local totals = {{}}
local del_keys = {{}}
for _, key in ipairs(keys) do
    key = tonumber(key)
    if key >= buffer_start then
        break
    end
    local minute = math.floor(key/60)*60 
    totals[minute] = (totals[minute] or 0) + (redis.call("hget", KEYS[1], key) or 0)
    table.insert(del_keys, key)
end

-- Clear out the values we have read
if #del_keys > 0 then redis.call("hdel", KEYS[1], unpack(del_keys)) end

-- flatten the table for redis transfer
local out = {{}}
for k, v in pairs(totals) do
    table.insert(out, k)
    table.insert(out, v)
end

return {{out, buffer_start}}
"""

_M_COUNTER_ADVANCE = f"""
local now = redis.call("time")[1]
local current_minute_start = math.floor(now / 60) * 60 
local buffer_start = current_minute_start - 60  
local read_head = tonumber(ARGV[1])

-- A new second isn't available yet
if read_head >= buffer_start then
    return {{{{}}, buffer_start}} 
end

-- Count up the keys we want to read
local keys = {{}}
for value=read_head,buffer_start-1 do
    table.insert(keys, value)
end

local values = redis.call("hmget", KEYS[1], unpack(keys))

-- Build up the totals per minute
local totals = {{}}
for index, key in ipairs(keys) do
    local minute = math.floor(key/60)*60 
    totals[minute] = (totals[minute] or 0) + (values[index] or 0)
end

-- Clear out the values we have read
redis.call("hdel", KEYS[1], unpack(keys))

-- flatten the table for redis transfer
local out = {{}}
for k, v in pairs(totals) do
    table.insert(out, k)
    table.insert(out, v)
end

return {{out, buffer_start}}
"""

# Increment the counter, use server side seconds-since-epoch as the key
_M_COUNTER_INCREMENT = """
local second = redis.call("time")[1]
return redis.call("hincrby", KEYS[1], second, ARGV[1])
"""

# Read the values for the last 60 seconds
_M_COUNTER_READ = f"""
local now = redis.call("time")[1]
local keys = {{}}

for offset = 0,59 do
    table.insert(keys, now-offset)
end

local values = redis.call("hmget", KEYS[1], unpack(keys))

local out = 0
for _, val in pairs(values) do
    out = out + (val or 0)
end

return out 
"""


class MetricCounter:
    """A redis counter that provides a second by second rolling window for the value.

    This class may not be efficient enough yet. But should do for now.
    """
    PREFIX = 'metric-counter-'

    def __init__(self, name, host, db=None, port=None):
        self.client = get_client(host, port, db, False)
        self.path = self.PREFIX + name
        self._inc_script = self.client.register_script(_M_COUNTER_INCREMENT)
        self._flush_script = self.client.register_script(_M_COUNTER_FLUSH)
        self._flush_advance = self.client.register_script(_M_COUNTER_ADVANCE)
        self._read_script = self.client.register_script(_M_COUNTER_READ)
        self.next_block = None

    def delete(self):
        retry_call(self.client.delete, self.path)
        self.next_block = None

    def flush(self) -> Dict[int, int]:
        """"If a reader is starting, flush out values further back than the window size.

        Returns: Mapping from timestamp to count value
        """
        data, self.next_block = retry_call(self._flush_script, keys=[self.path])
        return dict(zip(data[::2], data[1::2]))

    def advance(self) -> Dict[int, int]:
        """Pop out calendar aligned minute(s) worth of data if available.

        Should follow a previous call to flush or advance by a few seconds.
        """
        data, self.next_block = retry_call(self._flush_advance, keys=[self.path], args=[self.next_block])
        return dict(zip(data[::2], data[1::2]))

    def read(self) -> int:
        """A Non-destructive read of the last minute."""
        return retry_call(self._read_script, keys=[self.path])

    def increment(self, increment_by=1) -> int:
        """Add a quantity to the counter.

        Returns the value of the (per second) counter.
        """
        return retry_call(self._inc_script, keys=[self.path], args=[increment_by])
