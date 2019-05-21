from math import floor

from redis.exceptions import ConnectionError

from assemblyline.common import forge
from assemblyline.common.chunk import chunked_list
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


_M_COUNTER_POP_EXPIRED = """
local now = redis.call("time")[1]
local cur_minute = (math.floor(now / 60) * 60)
local window = cur_minute - 60
local values = redis.call('hgetall' , KEYS[1])
if values == nil then
    values = {{}}
end

redis.call('del', KEYS[1])

for idx = 1, #values, 2 do 
    if tonumber(values[idx]) >= window then
        redis.call("hset", KEYS[1], values[idx], values[idx + 1])
    end
end

return {window, values}
"""

# Increment the counter, use server side seconds-since-epoch as the key
_M_COUNTER_INCREMENT = """
local second = redis.call("time")[1]
return redis.call("hincrby", KEYS[1], second, ARGV[1])
"""

# Read the values for the last 60 seconds
_M_COUNTER_READ = """
local now = redis.call("time")[1]
local keys = {}

for offset = 0,59 do
    table.insert(keys, now-offset)
end

local values = redis.call("hmget", KEYS[1], unpack(keys))

local out = 0
for idx = 1, #values do
    out = out + (values[idx] or 0)
end

return out
"""


class MetricCounter:
    """A redis counter that provides a second by second rolling window for the value.

    This class may not be efficient enough yet. But should do for now.
    """
    PREFIX = 'metrics.counter.'

    def __init__(self, name, host=None, db=None, port=None):
        self.client = get_client(host, port, db, False)
        self.path = self.PREFIX + name
        self._inc_script = self.client.register_script(_M_COUNTER_INCREMENT)
        self._pop_old = self.client.register_script(_M_COUNTER_POP_EXPIRED)
        self._read_script = self.client.register_script(_M_COUNTER_READ)

    def get_server_time(self):
        return self.client.time()[0]

    def get_current_minute(self):
        return floor(self.client.time()[0] / 60) * 60

    def reset(self):
        retry_call(self.client.delete, self.path)

    def pop_expired(self):
        """
        Pop out calendar aligned minute(s) worth of data that is outside the runnning window to move it to the metrics
        elasticsearch instance
        """

        time_window, data = retry_call(self._pop_old, keys=[self.path])
        filtered = [(int(x[0]), int(x[1])) for x in chunked_list(data, 2) if int(x[0]) < time_window]
        out = {}
        for ts, count in filtered:
            c_ts = floor(ts / 60) * 60
            if c_ts not in out:
                out[c_ts] = count
            else:
                out[c_ts] += count

        return out

    def read(self) -> int:
        """A Non-destructive read of the last minute."""
        return retry_call(self._read_script, keys=[self.path])

    def increment(self, increment_by=1) -> int:
        """Add a quantity to the counter.

        Returns the value of the (per second) counter.
        """
        return retry_call(self._inc_script, keys=[self.path], args=[increment_by])

    def increment_execution_time(self, execution_time) -> int:
        """Add a quantity to the counter.

        Returns the value of the (per second) counter.
        """
        retry_call(self._inc_script, keys=[f"{self.path}.c"], args=[1])
        return retry_call(self._inc_script, keys=[f"{self.path}.t"], args=[execution_time])

    @classmethod
    def list_counters(cls, redis):
        """List all active counters on a redis server.

        Note: active means they have some count values CURRENTLY.
        """
        data = retry_call(redis.keys, cls.PREFIX + '*')
        pre = len(cls.PREFIX)
        return [key[pre:].decode() for key in data]


class MetricsCounterAggregator(object):
    def __init__(self, metrics_type, name=None, config=None, redis=None):
        self.config = config or forge.get_config()
        self.redis = redis or get_client(
            self.config.core.metrics.redis.host,
            self.config.core.metrics.redis.port,
            self.config.core.metrics.redis.db,
            False
        )
        self.counter_cache = {}
        self.metrics_type = metrics_type
        self.name = name or metrics_type

    def _init_counter(self, name):
        self.counter_cache[name] = MetricCounter(f"{self.metrics_type}.{self.name}.{name}", self.redis)

    def stop(self):
        self.counter_cache = {}

    def increment(self, name, increment_by=1):
        if name not in self.counter_cache:
            self._init_counter(name)

        self.counter_cache[name].increment(increment_by)

    def increment_execution_time(self, name, execution_time):
        if f"{name}.c" not in self.counter_cache:
            self._init_counter(f"{name}.c")

        self.counter_cache[f"{name}.c"].increment()

        if f"{name}.t" not in self.counter_cache:
            self._init_counter(f"{name}.t")

        self.counter_cache[f"{name}.t"].increment(execution_time)
