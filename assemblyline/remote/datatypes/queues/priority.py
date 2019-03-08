import json

from assemblyline.remote.datatypes import get_client, retry_call, decode

# Work around for inconsistency between ZRANGEBYSCORE and ZREMRANGEBYSCORE
#   (No limit option available or we would just be using that directly)
#
# args:
#   minimum score to pop
#   maximum score to pop
#   number of elements to skip before popping any
#   max element count to pop
pq_dequeue_range_script = """
local unpack = table.unpack or unpack
local min_score = tonumber(ARGV[1]); 
if min_score == nil then min_score = -math.huge end
local max_score = tonumber(ARGV[2]);
if max_score == nil then max_score = math.huge end 
local rem_offset = tonumber(ARGV[3]); 
local rem_limit = tonumber(ARGV[4]); 

local entries = redis.call("zrangebyscore", KEYS[1], -max_score, -min_score, "limit", rem_offset, rem_limit);
if #entries > 0 then redis.call("zrem", KEYS[1], unpack(entries)) end
return entries 
"""


# ARGV[1]: <queue name>
# ARGV[2]: <max items to pop minus one>
pq_pop_script = """
local result = redis.call('zrange', ARGV[1], 0, ARGV[2])
if result then redis.call('zremrangebyrank', ARGV[1], 0, ARGV[2]) end
return result
"""

# ARGV[1]: <queue name>
# ARGV[2]: <priority>
# ARGV[3]: <vip>,
# ARGV[4]: <item (string) to push>
pq_push_script = """
local seq = string.format('%020d', redis.call('incr', 'global-sequence'))
local vip = string.format('%1d', ARGV[3])
redis.call('zadd', ARGV[1], 0 - ARGV[2], vip..seq..ARGV[4])
"""

# ARGV[1]: <queue name>
# ARGV[2]: <max items to unpush>
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
        self._deque_range = self.c.register_script(pq_dequeue_range_script)
        self.name = name

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.delete()

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

    def dequeue_range(self, lower_limit='', upper_limit='', skip=0, num=1):
        """Dequeue a number of elements, within a specified range of scores.

        Limits given are inclusive, can be made exclusive, see redis docs on how to format limits for that.

        NOTE: lower/upper limit is negated+swapped in the lua script, no need to do it here

        :param lower_limit: The score of all dequeued elements must be higher or equal to this.
        :param upper_limit: The score of all dequeued elements must be lower or equal to this.
        :param skip: In the range of available items to dequeue skip over this many.
        :param num: Maximum number of elements to dequeue.
        :return: list
        """
        results = retry_call(self._deque_range, keys=[self.name], args=[lower_limit, upper_limit, skip, num])
        return [decode(res[21:]) for res in results]

    def push(self, priority: int, data, vip=None):
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


class UniquePriorityQueue(PriorityQueue):
    """A priority queue where duplicate entries will be merged."""

    def __init__(self, name, host=None, port=None, db=None, private=False):
        super().__init__(name, host, port, db, private)
        del self.s

    def remove(self, data: str):
        """Remove a value from the priority  queue."""
        retry_call(self.c.zrem, self.name, json.dumps(data))

    def push(self, priority: int, data) -> int:
        """Add or update elements in the priority queue.

        Existing elements will have their priority updated.

        Returns:
            Number of _NEW_ elements in the queue after the operation.
        """
        return retry_call(self.c.zadd, self.name, {json.dumps(data): -priority})

    def pop(self, num=None):
        if num is not None and num <= 0:
            return []

        if num:
            return [decode(s) for s in retry_call(self.r, args=[self.name, num-1])]
        else:
            ret_val = retry_call(self.r, args=[self.name, 0])
            if ret_val:
                return decode(ret_val[0])
            return None

    def unpush(self, num=None):
        if num is not None and num <= 0:
            return []

        if num:
            return [decode(s) for s in retry_call(self.t, args=[self.name, num])]
        else:
            ret_val = retry_call(self.t, args=[self.name, 1])
            if ret_val:
                return decode(ret_val[0])
            return None

    def dequeue_range(self, lower_limit='', upper_limit='', skip=0, num=1):
        """Dequeue a number of elements, within a specified range of scores.

        Limits given are inclusive, can be made exclusive, see redis docs on how to format limits for that.

        NOTE: lower/upper limit is negated+swapped in the lua script, no need to do it here

        :param lower_limit: The score of all dequeued elements must be higher or equal to this.
        :param upper_limit: The score of all dequeued elements must be lower or equal to this.
        :param skip: In the range of available items to dequeue skip over this many.
        :param num: Maximum number of elements to dequeue.
        :return: list
        """
        results = retry_call(self._deque_range, keys=[self.name], args=[lower_limit, upper_limit, skip, num])
        return [decode(res) for res in results]
