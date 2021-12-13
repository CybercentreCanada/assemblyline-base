from __future__ import annotations

import json
import time

from typing import Generic, Optional, TypeVar, Union

from assemblyline.remote.datatypes import get_client, retry_call, decode

SORTING_KEY_LEN = 21

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

T = TypeVar('T')


class PriorityQueue(Generic[T]):
    def __init__(self, name, host=None, port=None, private=False):
        self.c = get_client(host, port, private)
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
            return [decode(s[SORTING_KEY_LEN:]) for s in retry_call(self.c.zpopmin, self.name, num-1)]
        else:
            ret_val = retry_call(self.c.zpopmin, self.name, 0)
            if ret_val:
                return decode(ret_val[0][SORTING_KEY_LEN:])
            return None

    def blocking_pop(self, timeout=0, low_priority=False):
        """When only one item is requested, blocking is is possible."""
        if low_priority:
            result = retry_call(self.c.bzpopmax, self.name, timeout)
        else:
            result = retry_call(self.c.bzpopmin, self.name, timeout)
        if result:
            return decode(result[1][SORTING_KEY_LEN:])
        return None

    def dequeue_range(self, lower_limit='', upper_limit='', skip=0, num=1) -> list[T]:
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
        return [decode(res[SORTING_KEY_LEN:]) for res in results]

    def push(self, priority: int, data: T, vip=None):
        vip = 0 if vip else 9
        return retry_call(self.c.zadd, self.name,
                          {f"{vip}{f'{int(time.time()*1000000):020}'}{json.dumps(data)}": -priority})

    def rank(self, raw_value):
        return retry_call(self.c.zrank, self.name, raw_value)

    def remove(self, raw_value):
        return retry_call(self.c.zrem, self.name, raw_value)

    def unpush(self, num=None) -> Union[list[T], Optional[T]]:
        if num is not None and num <= 0:
            return []

        if num:
            return [decode(s[SORTING_KEY_LEN:]) for s in retry_call(self.c.zpopmax, self.name, num)]
        else:
            ret_val = retry_call(self.c.zpopmax, self.name, 1)
            if ret_val:
                return decode(ret_val[0][SORTING_KEY_LEN:])
            return None


class UniquePriorityQueue(PriorityQueue):
    """A priority queue where duplicate entries will be merged."""

    def __init__(self, name, host=None, port=None, private=False):
        super().__init__(name, host, port, private)

    def remove(self, data: str):
        """Remove a value from the priority  queue."""
        retry_call(self.c.zrem, self.name, json.dumps(data))

    def push(self, priority: int, data, vip=None) -> int:
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
            return [decode(s) for s in retry_call(self.c.zpopmin, self.name, num-1)]
        else:
            ret_val = retry_call(self.c.zpopmin, self.name, 0)
            if ret_val:
                return decode(ret_val[0])
            return None

    def unpush(self, num=None):
        if num is not None and num <= 0:
            return []

        if num:
            return [decode(s) for s in retry_call(self.c.zpopmax, self.name, num)]
        else:
            ret_val = retry_call(self.c.zpopmax, self.name, 1)
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


def select(*queues, **kw):
    timeout = kw.get('timeout', 0)
    if len(queues) < 1:
        raise TypeError('At least one queue must be specified')
    if any([type(q) != PriorityQueue for q in queues]):
        raise TypeError('Only NamedQueues supported')

    c = queues[0].c
    response = retry_call(c.bzpopmin, [q.name for q in queues], timeout)

    if not response:
        return response

    return response[0].decode('utf-8'), json.loads(response[1][SORTING_KEY_LEN:])


def length(*queues: PriorityQueue) -> list[int]:
    """Utility function for batch reading queue lengths."""
    if not queues:
        return []
    pipeline = queues[0].c.pipeline(transaction=False)

    for que in queues:
        pipeline.zcard(que.name)

    return retry_call(pipeline.execute)
