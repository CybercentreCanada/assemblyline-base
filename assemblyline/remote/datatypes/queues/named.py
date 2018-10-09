import json
import time
import redis

from assemblyline.common.exceptions import get_stacktrace_info
from assemblyline.remote.datatypes import get_client, retry_call, log


class NamedQueue(object):
    def __init__(
        self, name, host=None, port=None, db=None, private=False, ttl=0
    ):
        self.c = get_client(host, port, db, private)
        self.name = name
        self.ttl = ttl

    def delete(self):
        retry_call(self.c.delete, self.name)

    def length(self):
        return retry_call(self.c.llen, self.name)

    def peek_next(self):
        response = retry_call(self.c.lrange, self.name, 0, 0)

        if not response:
            return None
        else:
            return json.loads(response[0])

    def pop(self, blocking=True, timeout=0):
        if blocking:
            if not timeout:
                response = retry_call(self.c.blpop, self.name, timeout)
            else:
                try:
                    response = self.c.blpop(self.name, timeout)
                except redis.ConnectionError as ex:
                    trace = get_stacktrace_info(ex)
                    log.info('Redis connection error (3): %s', trace)
                    time.sleep(timeout)
                    response = None
        else:
            response = retry_call(self.c.lpop, self.name)

        if not response:
            return response

        if blocking:
            return json.loads(response[1])
        else:
            return json.loads(response)

    def push(self, *messages):
        for message in messages:
            retry_call(self.c.rpush, self.name, json.dumps(message))
        if self.ttl:
            retry_call(self.c.expire, self.name, self.ttl)

    def unpop(self, *messages):
        """Put all messages passed back at the head of the FIFO queue."""
        for message in messages:
            retry_call(self.c.lpush, self.name, json.dumps(message))
        if self.ttl:
            retry_call(self.c.expire, self.name, self.ttl)


def select(*queues, **kw):
    timeout = kw.get('timeout', 0)
    if len(queues) < 1:
        raise TypeError('At least one queue must be specified')
    if any([type(q) != NamedQueue for q in queues]):
        raise TypeError('Only NamedQueues supported')

    c = queues[0].c
    # TODO: Can we compare two StrictRedis instances for equality?
    #       (Queues are back to having their own StrictRedis instance).
    # if any([q.c != c for q in queues[1:]]):
    #    raise ValueError('All queues must share a client')

    if not timeout:
        response = retry_call(c.blpop, [q.name for q in queues], timeout)
    else:
        try:
            response = c.blpop([q.name for q in queues], timeout)
        except redis.ConnectionError as ex:
            trace = get_stacktrace_info(ex)
            log.warning('Redis connection error (4): %s', trace)
            time.sleep(timeout)
            response = None

    if not response:
        return response

    return response[0], json.loads(response[1])


