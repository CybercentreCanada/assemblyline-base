import json
import redis
import time

from assemblyline.common.exceptions import get_stacktrace_info
from assemblyline.remote.datatypes import get_client, retry_call, log


class MultiQueue(object):
    def __init__(self, host=None, port=None, db=None, private=False):
        self.c = get_client(host, port, db, private)

    def delete(self, name):
        retry_call(self.c.delete, name)

    def pop(self, name, blocking=True, timeout=0):
        if blocking:
            if not timeout:
                response = retry_call(self.c.blpop, name, timeout)
            else:
                try:
                    response = self.c.blpop(name, timeout)
                except redis.ConnectionError as ex:
                    trace = get_stacktrace_info(ex)
                    log.warning('Redis connection error (2): %s', trace)
                    time.sleep(timeout)
                    response = None
        else:
            response = retry_call(self.c.lpop, name)

        if not response:
            return response

        if blocking:
            return json.loads(response[1])
        else:
            return json.loads(response)

    def push(self, name, *messages):
        for message in messages:
            retry_call(self.c.rpush, name, json.dumps(message))

    def length(self, name):
        return retry_call(self.c.llen, name)
