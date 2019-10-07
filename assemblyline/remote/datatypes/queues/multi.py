import json

from assemblyline.remote.datatypes import get_client, retry_call


class MultiQueue(object):
    def __init__(self, host=None, port=None, private=False):
        self.c = get_client(host, port, private)

    def delete(self, name):
        retry_call(self.c.delete, name)

    def length(self, name):
        return retry_call(self.c.llen, name)

    def pop(self, name, blocking=True, timeout=0):
        if blocking:
            response = retry_call(self.c.blpop, name, timeout)
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
