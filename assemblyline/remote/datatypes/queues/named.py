import json
from typing import Generic, TypeVar, Optional
from collections import defaultdict

from assemblyline.remote.datatypes import get_client, retry_call

T = TypeVar('T')


class NamedQueue(Generic[T]):
    def __init__(self, name: str, host=None, port=None, private: bool = False, ttl: int = 0):
        self.c = get_client(host, port, private)
        self.name: str = name
        self.ttl: int = ttl

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.delete()

    def delete(self):
        retry_call(self.c.delete, self.name)

    def __len__(self):
        return self.length()

    def length(self):
        return retry_call(self.c.llen, self.name)

    def peek_next(self) -> Optional[T]:
        response = retry_call(self.c.lrange, self.name, 0, 0)

        if response:
            return json.loads(response[0])
        return None

    def pop_batch(self, size) -> list[T]:
        response = retry_call(self.c.lpop, self.name, size)

        if not response:
            return []
        return [json.loads(r) for r in response]

    def pop(self, blocking: bool = True, timeout: int = 0) -> Optional[T]:
        if blocking:
            response = retry_call(self.c.blpop, self.name, timeout)
        else:
            response = retry_call(self.c.lpop, self.name)

        if not response:
            return response

        if blocking:
            return json.loads(response[1])
        else:
            return json.loads(response)

    def push(self, *messages: T):
        for message in messages:
            retry_call(self.c.rpush, self.name, json.dumps(message))
        if self.ttl:
            retry_call(self.c.expire, self.name, self.ttl)

    def unpop(self, *messages: T):
        """Put all messages passed back at the head of the FIFO queue."""
        for message in messages:
            retry_call(self.c.lpush, self.name, json.dumps(message))
        if self.ttl:
            retry_call(self.c.expire, self.name, self.ttl)


def select(*queues, **kw):
    """
    Do a blocking pop on each queue in sequence.

    Queues that map to the same keyslot will get bundled into the same call.

    This isn't as efficent as it was on a single node. Consider carefully
    the options if you need efficent select over many queues, this probably isn't it.
    """

    timeout = kw.get('timeout', 0)
    if len(queues) < 1:
        raise TypeError('At least one queue must be specified')
    if any([type(q) != NamedQueue for q in queues]):
        raise TypeError('Only NamedQueues supported')

    client = queues[0].c

    if hasattr(client.connection_pool, 'nodes'):
        mapping = defaultdict(list)
        for queue in queues:
            keyslot = client.connection_pool.nodes.keyslot(queue.name)
            mapping[keyslot].append(queue)
    else:
        mapping = {'': queues}

    if len(mapping) == 1:
        response = retry_call(client.blpop, [q.name for q in queues], timeout)

        if not response:
            return response

        return response[0].decode('utf-8'), json.loads(response[1])
    else:
        total = 0
        while total <= timeout or timeout == 0:
            for node_queues in mapping.values():
                total += 1
                response = retry_call(client.blpop, [q.name for q in node_queues], 1)

                if not response:
                    continue

                return response[0].decode('utf-8'), json.loads(response[1])
        return None
