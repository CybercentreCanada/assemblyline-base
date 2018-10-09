from queue import Queue, Empty


class LocalQueue(Queue):
    # To set a timeout call with timeout=<seconds>.
    def pop(self, blocking=True, **kw):
        try:
            result = self.get(block=blocking, **kw)
        except Empty:
            result = None
        return result

    def push(self, *messages):
        for message in messages:
            self.put(message)


