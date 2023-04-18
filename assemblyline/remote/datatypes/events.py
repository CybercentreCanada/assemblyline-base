from __future__ import annotations
from typing import Any, Callable, Optional, TYPE_CHECKING, TypeVar, Generic
import json
import logging
import threading
import time

from assemblyline.remote.datatypes import retry_call, get_client

if TYPE_CHECKING:
    from redis import Redis


logger = logging.getLogger(__name__)

MessageType = TypeVar('MessageType')


def _make_logger(error_event: Optional[threading.Event]):

    error_count: list[float] = []

    def _exception_logger(exception, pubsub, thread):
        # Track previous error count, throwing out counts older a minute
        nonlocal error_count
        error_count = [e for e in error_count if e > time.time() - 60]
        error_count.append(time.time())
        if error_count:
            error_event.set()

        # Present the error
        logger.error(f"Exception in pubsub watcher: {exception}")

        # sleep if needed
        time.sleep(min(len(error_count) - 1, 5))

    return _exception_logger


class EventSender(Generic[MessageType]):
    def __init__(self, prefix: str, host=None, port=None, private=None,
                 serializer: Callable[[MessageType],
                                      str] = json.dumps):
        self.client: Redis[Any] = get_client(host, port, private)
        self.prefix = prefix.lower()
        if not self.prefix.endswith('.'):
            self.prefix += '.'
        self.serializer = serializer

    def send(self, name: str, data: MessageType):
        path = self.prefix + name.lower().lstrip('.')
        retry_call(self.client.publish, path, self.serializer(data))


class EventWatcher(Generic[MessageType]):
    def __init__(self, host=None, port=None, private=None, deserializer: Callable[[str], MessageType] = json.loads,
                 error_event: Optional[threading.Event] = None):
        client: Redis[Any] = get_client(host, port, private)
        self.pubsub = retry_call(client.pubsub)
        self.worker: Optional[threading.Thread] = None
        self.deserializer = deserializer
        self.error_event = error_event

    def register(self, path: str, callback: Callable[[MessageType], None]):
        def _callback(message: dict[str, Any]):
            if message['type'] == 'pmessage':
                data = self.deserializer(message.get('data', ''))
                callback(data)
        self.pubsub.psubscribe(**{path.lower(): _callback})

    def start(self):
        self.worker = self.pubsub.run_in_thread(0.01, daemon=True, exception_handler=_make_logger(self.error_event))

    def stop(self):
        if self.worker is not None:
            self.worker.stop()
