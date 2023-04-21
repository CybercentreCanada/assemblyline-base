from __future__ import annotations
from typing import Any, Callable, Optional, TYPE_CHECKING, TypeVar, Generic
import json
import logging
import threading

from assemblyline.remote.datatypes import retry_call, get_client

if TYPE_CHECKING:
    from redis import Redis
    from redis.client import PubSub


logger = logging.getLogger(__name__)

MessageType = TypeVar('MessageType')


def _make_logger(watcher: EventWatcher):

    def _exception_logger(exception, pubsub: PubSub, thread):
        # Present the error
        logger.error(f"Exception in pubsub watcher: {exception}")

        # Wait until we can reach the server
        retry_call(watcher.client.ping)

        # Call the handlers so they know to start trying to recover from pubsub desync
        for channel, handler in pubsub.channels.items():
            if handler is not None:
                try:
                    handler(None)
                except Exception:
                    logger.exception(f"Error calling handler for reconnect on {channel}")
        for pattern, handler in pubsub.patterns.items():
            if handler is not None:
                try:
                    handler(None)
                except Exception:
                    logger.exception(f"Error calling handler for reconnect on {pattern}")

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


# class ReconnectNotifyPubsub(PubSub):
#     def __init__(self, *args, **kwargs) -> None:
#         super().__init__(*args, **kwargs)
#         self._first_connect = True

#     def on_connect(self, connection):
#         super().on_connect(connection)

#         if self._first_connect:
#             self._first_connect = False
#             return

#         # Call the handlers so they know to start trying to recover from pubsub desync
#         for channel, handler in self.channels.items():
#             if handler is not None:
#                 try:
#                     handler(None)
#                 except Exception:
#                     logger.exception(f"Error calling handler for reconnect on {channel}")
#         for pattern, handler in self.patterns.items():
#             if handler is not None:
#                 try:
#                     handler(None)
#                 except Exception:
#                     logger.exception(f"Error calling handler for reconnect on {pattern}")


class EventWatcher(Generic[MessageType]):
    def __init__(self, host=None, port=None, deserializer: Callable[[str], MessageType] = json.loads):
        self.client: Redis[Any] = get_client(host, port, False)
        self.pubsub = retry_call(self.client.pubsub)
        self.worker: Optional[threading.Thread] = None
        self.deserializer = deserializer

    def register(self, path: str, callback: Callable[[MessageType | None], None]):
        def _callback(message: Optional[dict[str, Any]]):
            if message is None:
                callable(None)
            elif message['type'] == 'pmessage':
                data = self.deserializer(message.get('data', ''))
                callback(data)
        self.pubsub.psubscribe(**{path.lower(): _callback})

    def start(self):
        self.worker = self.pubsub.run_in_thread(0.01, daemon=True, exception_handler=_make_logger(self))

    def stop(self):
        if self.worker is not None:
            self.worker.stop()
