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


class PubSubWorkerThread(threading.Thread):
    """
    Worker thread that continually reads messages from pubsub.

    We reimplement the worker thread here rather than use the one in the redis
    package because we want to use the subscribe messages for disconnect/reconnect
    detection.
    """

    def __init__(self, watcher, exception_handler=None, skip_first_refresh=True):
        super().__init__(daemon=True)
        self.watcher = watcher
        self.exception_handler = exception_handler
        self._running = threading.Event()
        self.skip_first_refresh = skip_first_refresh

    def run(self):
        if self._running.is_set():
            return
        self._running.set()

        pubsub: PubSub = self.watcher.pubsub
        ping = self.watcher.client.ping
        sleep_time = 1
        initialized = set()

        while self._running.is_set():
            try:
                message = pubsub.get_message(ignore_subscribe_messages=False, timeout=sleep_time)
                if message is not None and message['type'] == 'psubscribe':
                    channel = message.get("channel")
                    if channel is None:
                        continue

                    if self.skip_first_refresh and channel not in initialized:
                        initialized.add(channel)
                        continue

                    handler = pubsub.patterns.get(channel, None)
                    if handler:
                        handler(None)

            except BaseException as exception:
                # Present the error
                logger.error(f"Exception in pubsub watcher: {exception}")

                # Wait until we can reach the server
                retry_call(ping)

        pubsub.close()

    def stop(self):
        # trip the flag so the run loop exits. the run loop will
        # close the pubsub connection, which disconnects the socket
        # and returns the connection to the pool.
        self._running.clear()


class EventWatcher(Generic[MessageType]):
    def __init__(self, host=None, port=None, deserializer: Callable[[str], MessageType] = json.loads):
        self.client: Redis[Any] = get_client(host, port, False)
        self.pubsub = retry_call(self.client.pubsub)
        self.pubsub.ignore_subscribe_messages = False
        self.thread: Optional[PubSubWorkerThread] = None
        self.deserializer = deserializer
        self.skip_first_refresh = True

    def register(self, path: str, callback: Callable[[MessageType | None], None]):
        def _callback(message: Optional[dict[str, Any]]):
            if message is None:
                callback(None)
            elif message['type'] == 'pmessage':
                data = self.deserializer(message.get('data', ''))
                callback(data)
        self.pubsub.psubscribe(**{path.lower(): _callback})

    def start(self):
        self.thread = PubSubWorkerThread(self, skip_first_refresh=self.skip_first_refresh)
        self.thread.start()
        return self.thread

    def stop(self):
        if self.thread is not None:
            self.thread.stop()
