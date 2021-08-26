from __future__ import annotations
import uuid
import time
import enum
import json
from typing import Any
from dataclasses import dataclass, asdict

from assemblyline.remote.datatypes.events import EventSender, EventWatcher

import pytest
from redis import Redis


def test_exact_event(redis_connection: Redis[Any]):
    calls = []

    def _track_call(data):
        calls.append(data)

    try:
        watcher = EventWatcher(redis_connection)
        watcher.register('changes.test', _track_call)
        watcher.start()
        sender = EventSender('changes.', redis_connection)
        start = time.time()

        while len(calls) < 5:
            sender.send('test', {'payload': 100})

            if time.time() - start > 10:
                pytest.fail()
        assert len(calls) >= 5

        for row in calls:
            assert row == {'payload': 100}

    finally:
        watcher.stop()


def test_serialized_event(redis_connection: Redis[Any]):

    class Event(enum.IntEnum):
        ADD = 0
        REM = 1

    @dataclass
    class Message:
        name: str
        event: Event

    def _serialize(message: Message):
        return json.dumps(asdict(message))

    def _deserialize(data: str) -> Message:
        return Message(**json.loads(data))

    calls: list[Message] = []

    def _track_call(data: Message):
        calls.append(data)

    watcher = EventWatcher(redis_connection, deserializer=_deserialize)
    try:
        watcher.register('changes.test', _track_call)
        watcher.start()
        sender = EventSender('changes.', redis_connection, serializer=_serialize)
        start = time.time()

        while len(calls) < 5:
            sender.send('test', Message(name='test', event=Event.ADD))

            if time.time() - start > 10:
                pytest.fail()
        assert len(calls) >= 5

        expected = Message(name='test', event=Event.ADD)
        for row in calls:
            assert row == expected

    finally:
        watcher.stop()


def test_pattern_event(redis_connection):
    calls = []

    def _track_call(data):
        calls.append(data)

    try:
        watcher = EventWatcher(redis_connection)
        watcher.register('changes.*', _track_call)
        watcher.start()
        sender = EventSender('changes.', redis_connection)
        start = time.time()

        while len(calls) < 5:
            sender.send(uuid.uuid4().hex, {'payload': 100})

            if time.time() - start > 10:
                pytest.fail()
        assert len(calls) >= 5

        for row in calls:
            assert row == {'payload': 100}

    finally:
        watcher.stop()

