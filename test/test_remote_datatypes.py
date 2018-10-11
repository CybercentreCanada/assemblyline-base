import pytest
import time

from redis.exceptions import ConnectionError
from threading import Thread


@pytest.fixture
def redis_connection():
    from assemblyline.remote.datatypes import get_client
    c = get_client(None, None, None, False)
    try:
        ret_val = c.ping()
        if ret_val:
            return True
    except ConnectionError:
        pass

    return pytest.skip("Connection to the Redis server failed. This test cannot be performed...")


# noinspection PyShadowingNames
def test_hash(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.hash import Hash
        with Hash('test-hashmap') as h:
            assert h.add("key", "value") == 1
            assert h.exists("key") == 1
            assert h.get("key") == "value"
            assert h.set("key", "new-value") == 0
            assert h.keys() == ["key"]
            assert h.length() == 1
            assert h.items() == {"key": "new-value"}
            assert h.pop("key") == "new-value"
            assert h.length() == 0


# noinspection PyShadowingNames
def test_expiring_hash(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.hash import ExpiringHash
        with ExpiringHash('test-expiring-hashmap', ttl=2) as eh:
            assert eh.add("key", "value") == 1
            assert eh.length() == 1
            time.sleep(2)
            assert eh.length() == 0


# noinspection PyShadowingNames
def test_basic_counters(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.counters import Counters
        with Counters('test-counter') as ct:
            for x in range(10):
                ct.inc('t1')
            for x in range(20):
                ct.inc('t2', value=2)
            ct.dec('t1')
            ct.dec('t2')
            assert sorted(ct.get_queues()) == ['test-counter-t1',
                                               'test-counter-t2']
            assert ct.get_queues_sizes() == {'test-counter-t1': 9,
                                             'test-counter-t2': 39}
            ct.reset_queues()
            assert ct.get_queues_sizes() == {'test-counter-t1': 0,
                                             'test-counter-t2': 0}


# noinspection PyShadowingNames
def test_tracked_counters(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.counters import Counters
        with Counters('tracked-test-counter', track_counters=True) as ct:
            for x in range(10):
                ct.inc('t1')
            for x in range(20):
                ct.inc('t2', value=2)
            assert ct.tracker.keys() == ['t1', 't2']
            ct.dec('t1')
            ct.dec('t2')
            assert ct.tracker.keys() == []
            assert sorted(ct.get_queues()) == ['tracked-test-counter-t1',
                                               'tracked-test-counter-t2']
            assert ct.get_queues_sizes() == {'tracked-test-counter-t1': 9,
                                             'tracked-test-counter-t2': 39}
            ct.reset_queues()
            assert ct.get_queues_sizes() == {'tracked-test-counter-t1': 0,
                                             'tracked-test-counter-t2': 0}


# noinspection PyShadowingNames
def test_sets(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.set import Set
        with Set('test-set') as s:
            values = ['a', 'b', 1, 2]
            assert s.add(*values) == 4
            assert s.length() == 4
            for x in s.members():
                assert x in values
            assert s.random() in values
            assert s.exist(values[2])
            s.remove(values[2])
            assert not s.exist(values[2])
            pop_val = s.pop()
            assert pop_val in values
            assert not s.exist(pop_val)
            assert s.length() == 2


# noinspection PyShadowingNames
def test_expiring_sets(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.set import ExpiringSet
        with ExpiringSet('test-expiring-set', ttl=2) as es:
            values = ['a', 'b', 1, 2]
            assert es.add(*values) == 4
            assert es.length() == 4
            assert es.exist(values[2])
            for x in es.members():
                assert x in values
            time.sleep(2)
            assert es.length() == 0
            assert not es.exist(values[2])


# noinspection PyShadowingNames
def test_lock(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.lock import Lock

        def locked_execution(next_thread=None):
            with Lock('test', 10):
                if next_thread:
                    next_thread.start()
                time.sleep(2)

        t2 = Thread(target=locked_execution)
        t1 = Thread(target=locked_execution, args=(t2,))
        t1.start()

        time.sleep(1)
        assert t1.is_alive()
        assert t2.is_alive()
        time.sleep(2)
        assert not t1.is_alive()
        assert t2.is_alive()
        time.sleep(2)
        assert not t1.is_alive()
        assert not t2.is_alive()


# noinspection PyShadowingNames
def test_priority_queue(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.queues.priority import PriorityQueue
        with PriorityQueue('test-priority-queue') as pq:
            for x in range(10):
                pq.push(100, x)

            pq.push(101, 'a')
            pq.push(99, 'z')

            assert pq.pop() == 'a'
            assert pq.unpush() == 'z'
            assert pq.count(100, 100) == 10
            assert pq.pop() == 0
            assert pq.unpush() == 9
            assert pq.length() == 8
            assert pq.pop(4) == [1, 2, 3, 4]
            assert pq.unpush(3) == [6, 7, 8]
            assert pq.length() == 1

from assemblyline.remote.datatypes.queues.dispatch import DispatchQueue
from assemblyline.remote.datatypes.queues.comms import CommsQueue
from assemblyline.remote.datatypes.queues.local import LocalQueue
from assemblyline.remote.datatypes.queues.multi import MultiQueue
from assemblyline.remote.datatypes.queues.named import NamedQueue