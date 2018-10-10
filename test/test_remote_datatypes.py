import pytest
import time

from redis.exceptions import ConnectionError


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
            assert ct.get_queues() == ['test-counter-t1',
                                       'test-counter-t2']
            assert ct.get_queues_sizes() == {'test-counter-t1': 9,
                                             'test-counter-t2': 39}
            ct.reset_queues()
            assert ct.get_queues_sizes() == {'test-counter-t1': 0,
                                             'test-counter-t2': 0}


# noinspection PyShadowingNames
def test_tacked_counters(redis_connection):
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
            assert ct.get_queues() == ['tracked-test-counter-t1',
                                       'tracked-test-counter-t2']
            assert ct.get_queues_sizes() == {'tracked-test-counter-t1': 9,
                                             'tracked-test-counter-t2': 39}
            ct.reset_queues()
            assert ct.get_queues_sizes() == {'tracked-test-counter-t1': 0,
                                             'tracked-test-counter-t2': 0}


from assemblyline.remote.datatypes.set import ExpiringSet
from assemblyline.remote.datatypes.syncronization import ExclusionWindow
from assemblyline.remote.datatypes.queues.priority import PriorityQueue
from assemblyline.remote.datatypes.queues.dispatch import DispatchQueue
from assemblyline.remote.datatypes.queues.comms import CommsQueue
from assemblyline.remote.datatypes.queues.local import LocalQueue
from assemblyline.remote.datatypes.queues.multi import MultiQueue
from assemblyline.remote.datatypes.queues.named import NamedQueue