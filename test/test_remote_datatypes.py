import uuid
import time
from threading import Thread

import pytest
from redis.exceptions import ConnectionError

from assemblyline.remote.datatypes.counters import MetricCounter


@pytest.fixture(scope='session')
def redis_connection():
    from assemblyline.remote.datatypes import get_client
    c = get_client(None, None, None, False)
    try:
        ret_val = c.ping()
        if ret_val:
            return c
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
        with ExpiringHash('test-expiring-hashmap', ttl=1) as eh:
            assert eh.add("key", "value") == 1
            assert eh.length() == 1
            time.sleep(1.1)
            assert eh.length() == 0


# noinspection PyShadowingNames
def test_basic_counters(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.counters import Counters
        with Counters('test-counter') as ct:
            ct.delete()

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
            ct.delete()

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
            s.delete()

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
        with ExpiringSet('test-expiring-set', ttl=1) as es:
            es.delete()

            values = ['a', 'b', 1, 2]
            assert es.add(*values) == 4
            assert es.length() == 4
            assert es.exist(values[2])
            for x in es.members():
                assert x in values
            time.sleep(1.1)
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
            pq.delete()

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
            assert pq.length() == 1  # Should be [<100, 5>] at this point

            for x in range(5):
                pq.push(100 + x, x)

            assert pq.length() == 6
            assert pq.dequeue_range(lower_limit=106) == []
            assert pq.length() == 6
            assert pq.dequeue_range(lower_limit=103) == [4]  # 3 and 4 are both options, 4 has higher score
            assert pq.dequeue_range(lower_limit=102, skip=1) == [2]  # 2 and 3 are both options, 3 has higher score, skip it
            assert pq.dequeue_range(upper_limit=100, num=10) == [5, 0]  # Take some off the other end
            assert pq.length() == 2


# noinspection PyShadowingNames
def test_named_queue(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.queues.named import NamedQueue, select
        with NamedQueue('test-named-queue') as nq:
            nq.delete()

            for x in range(5):
                nq.push(x)

            assert nq.length() == 5
            nq.push(*list(range(5)))
            assert nq.length() == 10

            assert nq.peek_next() == nq.pop()
            assert nq.peek_next() == 1
            v = nq.pop()
            assert v == 1
            assert nq.peek_next() == 2
            nq.unpop(v)
            assert nq.peek_next() == 1

            assert select(nq) == ('test-named-queue', 1)

        with NamedQueue('test-named-queue-1') as nq1:
            nq1.delete()

            with NamedQueue('test-named-queue-2') as nq2:
                nq2.delete()

                nq1.push(1)
                nq2.push(2)

                assert select(nq1, nq2) == ('test-named-queue-1', 1)
                assert select(nq1, nq2) == ('test-named-queue-2', 2)


# noinspection PyShadowingNames
def test_multi_queue(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.queues.multi import MultiQueue
        mq = MultiQueue()
        mq.delete('test-multi-q1')
        mq.delete('test-multi-q2')

        for x in range(5):
            mq.push('test-multi-q1', x+1)
            mq.push('test-multi-q2', x+6)

        assert mq.length('test-multi-q1') == 5
        assert mq.length('test-multi-q2') == 5

        assert mq.pop('test-multi-q1') == 1
        assert mq.pop('test-multi-q2') == 6

        assert mq.length('test-multi-q1') == 4
        assert mq.length('test-multi-q2') == 4

        mq.delete('test-multi-q1')
        mq.delete('test-multi-q2')

        assert mq.length('test-multi-q1') == 0
        assert mq.length('test-multi-q2') == 0


# noinspection PyShadowingNames
def test_comms_queue(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.queues.comms import CommsQueue

        def publish_messages(msg_list):
            time.sleep(0.1)
            with CommsQueue('test-comms-queue') as cq:
                for msg in msg_list:
                    cq.publish(msg)

        msg_list = ["bob", 1, {"bob": 1}, [1, 2, 3], None, "Nice!", "stop"]
        t = Thread(target=publish_messages, args=(msg_list,))
        t.start()

        with CommsQueue('test-comms-queue') as cq:
            x = 0
            for msg in cq.listen():
                if msg == "stop":
                    break

                assert msg == msg_list[x]

                x += 1

        t.join()
        assert not t.is_alive()


def test_metric_counter(redis_connection):
    # Flush the counter before starting the test
    test_counter_id = uuid.uuid4().hex
    counter = MetricCounter(test_counter_id, redis_connection)
    counter.delete()
    try:
        local_start = int(time.time())
        redis_start = counter.client.time()[0]


        def server_time(offset: float = 0):
            return int(time.time() - local_start + redis_start + offset)


        # initialize on an empty set, should do nothing, return empty dict
        data = counter.flush()
        assert not data
        assert counter.next_block is not None

        # Call increment properly
        counter.increment(5)

        # Now that there is some data in the counter, we should
        assert test_counter_id in MetricCounter.list_counters(redis_connection)

        # Add a bunch of data directly, but not enough to flush any out
        total = 5
        for offset in range(60):
            total += 5
            counter.client.hincrby(counter.path, server_time(-offset / 2), 5)

        assert counter.read() == total
        assert not counter.advance()
        assert counter.next_block is not None

        # Fill in some old data to simulate backlog
        for offset in range(6000):
            total += 5
            counter.client.hincrby(counter.path, server_time(-offset / 2), 5)

        # Run flush as if we are just starting since we just added data over 3000 seconds in the past
        # we should get around 50 one minute buckets, depending on if we are on the edge of a minute or not
        data = counter.flush()
        assert len(data) in range(45, 55)

        # Fill in some data for the 'newest minute'
        counter.next_block -= 60  # Make the newest minute one that has already passed
        total = 0
        for offset in range(30):
            total += 5
            counter.client.hincrby(counter.path, counter.next_block + offset, 5)

        data = counter.advance()
        assert sum(data.values()) == total
        assert len(data) in [1, 2, 3, 4]
    finally:
        counter.delete()
