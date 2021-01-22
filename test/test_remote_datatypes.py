
import time

from threading import Thread

from assemblyline.common.uid import get_random_id


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

            # Make sure we can limit the size of a hash table
            assert h.limited_add("a", 1, 2) == 1
            assert h.limited_add("a", 1, 2) == 0
            assert h.length() == 1
            assert h.limited_add("b", 10, 2) == 1
            assert h.length() == 2
            assert h.limited_add("c", 1, 2) is None
            assert h.length() == 2
            assert h.pop("a")

            # Can we increment integer values in the hash
            assert h.increment("a") == 1
            assert h.increment("a") == 2
            assert h.increment("a", 10) == 12
            assert h.increment("a", -22) == -10


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

            assert s.limited_add('dog', 3)
            assert not s.limited_add('cat', 3)
            assert s.exist('dog')
            assert not s.exist('cat')
            assert s.length() == 3


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


# noinspection PyShadowingNames,PyUnusedLocal
def test_priority_queue(redis_connection):
    from assemblyline.remote.datatypes.queues.priority import PriorityQueue
    with PriorityQueue('test-priority-queue') as pq:
        pq.delete()

        for x in range(10):
            pq.push(100, x)

        a_key = pq.push(101, 'a')
        z_key = pq.push(99, 'z')
        assert pq.rank(a_key) == 0
        assert pq.rank(z_key) == pq.length() - 1

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
        pq.pop(2)

        pq.push(50, 'first')
        pq.push(-50, 'second')

        assert pq.dequeue_range(0, 100) == ['first']
        assert pq.dequeue_range(-100, 0) == ['second']


# noinspection PyShadowingNames,PyUnusedLocal
def test_unique_priority_queue(redis_connection):
    from assemblyline.remote.datatypes.queues.priority import UniquePriorityQueue
    with UniquePriorityQueue('test-priority-queue') as pq:
        pq.delete()

        for x in range(10):
            pq.push(100, x)
        assert pq.length() == 10

        # Values should be unique, this should have no effect on the length
        for x in range(10):
            pq.push(100, x)
        assert pq.length() == 10

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
        assert sorted(pq.dequeue_range(upper_limit=100, num=10)) == [0, 5]  # Take some off the other end
        assert pq.length() == 2
        pq.pop(2)

        pq.push(50, 'first')
        pq.push(-50, 'second')

        assert pq.dequeue_range(0, 100) == ['first']
        assert pq.dequeue_range(-100, 0) == ['second']


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

        def publish_messages(message_list):
            time.sleep(0.1)
            with CommsQueue('test-comms-queue') as cq_p:
                for message in message_list:
                    cq_p.publish(message)

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


# noinspection PyShadowingNames
def test_user_quota_tracker(redis_connection):
    if redis_connection:
        from assemblyline.remote.datatypes.user_quota_tracker import UserQuotaTracker

        max_quota = 3
        timeout = 2
        name = get_random_id()
        uqt = UserQuotaTracker('test-quota', timeout=timeout)

        # First 0 to max_quota items should succeed
        for _ in range(max_quota):
            assert uqt.begin(name, max_quota) is True

        # All other items should fail until items timeout
        for _ in range(max_quota):
            assert uqt.begin(name, max_quota) is False

        # if you remove and item only one should be able to go in
        uqt.end(name)
        assert uqt.begin(name, max_quota) is True
        assert uqt.begin(name, max_quota) is False

        # if you wait the timeout, all items can go in
        time.sleep(timeout+1)
        for _ in range(max_quota):
            assert uqt.begin(name, max_quota) is True
