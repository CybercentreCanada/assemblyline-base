import pytest
import time

from threading import Thread

from assemblyline.common.importing import load_module_by_path
from assemblyline.odm.messages.alert import AlertMessage
from assemblyline.odm.messages.dispatcher_heartbeat import DispatcherMessage
from assemblyline.odm.messages.ingest_heartbeat import IngestMessage
from assemblyline.odm.messages.metrics import MetricsMessage
from assemblyline.odm.messages.service_heartbeat import ServiceMessage
from assemblyline.odm.messages.submission import SubmissionMessage
from assemblyline.odm.messages.task import TaskMessage
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.remote.datatypes.queues.comms import CommsQueue

# noinspection PyUnresolvedReferences
from test.test_remote_datatypes import redis_connection


def publish_message(queue_name, test_message, redis):
    time.sleep(0.1)
    with CommsQueue(queue_name, redis) as cq:
        cq.publish(test_message.as_primitives())


def _test_message_through_queue(queue_name, test_message, redis):
    t = Thread(target=publish_message, args=(queue_name, test_message, redis))

    try:
        t.start()

        with CommsQueue(queue_name) as cq:
            for msg in cq.listen():
                loader_path = msg.get('msg_loader', None)
                if loader_path is None:
                    raise ValueError("Message does not have a message loader class path.")

                msg_obj = load_module_by_path(loader_path)
                obj = msg_obj(msg)

                assert obj == test_message

                break

    finally:
        t.join()
        assert not t.is_alive()


def test_alert_message(redis_connection):
    try:
        _test_message_through_queue('alerts', random_model_obj(AlertMessage), redis_connection)
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'AlertMessage' object and validate it.")


def test_dispatcher_message(redis_connection):
    try:
        _test_message_through_queue('status', random_model_obj(DispatcherMessage), redis_connection)
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'DispatcherMessage' object and validate it.")


def test_ingest_message(redis_connection):
    try:
        _test_message_through_queue('status', random_model_obj(IngestMessage), redis_connection)
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'IngestMessage' object and validate it.")


def test_metrics_message(redis_connection):
    try:
        _test_message_through_queue('metrics', random_model_obj(MetricsMessage), redis_connection)
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'MetricsMessage' object and validate it.")


def test_service_message(redis_connection):
    try:
        _test_message_through_queue('status', random_model_obj(ServiceMessage), redis_connection)
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'ServiceMessage' object and validate it.")


def test_submission_message(redis_connection):
    try:
        _test_message_through_queue('submissions', random_model_obj(SubmissionMessage), redis_connection)
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'SubmissionMessage' object and validate it.")


def test_task_message(redis_connection):
    try:
        _test_message_through_queue('submissions', random_model_obj(TaskMessage), redis_connection)
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'TaskMessage' object and validate it.")
