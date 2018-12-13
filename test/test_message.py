import pytest
import time

from threading import Thread

from assemblyline.common.importing import load_module_by_path
from assemblyline.odm.messages.alert import AlertMessage
from assemblyline.odm.messages.controller import ControllerMessage
from assemblyline.odm.messages.dispatcher import DispatcherMessage
from assemblyline.odm.messages.ingest import IngestMessage
from assemblyline.odm.messages.metrics import MetricsMessage
from assemblyline.odm.messages.service import ServiceMessage
from assemblyline.odm.messages.submission import SubmissionMessage
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.remote.datatypes.queues.comms import CommsQueue


def publish_message(queue_name, test_message):
    time.sleep(0.1)
    with CommsQueue(queue_name) as cq:
        cq.publish(test_message.as_primitives())


def _test_message_through_queue(queue_name, test_message):
    t = Thread(target=publish_message, args=(queue_name, test_message))

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


def test_alert_message():
    try:
        _test_message_through_queue('alerts', random_model_obj(AlertMessage))
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'AlertMessage' object and validate it.")


def test_controller_message():
    try:
        _test_message_through_queue('status', random_model_obj(ControllerMessage))
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'ControllerMessage' object and validate it.")


def test_dispatcher_message():
    try:
        _test_message_through_queue('status', random_model_obj(DispatcherMessage))
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'DispatcherMessage' object and validate it.")


def test_ingest_message():
    try:
        _test_message_through_queue('status', random_model_obj(IngestMessage))
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'IngestMessage' object and validate it.")


def test_metrics_message():
    try:
        _test_message_through_queue('metrics', random_model_obj(MetricsMessage))
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'MetricsMessage' object and validate it.")


def test_service_message():
    try:
        _test_message_through_queue('status', random_model_obj(ServiceMessage))
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'ServiceMessage' object and validate it.")


def test_submission_message():
    try:
        _test_message_through_queue('submissions', random_model_obj(SubmissionMessage))
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'SubmissionMessage' object and validate it.")
