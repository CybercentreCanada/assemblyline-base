import pytest

from assemblyline.odm.messages.alert import AlertMessage
from assemblyline.odm.messages.controller import ControllerMessage
from assemblyline.odm.messages.dispatcher import DispatcherMessage
from assemblyline.odm.messages.metrics import MetricsMessage
from assemblyline.odm.messages.submission import SubmissionMessage
from assemblyline.odm.models import random_model_obj


def test_alert_message():
    try:
        random_model_obj(AlertMessage).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'AlertMessage' object and validate it.")


def test_controller_message():
    try:
        random_model_obj(ControllerMessage).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'ControllerMessage' object and validate it.")


def test_dispatcher_message():
    try:
        random_model_obj(DispatcherMessage).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'DispatcherMessage' object and validate it.")


def test_metrics_message():
    try:
        random_model_obj(MetricsMessage).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'MetricsMessage' object and validate it.")


def test_submission_message():
    try:
        random_model_obj(SubmissionMessage).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'SubmissionMessage' object and validate it.")
