import pytest

from assemblyline.odm.models import random_model_obj
from assemblyline.odm.messages.alert import AlertMessage
from assemblyline.odm.messages.metrics import MetricsMessage
from assemblyline.odm.messages.submission import SubmissionMessage


def test_alert_created_message():
    try:
        random_model_obj(AlertMessage).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'AlertMessage' object and validate it.")


def test_metrics_message():
    try:
        random_model_obj(MetricsMessage).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'MetricsMessage' object and validate it.")


def test_submission_started_message():
    try:
        random_model_obj(SubmissionMessage).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'SubmissionMessage' object and validate it.")
