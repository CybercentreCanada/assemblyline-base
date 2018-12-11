import pytest

from assemblyline.odm.models import random_model_obj
from assemblyline.odm.messages.alert_created import AlertCreatedMessage


def test_alert_created_message():
    try:
        random_model_obj(AlertCreatedMessage).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'AlertCreatedMessage' object and validate it.")


