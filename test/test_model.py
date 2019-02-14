import pytest

from assemblyline.common import forge
from assemblyline.odm.models.config import DEFAULT_CONFIG, Config
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.filescore import FileScore
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.signature import Signature
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.submission_tree import SubmissionTree
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline.odm.models.workflow import Workflow
from assemblyline.odm.randomizer import random_model_obj


def test_alert_model():
    try:
        random_model_obj(Alert).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Alert' object and validate it.")


def test_config_model():
    try:
        random_model_obj(Config).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Config' object and validate it.")


def test_default_config_model():
    config = forge.get_config()
    assert config.as_primitives() == DEFAULT_CONFIG


def test_error_model():
    try:
        random_model_obj(Error).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Error' object and validate it.")


def test_file_model():
    try:
        random_model_obj(File).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'File' object and validate it.")


def test_filescore_model():
    try:
        random_model_obj(FileScore).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'FileScore' object and validate it.")


def test_result_model():
    try:
        random_model_obj(Result).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Result' object and validate it.")


def test_service_model():
    try:
        random_model_obj(Service).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Service' object and validate it.")


def test_signature_model():
    try:
        random_model_obj(Signature).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Signature' object and validate it.")


def test_submission_model():
    try:
        random_model_obj(Submission).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Submission' object and validate it.")


def test_submission_tree_model():
    try:
        random_model_obj(SubmissionTree).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'SubmissionTree' object and validate it.")


def test_user_model():
    try:
        random_model_obj(User).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'User' object and validate it.")


def test_user_settings_model():
    try:
        random_model_obj(UserSettings).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'UserSettings' object and validate it.")


def test_workflow_model():
    try:
        random_model_obj(Workflow).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Workflow' object and validate it.")
