import pytest

from assemblyline.common import forge
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.badlist import Badlist
from assemblyline.odm.models.cached_file import CachedFile
from assemblyline.odm.models.config import DEFAULT_CONFIG, Config
from assemblyline.odm.models.emptyresult import EmptyResult
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.filescore import FileScore
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.service_delta import ServiceDelta
from assemblyline.odm.models.signature import Signature
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.submission_summary import SubmissionSummary
from assemblyline.odm.models.submission_tree import SubmissionTree
from assemblyline.odm.models.tagging import Tagging
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_favorites import UserFavorites
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline.odm.models.safelist import Safelist
from assemblyline.odm.models.workflow import Workflow
from assemblyline.odm.randomizer import random_model_obj, random_minimal_obj


def test_alert_model():
    try:
        random_model_obj(Alert).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Alert' object and validate it.")


def test_badlist_model():
    try:
        random_model_obj(Badlist).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Badlist' object and validate it.")


def test_cached_file_model():
    try:
        random_model_obj(CachedFile).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'CachedFile' object and validate it.")


def test_config_model():
    try:
        random_model_obj(Config).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Config' object and validate it.")


def test_default_config_model():
    config = forge.get_config(yml_config="/etc/assemblyline/default.yml")
    assert config.as_primitives() == Config(DEFAULT_CONFIG).as_primitives()


def test_emptyresult_model():
    try:
        random_model_obj(EmptyResult).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'EmptyResult' object and validate it.")


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


def test_heuristic_model():
    try:
        random_model_obj(Heuristic).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Heuristic' object and validate it.")


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


def test_service_delta_model():
    try:
        random_model_obj(ServiceDelta).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'ServiceDelta' object and validate it.")


def test_service_to_service_delta_model():
    try:
        data = random_model_obj(Service).as_primitives()
        ServiceDelta(data).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not use a 'Service' object to create a 'ServiceDelta' object.")


def test_service_delta_to_service_model():
    try:
        data = random_model_obj(ServiceDelta).as_primitives()
        Service(data).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not use a 'ServiceDelta' object to create a 'Service' object.")


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


def test_submission_summary_model():
    try:
        random_model_obj(SubmissionSummary).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'SubmissionSummary' object and validate it.")


def test_submission_tree_model():
    try:
        random_model_obj(SubmissionTree).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'SubmissionTree' object and validate it.")


def test_tagging_model():
    try:
        random_model_obj(Tagging).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Tagging' object and validate it.")


def test_user_model():
    try:
        random_model_obj(User).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'User' object and validate it.")


def test_user_favorites_model():
    try:
        random_model_obj(UserFavorites).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'UserFavorites' object and validate it.")


def test_user_settings_model():
    try:
        random_model_obj(UserSettings).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'UserSettings' object and validate it.")


def test_safelist_model():
    try:
        random_model_obj(Safelist).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Safelist' object and validate it.")


def test_workflow_model():
    try:
        random_model_obj(Workflow).as_primitives()
    except (ValueError, TypeError, KeyError):
        pytest.fail("Could not generate 'Workflow' object and validate it.")


def test_update_alert():
    import time
    import assemblyline.odm.models.alert
    from assemblyline.odm.models.alert import Event

    ea = Event(dict(
        entity_type='user',
        entity_id='abc123',
        entity_name='abc123',
        labels=['1', '2'],
        status='MALICIOUS',
        priority='LOW',
    ))

    eb = Event(dict(
        entity_type='user',
        entity_id='abc123',
        entity_name='abc123',
        labels=[],
        status='MALICIOUS',
        priority='LOW',
    ))

    a1 = Alert(dict(
        alert_id='abc',
        al=dict(
            detailed=dict(
                yara=[dict(
                    type='tests',
                    value='yara-1',
                    verdict='safe',
                )]
            ),
            request_end_time=0,
            score=0,
            yara=["yara-1"]
        ),
        attack=dict(),
        classification='U',
        extended_scan='submitted',
        file=random_minimal_obj(assemblyline.odm.models.alert.File),
        heuristic=dict(),
        owner='user',
        reporting_ts=100,
        submission_relations=[dict(parent=None, child='abc123')],
        sid='abc123',
        ts=100,
        type='big',
        events=[ea],
    ))

    a2 = Alert(dict(
        alert_id='abc',
        al=dict(
            detailed=dict(
                yara=[dict(
                    type='tests',
                    value='yara-1',
                    verdict='safe',
                ), dict(
                    type='tests',
                    value='yara-2',
                    verdict='safe',
                )]
            ),
            request_end_time=500,
            score=0,
            yara=['yara-1', 'yara-2']
        ),
        attack=dict(),
        classification='U',
        extended_scan='completed',
        file=a1.file,
        heuristic=dict(),
        owner='user',
        reporting_ts=100,
        submission_relations=[dict(parent='abc123', child='abc1234')],
        sid='abc1234',
        ts=100,
        type='big',
        events=[ea, eb],
    ))

    o1 = Alert(a1.as_primitives())
    o2 = Alert(a2.as_primitives())

    assert a1.al.yara == ['yara-1']
    assert sorted(a2.al.yara) == ['yara-1', 'yara-2']
    assert a1.al.detailed.yara == [dict(type='tests', value='yara-1', verdict='safe')]
    assert sorted(a2.al.detailed.yara) == [dict(type='tests', value='yara-1', verdict='safe'), dict(type='tests', value='yara-2', verdict='safe')]
    assert a1.sid == 'abc123'

    a1.update(a2)

    assert sorted(a1.al.yara) == ['yara-1', 'yara-2']
    assert sorted(a1.al.detailed.yara) == [dict(type='tests', value='yara-1', verdict='safe'), dict(type='tests', value='yara-2', verdict='safe')]
    assert a1.sid == 'abc1234'

    o2.update(o1)

    # Submission relations might be out of order after update, so test them independently
    a1, o2 = a1.as_primitives(), o2.as_primitives()
    a1_sub_rel, o2_sub_rel = a1.pop('submission_relations'), o2.pop('submission_relations')
    assert len(a1_sub_rel) == len(o2_sub_rel)
    for rel in a1_sub_rel:
        assert rel in o2_sub_rel

    # Compare the rest of the alert properties
    assert a1 == o2
