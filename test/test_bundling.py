import os

from cart import is_cart

from assemblyline.common.bundling import SubmissionAlreadyExist, create_bundle, import_bundle, SubmissionNotFound, \
    AlertNotFound
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.random_data import create_submission
from assemblyline.odm.randomizer import random_model_obj
import pytest

ALERT_ID = "test_alert_id"
SUBMISSION_ID = "test_submission_id"


def test_failed_alert_bundle():
    # Test creation failure
    with pytest.raises(AlertNotFound):
        create_bundle("ThisAlertIDDoesNotExists", use_alert=True)


def test_alert_bundle(datastore_connection, filestore, config):
    # Cleanup previous runs
    datastore_connection.alert.delete(ALERT_ID)

    # Create a temporary submission
    submission = create_submission(datastore_connection, filestore)
    sid = submission['sid']

    # Create a random alert
    alert = random_model_obj(Alert)
    alert.alert_id = ALERT_ID
    alert.sid = sid
    datastore_connection.alert.save(ALERT_ID, alert)

    # Create the submission's bundle
    path = create_bundle(ALERT_ID, use_alert=True)

    # Test if the bundle
    assert os.path.exists(path)
    with open(path, 'rb') as fh:
        assert is_cart(fh.read(256))

    # Remove alert and submission from DB
    datastore_connection.alert.delete(alert.alert_id)
    datastore_connection.delete_submission_tree_bulk(sid, transport=filestore)
    assert datastore_connection.alert.get_if_exists(alert.alert_id) is None
    assert datastore_connection.submission.get_if_exists(sid) is None

    # Restore bundle
    new_submission = import_bundle(path)

    # Validate restored submission
    assert new_submission['sid'] == sid
    assert new_submission['metadata']['bundle.source'] == config.ui.fqdn

    # Validate restored alert
    new_alert = datastore_connection.alert.get_if_exists(alert.alert_id, as_obj=False)
    assert new_alert['alert_id'] == ALERT_ID
    assert new_alert['sid'] == sid
    assert new_alert['metadata']['bundle.source'] == config.ui.fqdn

    # Cleanup
    assert not os.path.exists(path)
    datastore_connection.alert.delete(alert.alert_id)
    datastore_connection.delete_submission_tree_bulk(sid, transport=filestore)
    assert datastore_connection.alert.get_if_exists(alert.alert_id) is None
    assert datastore_connection.submission.get_if_exists(sid) is None


def test_alert_no_submission_bundle(datastore_connection, config):
    # Cleanup previous runs
    datastore_connection.alert.delete(ALERT_ID)
    datastore_connection.submission.delete(SUBMISSION_ID)

    # Create a random alert
    alert = random_model_obj(Alert)
    alert.alert_id = ALERT_ID
    alert.sid = SUBMISSION_ID
    datastore_connection.alert.save(ALERT_ID, alert)

    # Create the submission's bundle
    path = create_bundle(ALERT_ID, use_alert=True)

    # Test if the bundle
    assert os.path.exists(path)
    with open(path, 'rb') as fh:
        assert is_cart(fh.read(256))

    # Remove alert from Datastore
    datastore_connection.alert.delete(alert.alert_id)
    assert datastore_connection.alert.get_if_exists(alert.alert_id) is None
    assert datastore_connection.submission.get_if_exists(alert.sid) is None

    # Restore bundle
    new_submission = import_bundle(path)

    # Validate restored submission
    assert new_submission is None

    # Validate restored alert
    new_alert = datastore_connection.alert.get_if_exists(alert.alert_id)
    assert new_alert['alert_id'] == ALERT_ID
    assert new_alert['sid'] == SUBMISSION_ID
    assert new_alert['metadata']['bundle.source'] == config.ui.fqdn

    # Cleanup
    datastore_connection.alert.delete(ALERT_ID)
    datastore_connection.submission.delete(SUBMISSION_ID)


def test_failed_submission_bundle():
    # Test creation failure
    with pytest.raises(SubmissionNotFound):
        create_bundle("ThisSIDDoesNotExists")


def test_submission_bundle(datastore_connection, filestore, config):
    # Create a temporary submission
    submission = create_submission(datastore_connection, filestore)
    sid = submission['sid']

    # Create the submission's bundle
    path = create_bundle(sid)

    # Test if the bundle
    assert os.path.exists(path)
    with open(path, 'rb') as fh:
        assert is_cart(fh.read(256))

    # Remove submission from DB
    datastore_connection.delete_submission_tree_bulk(sid, transport=filestore)
    assert datastore_connection.submission.get_if_exists(sid) is None

    # Restore bundle
    new_submission = import_bundle(path, cleanup=False)

    # Validate restored submission
    assert new_submission['sid'] == sid
    assert new_submission['metadata']['bundle.source'] == config.ui.fqdn

    # Test inserting failure
    with pytest.raises(SubmissionAlreadyExist):
        import_bundle(path, cleanup=False)

    # Test skip failure on exist
    new_submission = import_bundle(path, exist_ok=True)

    # Validate restored submission
    assert new_submission['sid'] == sid
    assert new_submission['metadata']['bundle.source'] == config.ui.fqdn

    # Cleanup
    assert not os.path.exists(path)
    datastore_connection.delete_submission_tree_bulk(sid, transport=filestore)
    assert datastore_connection.submission.get_if_exists(sid) is None
