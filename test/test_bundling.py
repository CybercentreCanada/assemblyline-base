import json
import os
import tarfile
from io import BytesIO
from itertools import product

import pytest
from assemblyline.common.bundling import (
    AlertNotFound,
    SubmissionAlreadyExist,
    SubmissionNotFound,
    create_bundle,
    import_bundle,
)
from assemblyline.common.forge import get_classification
from assemblyline.common.isotime import format_time
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.random_data import create_submission
from assemblyline.odm.randomizer import random_model_obj
from cart import is_cart, unpack_stream

ALERT_ID = "test_alert_id"
SUBMISSION_ID = "test_submission_id"
CLASSIFICATION = get_classification()

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


@pytest.mark.parametrize("as_user,dtl", list(product([False, True], [None, 1])),
                         ids=[f"as_user:{as_user},dtl:{dtl}" for as_user, dtl in product([False, True], [None, 1])])
def test_submission_bundle(datastore_connection, filestore, config, as_user, dtl):
    # Create a temporary submission
    submission = create_submission(datastore_connection, filestore)
    sid = submission['sid']
    original_expiry_ts = submission['expiry_ts']
    user_classification = None
    if as_user:
        # Update classification to match the submission's (since they can at the very least view the submission)
        user_classification = submission['classification'].value

    # Create the submission's bundle
    path = create_bundle(sid, user_classification=user_classification)

    # Test if the bundle
    assert os.path.exists(path)
    with open(path, 'rb') as fh:
        assert is_cart(fh.read(256))

    # Remove submission from DB
    datastore_connection.delete_submission_tree_bulk(sid, transport=filestore)
    assert datastore_connection.submission.get_if_exists(sid) is None

    # Assert that all data exported as a bundle is accessible to that user
    if as_user:
        with BytesIO() as uncarted_bundle:
            # Un-cart file to get the actual tar file
            with open(path, 'rb') as carted_fp:
                unpack_stream(carted_fp, uncarted_bundle)

            uncarted_bundle.seek(0)
            with tarfile.open(fileobj=uncarted_bundle, mode="r:gz") as tar_file:
                results = json.load(tar_file.extractfile("results.json"))

                # Ensure the user has access to the submission
                assert CLASSIFICATION.is_accessible(user_classification, results['submission']['classification'])

                # Ensure the user has access to the files relating to the submission
                for file in results['files'].get('info', {}).values():
                    assert CLASSIFICATION.is_accessible(user_classification, file['classification'])

                # Ensure the user has access to the results relating to the submission
                for result in results['results']['results'].values():
                    assert CLASSIFICATION.is_accessible(user_classification, result['classification'])


    # Restore bundle
    new_submission = import_bundle(path, cleanup=False, allow_incomplete=as_user, dtl=dtl)

    # Validate restored submission
    assert new_submission['sid'] == sid
    assert new_submission['metadata']['bundle.source'] == config.ui.fqdn
    if dtl is not None:
        # Expect the expiry time to have extended
        assert new_submission['expiry_ts'] != format_time(original_expiry_ts)
    else:
        # Expect the expiry time to be unchanged
        assert new_submission['expiry_ts'] == format_time(original_expiry_ts)

    # Test inserting failure
    with pytest.raises(SubmissionAlreadyExist):
        import_bundle(path, cleanup=False, allow_incomplete=as_user)

    # Test skip failure on exist
    new_submission = import_bundle(path, exist_ok=True, allow_incomplete=as_user, dtl=dtl)

    # Validate restored submission
    assert new_submission['sid'] == sid
    assert new_submission['metadata']['bundle.source'] == config.ui.fqdn

    # Cleanup
    assert not os.path.exists(path)
    datastore_connection.delete_submission_tree_bulk(sid, transport=filestore)
    assert datastore_connection.submission.get_if_exists(sid) is None
