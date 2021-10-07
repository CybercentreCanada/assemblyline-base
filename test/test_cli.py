from __future__ import annotations
import json
import io
import os
import pytest
import tempfile
import yaml

from assemblyline.common import forge
from assemblyline.odm.random_data import wipe_alerts, create_alerts, wipe_submissions, create_submission, \
    wipe_heuristics, create_heuristics, wipe_services, create_services, wipe_signatures, create_signatures, \
    wipe_workflows, create_workflows, wipe_users, create_users
from assemblyline.run.cli import ALCommandLineInterface


LOGS: dict[str, list[str]] = {
    'info': [],
    'warning': [],
    'error': []
}


def reset_logger():
    global LOGS
    LOGS = {
        'info': [],
        'warning': [],
        'error': []
    }


class CaptureLogger(object):
    @staticmethod
    def info(msg, **_):
        LOGS['info'].append(msg)

    @staticmethod
    def warning(msg, **_):
        LOGS['warning'].append(msg)

    @staticmethod
    def warn(msg, **_):
        LOGS['warning'].append(msg)

    @staticmethod
    def error(msg, **_):
        LOGS['error'].append(msg)

    @staticmethod
    def exception(msg, **_):
        LOGS['error'].append(msg)


@pytest.fixture(scope="module")
def fs():
    return forge.get_filestore(connection_attempts=1)


def purge_data(ds, fs):
    wipe_alerts(ds)
    wipe_heuristics(ds)
    wipe_services(ds)
    wipe_signatures(ds)
    wipe_submissions(ds, fs)
    wipe_users(ds)
    wipe_workflows(ds)


@pytest.fixture(scope="module")
def datastore(request, datastore_connection, fs):
    purge_data(datastore_connection, fs)

    create_alerts(datastore_connection, alert_count=1)
    create_heuristics(datastore_connection)
    create_services(datastore_connection)
    create_signatures(datastore_connection)
    create_submission(datastore_connection, fs)
    create_users(datastore_connection)
    create_workflows(datastore_connection)

    request.addfinalizer(lambda: purge_data(datastore_connection, fs))
    return datastore_connection


@pytest.fixture(scope="module")
def cli():
    cli = ALCommandLineInterface(show_prompt=False, logger_class=CaptureLogger)
    return cli


def test_backup(datastore, cli):
    # Get a temp directory
    temp_dir = tempfile.mkdtemp()
    os.rmdir(temp_dir)

    # Do a backup
    cli.do_backup(f"{temp_dir} alert force id:*")

    # Read the backup files
    backup_data = ""
    for f in os.listdir(temp_dir):
        with open(os.path.join(temp_dir, f), 'r') as temp_fh:
            backup_data += temp_fh.read()

    # Make sure the backup files match the data in the DB
    for line in backup_data.splitlines():
        collection, key, data = json.loads(line)
        assert data == datastore.get_collection(collection).get(key, as_obj=False)


def test_backup_follow(datastore, cli):
    # Get a temp directory
    temp_dir = tempfile.mkdtemp()
    os.rmdir(temp_dir)

    # Do a backup
    cli.do_backup(f"{temp_dir} submission follow force id:*")

    # Read the backup files
    backup_data = ""
    for f in os.listdir(temp_dir):
        with open(os.path.join(temp_dir, f), 'r') as temp_fh:
            backup_data += temp_fh.read()

    # Make sure the backup files match the data in the DB
    for line in backup_data.splitlines():
        collection, key, data = json.loads(line)
        assert data == datastore.get_collection(collection).get(key, as_obj=False)


def test_backup_system(datastore, cli):
    # Get a temp directory
    temp_dir = tempfile.mkdtemp()
    os.rmdir(temp_dir)

    # Do a backup
    cli.do_backup(f"{temp_dir}")

    # Read the backup files
    backup_data = ""
    for f in os.listdir(temp_dir):
        with open(os.path.join(temp_dir, f), 'r') as temp_fh:
            backup_data += temp_fh.read()

    # Make sure the backup files match the data in the DB
    for line in backup_data.splitlines():
        collection, key, data = json.loads(line)
        assert data == datastore.get_collection(collection).get(key, as_obj=False)


def test_data_reset(datastore, cli):
    reset_logger()
    cli.do_data_reset("")
    assert "Data reset completed." in LOGS['info'][-1]
    assert datastore.submission.search("id:*")['total'] != 0
    assert datastore.user.search("id:*")['total'] != 0


def test_delete(datastore, cli, fs):
    try:
        # delete all users and check if there are still users
        cli.do_delete("user force id:*")
        datastore.user.commit()
        assert datastore.user.search("id:*")['total'] == 0
    finally:
        # Restore users ...
        create_users(datastore)

    try:
        # Delete random submission and check if still there
        sub_id = datastore.submission.search("id:*", fl="id", rows=1, as_obj=False)['items'][0]['id']
        cli.do_delete(f"submission full force id:{sub_id}")
        datastore.submission.commit()
        assert datastore.user.search(f"id:{sub_id}")['total'] == 0
    finally:
        # Re-create a submission
        create_submission(datastore, fs)


def test_index(datastore, cli):
    reset_logger()
    cli.do_index("reindex user")
    assert "Reindexing USER" in LOGS['info'][0]

    reset_logger()
    cli.do_index("commit user")
    assert "Index USER was committed." in LOGS['info']

    # By reindexing we should not loose data
    assert datastore.user.search("id:*")['total'] != 0

    reset_logger()
    cli.do_index("reindex")
    assert len(LOGS['info']) == len(list(datastore.ds.get_models().keys())) * 2

    reset_logger()
    cli.do_index("commit")
    assert "All indexes committed." in LOGS['info'][-1]


def test_restore(datastore, cli, fs):
    # Get a temp directory
    temp_dir = tempfile.mkdtemp()
    os.rmdir(temp_dir)

    # Calculate the numbers of items in each collections
    result_len = datastore.result.search("id:*", rows=0)['total']
    submission_len = datastore.submission.search("id:*", rows=0)['total']
    error_len = datastore.error.search("id:*", rows=0)['total']
    file_len = datastore.file.search("id:*", rows=0)['total']

    # Do a backup
    reset_logger()
    cli.do_backup(f"{temp_dir} submission follow force id:*")
    print(LOGS)

    # Wipe the database
    wipe_submissions(datastore, fs)

    # Test that the DB is empty
    assert datastore.result.search("id:*", rows=0)['total'] == 0
    assert datastore.submission.search("id:*", rows=0)['total'] == 0
    assert datastore.error.search("id:*", rows=0)['total'] == 0
    assert datastore.file.search("id:*", rows=0)['total'] == 0

    # Restore the backup
    cli.do_restore(temp_dir)

    # Refresh the indices
    datastore.submission.commit()
    datastore.file.commit()
    datastore.result.commit()
    datastore.error.commit()

    # Test that the DB is not empty anymore
    assert result_len == datastore.result.search("id:*", rows=0)['total']
    assert submission_len == datastore.submission.search("id:*", rows=0)['total']
    assert error_len == datastore.error.search("id:*", rows=0)['total']
    assert file_len == datastore.file.search("id:*", rows=0)['total']


def test_service(datastore, cli):
    reset_logger()

    cli.do_service("list")
    assert len(LOGS.get('info', [])) == datastore.service_delta.search("id:*")['total']

    reset_logger()
    cli.do_service("show Extract")
    assert yaml.safe_load(io.StringIO(LOGS['info'][0])) == datastore.get_service_with_delta("Extract", as_obj=False)

    cli.do_service("disable Extract")
    assert not datastore.service_delta.get('Extract').enabled

    cli.do_service("enable Extract")
    assert datastore.service_delta.get('Extract').enabled

    cli.do_service("remove Extract")
    datastore.service_delta.commit()
    assert datastore.service_delta.search("id:Extract")['total'] == 0


def test_signature(datastore, cli):
    reset_logger()
    sig_id = datastore.signature.search("id:*", fl="id", rows=1, as_obj=False)['items'][0]['id']
    sig = datastore.signature.get(sig_id, as_obj=False)
    cli.do_signature(f"show {sig_id}")
    assert yaml.safe_load(io.StringIO(LOGS['info'][0])) == sig

    cli.do_signature(f"change_status by_id DISABLED {sig_id}")
    assert datastore.signature.get(sig_id, as_obj=False)['status'] == 'DISABLED'
    datastore.signature.commit()

    cli.do_signature(f"change_status by_query force TESTING id:{sig_id}")
    assert datastore.signature.get(sig_id, as_obj=False)['status'] == 'TESTING'

    cli.do_signature(f"remove {sig_id}")
    datastore.signature.commit()
    assert datastore.signature.search(f"id:{sig_id}")['total'] == 0


def test_ui(cli):
    reset_logger()
    cli.do_ui("show_sessions")
    for line in LOGS.get('info', []):
        assert "=>" in line

    reset_logger()
    cli.do_ui("show_sessions bob")
    assert 'bob' in LOGS.get('info', [])[0]

    reset_logger()
    cli.do_ui("clear_sessions")
    assert LOGS.get('info', [])[0] == "All sessions where cleared."

    reset_logger()
    cli.do_ui("clear_sessions bob")
    assert 'bob' in LOGS.get('info', [])[0]


def test_user(datastore, cli):
    reset_logger()
    cli.do_user("list")
    assert len(LOGS.get('info', [])) == 2

    reset_logger()
    cli.do_user("show user")
    assert yaml.safe_load(io.StringIO(LOGS['info'][0])) == datastore.user.get("user", as_obj=False)

    cli.do_user("disable user")
    assert not datastore.user.get('user').is_active

    cli.do_user("enable user")
    assert datastore.user.get('user').is_active

    cli.do_user("set_admin user")
    assert 'admin' in datastore.user.get('user').type

    cli.do_user("unset_admin user")
    assert 'admin' not in datastore.user.get('user').type

    cli.do_user("set_otp user")
    assert datastore.user.get('user').otp_sk is not None

    cli.do_user("unset_otp user")
    assert datastore.user.get('user').otp_sk is None

    try:
        cli.do_user("remove user")
        datastore.user.commit()
        assert datastore.user.search("id:user")['total'] == 0
    finally:
        create_users(datastore)


def test_wipe(datastore, cli):
    # This needs to run last as it deletes important data for other tests
    try:
        cli.do_wipe('bucket user')
        datastore.user.commit()
        assert datastore.user.search("id:user")['total'] == 0
    finally:
        create_users(datastore)

    reset_logger()
    non_system = ['alert', 'cached_file', 'emptyresult', 'error', 'file', 'filescore', 'result',
                  'submission', 'submission_tree', 'submission_summary', 'workflow']
    cli.do_wipe('non_system')
    for (x, bucket) in enumerate(non_system):
        assert bucket.upper() in LOGS['info'][x]

    reset_logger()
    submission_data_buckets = ['emptyresult', 'error', 'file', 'filescore', 'result',
                               'submission', 'submission_tree', 'submission_summary']
    cli.do_wipe('submission_data')
    for (x, bucket) in enumerate(submission_data_buckets):
        assert bucket.upper() in LOGS['info'][x]
