
import json
import os
import pytest
import tempfile

from assemblyline.common import forge
from assemblyline.odm.random_data import wipe_alerts, create_alerts, wipe_submissions, create_submission, \
    wipe_heuristics, create_heuristics, wipe_services, create_services, wipe_signatures, create_signatures, \
    wipe_workflows, create_workflows, wipe_users, create_users
from assemblyline.run.cli import ALCommandLineInterface, NullLogger

ds = forge.get_datastore()
fs = forge.get_filestore()


def purge_data():
    wipe_alerts(ds)
    wipe_heuristics(ds)
    wipe_services(ds)
    wipe_signatures(ds)
    wipe_submissions(ds, fs)
    wipe_users(ds)
    wipe_workflows(ds)


@pytest.fixture(scope="module")
def datastore(request):
    purge_data()

    create_alerts(ds, alert_count=1)
    create_heuristics(ds)
    create_services(ds)
    create_signatures(ds)
    create_submission(ds, fs)
    create_users(ds)
    create_workflows(ds)

    request.addfinalizer(purge_data)
    return ds

@pytest.fixture(scope="module")
def cli():
    cli = ALCommandLineInterface(show_prompt=False, logger_class=NullLogger)
    return cli


def test_backup(datastore, cli):
    # Get a temp directory
    temp_dir = tempfile.mkdtemp()
    os.rmdir(temp_dir)

    # Do a backup
    cli.do_backup(f"{temp_dir} alert force *:*")

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
    cli.do_backup(f"{temp_dir} submission follow force *:*")

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


def test_restore(datastore, cli):
    # Get a temp directory
    temp_dir = tempfile.mkdtemp()
    os.rmdir(temp_dir)

    # Calculate the numbers of items in each collections
    result_len = datastore.result.search("*:*", rows=0)['total']
    submission_len = datastore.submission.search("*:*", rows=0)['total']
    error_len = datastore.error.search("*:*", rows=0)['total']
    file_len = datastore.file.search("*:*", rows=0)['total']

    # Do a backup
    cli.do_backup(f"{temp_dir} submission follow force *:*")

    # Wipe the database
    wipe_submissions(ds, fs)

    # Test that the DB is empty
    assert datastore.result.search("*:*", rows=0)['total'] == 0
    assert datastore.submission.search("*:*", rows=0)['total'] == 0
    assert datastore.error.search("*:*", rows=0)['total'] == 0
    assert datastore.file.search("*:*", rows=0)['total'] == 0

    # Restore the backup
    cli.do_restore(temp_dir)

    # Refresh the indices
    datastore.submission.commit()
    datastore.file.commit()
    datastore.result.commit()
    datastore.error.commit()

    # Test that the DB is not empty anymore
    assert result_len == datastore.result.search("*:*", rows=0)['total']
    assert submission_len == datastore.submission.search("*:*", rows=0)['total']
    assert error_len == datastore.error.search("*:*", rows=0)['total']
    assert file_len == datastore.file.search("*:*", rows=0)['total']

