
import json
import os
import pytest
import random
import tempfile

from assemblyline.common import forge
from assemblyline.odm.random_data import wipe_alerts, create_alerts, wipe_submissions, create_submission
from assemblyline.run.cli import ALCommandLineInterface

ds = forge.get_datastore()
fs = forge.get_filestore()


def purge_data():
    wipe_alerts(ds)
    wipe_submissions(ds, fs)


@pytest.fixture(scope="module")
def datastore(request):
    purge_data()

    create_alerts(ds, alert_count=1)
    create_submission(ds, fs)

    request.addfinalizer(purge_data)
    return ds

@pytest.fixture(scope="module")
def cli():
    cli = ALCommandLineInterface(show_prompt=False)
    return cli


def test_backup(datastore, cli):
    temp_dir = tempfile.mkdtemp()
    os.rmdir(temp_dir)

    cli.do_backup(f"{temp_dir} alert force *:*")
    backup_data = ""
    for f in os.listdir(temp_dir):
        with open(os.path.join(temp_dir, f), 'r') as temp_fh:
            backup_data += temp_fh.read()

    for line in backup_data.splitlines():
        collection, key, data = json.loads(line)
        assert data == datastore.get_collection(collection).get(key, as_obj=False)
