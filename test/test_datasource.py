import random

import pytest

from assemblyline.datasource.al import AL
from assemblyline.datasource.alert import Alert
from assemblyline.common import forge
from assemblyline.odm.random_data import wipe_alerts, create_alerts, wipe_submissions, create_submission, NullLogger

fs = forge.get_filestore()


def purge_alert(ds):
    wipe_alerts(ds)
    wipe_submissions(ds, fs)


@pytest.fixture(scope="module")
def datastore(request, datastore_connection):
    create_alerts(datastore_connection, alert_count=1)
    create_submission(datastore_connection, fs)

    request.addfinalizer(lambda: purge_alert(datastore_connection, fs))
    return datastore_connection


# noinspection PyUnusedLocal
def test_al_source(datastore):
    submission_id = random.choice(datastore.submission.search("id:*", fl="id", rows=1, as_obj=False)['items'])['id']
    submission = datastore.submission.get(submission_id)
    al_datasource = AL(NullLogger())
    resp = al_datasource.query(submission.files[0].sha256, access_control=None)
    for res in resp:
        score = res['data']['score']
        if score >= 2000:
            assert res['malicious']
            assert res['confirmed']
        elif 1000 <= score < 2000:
            assert res['malicious']
            assert not res['confirmed']
        else:
            assert not res['malicious']


# noinspection PyUnusedLocal
def test_alert_source(datastore):
    alert_id = random.choice(datastore.alert.search("id:*", fl="id", rows=1, as_obj=False)['items'])['id']
    alert = datastore.alert.get(alert_id)

    alert_datasource = Alert(NullLogger())
    resp = alert_datasource.query(alert.file.sha256, access_control=None)
    for res in resp:
        score = None
        for item in res['data']:
            if score is None or item['score'] > score:
                score = item['score']

        if score >= 2000:
            assert res['malicious']
            assert res['confirmed']
        elif 500 <= score < 2000:
            assert res['malicious']
            assert not res['confirmed']
        else:
            assert not res['malicious']
