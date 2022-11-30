
from assemblyline.odm.randomizer import SERVICES
import pytest

from retrying import retry

from assemblyline.common import forge
from assemblyline.datastore.helper import AssemblylineDatastore
from assemblyline.odm.models.config import Config
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.random_data import create_submission, create_heuristics


class SetupException(Exception):
    pass


@retry(stop_max_attempt_number=10, wait_random_min=100, wait_random_max=500)
def setup_store(al_datastore: AssemblylineDatastore, request):
    try:
        ret_val = al_datastore.ds.ping()
        if ret_val:

            # Create data
            fs = forge.get_filestore()
            for _ in range(3):
                create_submission(al_datastore, fs)
            create_heuristics(al_datastore)

            # Wipe all on finalize
            def cleanup():
                for index_name in al_datastore.ds.get_models():
                    al_datastore.enable_archive_access()
                    collection = al_datastore.get_collection(index_name)
                    collection.wipe(recreate=False)
            request.addfinalizer(cleanup)

            return al_datastore
    except ConnectionError:
        pass
    raise SetupException("Could not setup Datastore: %s" % al_datastore)


@pytest.fixture(scope='module')
def config():
    return forge.get_config()


@pytest.fixture(scope='module')
def ds(request, config):
    try:
        return setup_store(forge.get_datastore(config=config), request)
    except SetupException:
        pass

    return pytest.skip("Connection to the Elasticsearch server failed. This test cannot be performed...")


def test_index_archive_status(ds: AssemblylineDatastore, config: Config):
    """Save a new document atomically, then try to save it again and detect the failure."""
    ds.enable_archive_access()
    try:
        indices = ds.ds.get_models()
        archiveable_indices = config.datastore.archive.indices

        for index in indices:
            collection = ds.get_collection(index)
            if index in archiveable_indices:
                assert collection.archive_name == f"{index}-ma"
            else:
                assert collection.archive_name is None

    finally:
        ds.disable_archive_access()


def test_get_stats(ds: AssemblylineDatastore):
    stats = ds.get_stats()
    assert "cluster" in stats
    assert "nodes" in stats
    assert "indices" in stats
    assert stats['cluster']['status'] in ["green", "yellow"]


def test_create_empty_result(ds: AssemblylineDatastore):
    cl_engine = forge.get_classification()

    # Set expected values
    classification = cl_engine.normalize_classification(cl_engine.UNRESTRICTED)
    svc_name = "TEST"
    svc_version = "4"
    sha256 = "a123" * 16

    # Build result key
    result_key = Result.help_build_key(sha256=sha256, service_name=svc_name, service_version=svc_version, is_empty=True)

    # Create an empty result from the key
    empty_result = ds.create_empty_result_from_key(result_key, cl_engine=cl_engine)

    # Test the empty result
    assert empty_result.is_empty()
    assert empty_result.response.service_name == svc_name
    assert empty_result.response.service_version == svc_version
    assert empty_result.sha256 == sha256
    assert empty_result.classification.long() == classification


DELETE_TREE_PARAMS = [
    (True, "bulk"),
    (False, "direct"),
]


# noinspection PyShadowingNames
@pytest.mark.parametrize("bulk", [f[0] for f in DELETE_TREE_PARAMS], ids=[f[1] for f in DELETE_TREE_PARAMS])
def test_delete_submission_tree(ds: AssemblylineDatastore, bulk):
    # Reset the data
    fs = forge.get_filestore()

    # Create a random submission
    submission: Submission = create_submission(ds, fs)
    files = set({submission.files[0].sha256})
    files = files.union([x[:64] for x in submission.results])
    files = files.union([x[:64] for x in submission.errors])
    # Validate the submission is there
    assert ds.submission.exists(submission.sid)
    for f in files:
        assert ds.file.exists(f)
    for r in submission.results:
        if r.endswith(".e"):
            assert ds.emptyresult.exists(r)
        else:
            assert ds.result.exists(r)
    for e in submission.errors:
        assert ds.error.exists(e)

    # Delete the submission
    if bulk:
        ds.delete_submission_tree_bulk(submission.sid, transport=fs)
    else:
        ds.delete_submission_tree(submission.sid, transport=fs)

    # Make sure submission is completely gone
    assert not ds.submission.exists(submission.sid)
    for f in files:
        assert not ds.file.exists(f)
    for r in submission.results:
        if r.endswith(".e"):
            assert not ds.emptyresult.exists(r)
        else:
            assert not ds.result.exists(r)
    for e in submission.errors:
        assert not ds.error.exists(e)


def test_get_all_heuristics(ds: AssemblylineDatastore):
    data = ds.get_all_heuristics()
    assert len(data) == len(SERVICES)*5


def test_get_results(ds: AssemblylineDatastore):
    # Get a random submission
    submission: Submission = ds.submission.search("id:*", rows=1, fl="*")['items'][0]

    # Get all results for that submission
    results = ds.get_multiple_results(submission.results)
    assert len(results) == len(submission.results)

    # Get results one by one
    single_res = {}
    for r in submission.results:
        single_res[r] = ds.get_single_result(r)

    # Compare results
    for r_key in results:
        assert r_key in single_res
        if not r_key.endswith(".e"):
            assert single_res[r_key] == results[r_key]


def test_get_file_submission_meta(ds: AssemblylineDatastore):
    # Get a random submission
    submission: Submission = ds.submission.search("id:*", rows=1, fl="*")['items'][0]

    # Get submission meta
    submission_meta = ds.get_file_submission_meta(submission.files[0].sha256, ['params.submitter'])

    # check if current submission values are in submission meta
    assert submission.params.submitter in submission_meta['submitter']


def test_get_file_list_from_keys(ds: AssemblylineDatastore):
    # Get a random submission
    submission: Submission = ds.submission.search("id:*", rows=1, fl="*")['items'][0]

    # Get related file list
    file_list = ds.get_file_list_from_keys(submission.results)

    # Check if all files that are obvious from the results are there
    for f in submission.files:
        assert f.sha256 in file_list
    for r in submission.results:
        assert r[:64] in file_list
