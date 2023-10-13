
import hashlib
from assemblyline.common.isotime import now_as_iso
from assemblyline.odm.models.file import File
import pytest
import random

from retrying import retry

from assemblyline.common import forge
from assemblyline.datastore.helper import AssemblylineDatastore
from assemblyline.odm.base import DATEFORMAT, KeyMaskException
from assemblyline.odm.models.config import Config
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.randomizer import SERVICES, random_minimal_obj
from assemblyline.odm.random_data import create_signatures, create_submission, create_heuristics, create_services


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
            create_signatures(al_datastore)
            create_services(al_datastore)

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

    # Make sure delete operation is reflected in the DB
    ds.submission.commit()
    ds.error.commit()
    ds.emptyresult.commit()
    ds.result.commit()
    ds.file.commit()

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
    # Get a list of all services
    all_services = set([x.upper() for x in SERVICES.keys()])

    # List all heuristics
    heuristics = ds.get_all_heuristics()

    # Test each heuristics
    for heur in heuristics.values():
        assert heur['heur_id'].split(".")[0] in all_services


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
    file_list = [sha256 for sha256, supplementary, in ds.get_file_list_from_keys(submission.results)]

    # Check if all files that are obvious from the results are there
    for f in submission.files:
        assert f.sha256 in file_list
    for r in submission.results:
        assert r[:64] in file_list


def test_get_file_scores_from_keys(ds: AssemblylineDatastore):
    # Get a random submission
    submission: Submission = ds.submission.search("id:*", rows=1, fl="*")['items'][0]

    # Get scores
    file_scores = ds.get_file_scores_from_keys(submission.results)

    # Check if all files that are obvious from the results are there
    for f in submission.files:
        assert f.sha256 in file_scores
    for r in submission.results:
        assert r[:64] in file_scores

    for s in file_scores.values():
        assert isinstance(s, int)


def test_get_signature_last_modified(ds: AssemblylineDatastore):
    last_mod = ds.get_signature_last_modified()

    assert isinstance(last_mod, str)
    assert "T" in last_mod
    assert last_mod.endswith("Z")


def test_get_or_create_file_tree(ds: AssemblylineDatastore, config: Config):
    # Get a random submission
    submission: Submission = ds.submission.search("id:*", rows=1, fl="*")['items'][0]

    # Get file tree
    tree = ds.get_or_create_file_tree(submission, config.submission.max_extraction_depth)

    # Check if all files that are obvious from the results are there
    for x in ['tree', 'classification', 'filtered', 'partial', 'supplementary']:
        assert x in tree

    for f in submission.files:
        assert f.sha256 in tree['tree']


def test_get_summary_from_keys(ds: AssemblylineDatastore):
    # Get a random submission
    submission: Submission = ds.submission.search("id:*", rows=1, fl="*")['items'][0]

    # Get the summary
    summary = ds.get_summary_from_keys(submission.results)

    # Get the summary with heuristics
    summary_heur = ds.get_summary_from_keys(submission.results, keep_heuristic_sections=True)

    assert summary['tags'] == summary_heur['tags']
    assert summary['attack_matrix'] == summary_heur['attack_matrix']
    assert summary['heuristics'] == summary_heur['heuristics']
    assert summary['classification'] == summary_heur['classification']
    assert summary['filtered'] == summary_heur['filtered']
    assert summary['heuristic_sections'] == {}
    assert summary['heuristic_name_map'] == {}

    heuristics = ds.get_all_heuristics()

    for h in summary_heur['heuristic_sections']:
        assert h in heuristics

    for heur_list in summary_heur['heuristic_name_map'].values():
        for h in heur_list:
            assert h in heuristics


def test_get_tag_list_from_keys(ds: AssemblylineDatastore):
    # Get a random submission
    submission: Submission = ds.submission.search("id:*", rows=1, fl="*")['items'][0]

    # Get the list of tags
    tags = ds.get_tag_list_from_keys(submission.results)

    assert len(tags) > 0
    for t in tags:
        assert t['key'] in submission.results


def test_get_attack_matrix_from_keys(ds: AssemblylineDatastore):
    # Get a random submission
    submission: Submission = ds.submission.search("id:*", rows=1, fl="*")['items'][0]

    # Get the list of tags
    attacks = ds.get_attack_matrix_from_keys(submission.results)

    for a in attacks:
        assert a['key'] in submission.results


def test_get_service_with_delta(ds: AssemblylineDatastore):
    # Get a random service delta
    service_delta: Service = ds.service_delta.search("id:*", rows=1, fl="*")['items'][0]
    service_key = f"{service_delta.id}_{service_delta.version}"
    service_delta.category = "TEST"

    # Save fake service category
    ds.service_delta.save(service_delta.id, service_delta)
    ds.service_delta.commit()

    # Get the associated service
    service: Service = ds.service.get(service_key)

    # Get the full service with its delta
    full_service = ds.get_service_with_delta(service_delta.id)

    assert full_service.as_primitives() != service.as_primitives()
    assert full_service.category == "TEST"


def test_calculate_heuristic_stats(ds: AssemblylineDatastore):
    default_stats = {'count': 0, 'min': 0, 'max': 0, 'avg': 0, 'sum': 0, 'first_hit': None, 'last_hit': None}

    # Reset original heuristics stats
    for heur_id in ds.get_all_heuristics():
        ds.heuristic.update(heur_id, [(ds.heuristic.UPDATE_SET, 'stats', default_stats)])
    ds.heuristic.commit()

    # Make sure stats did get reset
    heuristics = ds.get_all_heuristics()
    assert all([heur['stats'] == default_stats for heur in heuristics.values()])

    # Do heuristics stat calculation for all
    ds.calculate_heuristic_stats()
    ds.heuristic.commit()

    # Get heuristics with calculated stats
    updated_heuristics = ds.get_all_heuristics()

    assert heuristics != updated_heuristics
    assert any([heur['stats'] != default_stats for heur in updated_heuristics.values()])


def test_calculate_signature_stats(ds: AssemblylineDatastore):
    default_stats = {'count': 0, 'min': 0, 'max': 0, 'avg': 0, 'sum': 0, 'first_hit': None, 'last_hit': None}

    def get_all_signatures():
        return {s['id']: s for s in ds.signature.stream_search("id:*", as_obj=False)}

    # Reset original signature stats
    for sig_id in get_all_signatures():
        ds.signature.update(sig_id, [(ds.signature.UPDATE_SET, 'stats', default_stats)])
    ds.signature.commit()

    # Make sure stats did get reset
    signatures = get_all_signatures()
    assert all([sig['stats'] == default_stats for sig in signatures.values()])

    # Do signature stat calculation for all
    ds.calculate_signature_stats(lookback_time="now-1y")
    ds.signature.commit()

    # Get signatures with calculated stats
    updated_signatures = get_all_signatures()

    assert signatures != updated_signatures
    assert any([sig['stats'] != default_stats for sig in updated_signatures.values()])


def test_list_all_services(ds: AssemblylineDatastore):
    all_svc: Service = ds.list_all_services()
    all_svc_full: Service = ds.list_all_services(full=True)

    # Make sure service lists are different
    assert all_svc != all_svc_full

    # Check that all services are there in the normal list
    for svc in all_svc:
        assert svc.name in SERVICES

    # Check that all services are there in the full list
    for svc in all_svc_full:
        assert svc.name in SERVICES

    # Make sure non full list raises exceptions
    for svc in all_svc:
        with pytest.raises(KeyMaskException):
            svc.timeout

    # Make sure the full list does not
    for svc in all_svc_full:
        assert svc.timeout is not None


def test_list_service_heuristics(ds: AssemblylineDatastore):
    # Get a random service
    svc_name = random.choice(list(SERVICES.keys()))

    # Get the service heuristics
    heuristics = ds.list_service_heuristics(svc_name)

    # Validate the heuristics
    for heur in heuristics:
        assert heur.heur_id.startswith(svc_name.upper())


def test_list_all_heuristics(ds: AssemblylineDatastore):
    # Get a list of all services
    all_services = set([x.upper() for x in SERVICES.keys()])

    # List all heuristics
    heuristics = ds.list_all_heuristics()

    # Test each heuristics
    for heur in heuristics:
        assert heur.heur_id.split(".")[0] in all_services


def test_save_or_freshen_file(ds: AssemblylineDatastore):
    classification = forge.get_classification()

    # Generate random data
    data = b"asfd"*64
    expiry_create = now_as_iso(60 * 60 * 24 * 14)
    expiry_freshen = now_as_iso(60 * 60 * 24 * 15)

    # Generate file info for random file
    f = random_minimal_obj(File)
    f.sha256 = hashlib.sha256(data).hexdigest()
    f.sha1 = hashlib.sha1(data).hexdigest()
    f.md5 = hashlib.md5(data).hexdigest()

    # Make sure file does not exists
    ds.file.delete(f.sha256)

    # Save the file
    ds.save_or_freshen_file(f.sha256, f.as_primitives(), expiry_create, classification.RESTRICTED)

    # Validate created file
    saved_file = ds.file.get_if_exists(f.sha256)
    assert saved_file.sha256 == f.sha256
    assert saved_file.sha1 == f.sha1
    assert saved_file.md5 == f.md5
    assert saved_file.expiry_ts.strftime(DATEFORMAT) == expiry_create
    assert saved_file.seen.count == 1
    assert saved_file.seen.first == saved_file.seen.last
    assert saved_file.classification.long() == classification.normalize_classification(classification.RESTRICTED)

    # Freshen the file
    ds.save_or_freshen_file(f.sha256, f.as_primitives(), expiry_freshen, classification.UNRESTRICTED)

    # Validate freshened file
    freshened_file = ds.file.get_if_exists(f.sha256)
    assert freshened_file.sha256 == f.sha256
    assert freshened_file.sha1 == f.sha1
    assert freshened_file.md5 == f.md5
    assert freshened_file.expiry_ts.strftime(DATEFORMAT) == expiry_freshen
    assert freshened_file.seen.count == 2
    assert freshened_file.seen.first < freshened_file.seen.last
    assert freshened_file.classification.long() == classification.normalize_classification(classification.UNRESTRICTED)
