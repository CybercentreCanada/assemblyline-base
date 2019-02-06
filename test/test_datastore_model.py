
import pytest

from elasticsearch import RequestError
from retrying import retry

from assemblyline.datastore import BaseStore
from assemblyline.datastore.stores.es_store import ESStore
from assemblyline.datastore.stores.riak_store import RiakStore
from assemblyline.datastore.stores.solr_store import SolrStore
from assemblyline.odm import Model, Mapping
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.emptyresult import EmptyResult
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.filescore import FileScore
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.signature import Signature
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.submission_tags import SubmissionTags
from assemblyline.odm.models.submission_tree import SubmissionTree
from assemblyline.odm.models.tc_signature import TCSignature
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_favorites import UserFavorites
from assemblyline.odm.models.user_options import UserOptions
from assemblyline.odm.models.vm import VM
from assemblyline.odm.models.workflow import Workflow
from assemblyline.odm.randomizer import random_model_obj, random_minimal_obj


class SetupException(Exception):
    pass


@retry(stop_max_attempt_number=10, wait_random_min=100, wait_random_max=500)
def setup_store(docstore):
    try:
        ret_val = docstore.ping()
        if ret_val:
            return docstore
    except ConnectionError:
        pass
    raise SetupException("Could not setup Datastore: %s" % docstore.__class__.__name__)


@pytest.fixture(scope='module')
def solr_datastore():
    try:
        document_store = setup_store(SolrStore(['127.0.0.1']))
    except SetupException:
        document_store = None

    if document_store:
        return document_store

    return pytest.skip("Connection to the SOLR server failed. This test cannot be performed...")


@pytest.fixture(scope='module')
def es_datastore():
    try:
        document_store = setup_store(ESStore(['127.0.0.1']))
    except SetupException:
        document_store = None

    if document_store:
        return document_store

    return pytest.skip("Connection to the Elasticsearch server failed. This test cannot be performed...")


@pytest.fixture(scope='module')
def riak_datastore():
    try:
        document_store = setup_store(RiakStore(['127.0.0.1']))
    except SetupException:
        document_store = None

    if document_store:
        return document_store

    return pytest.skip("Connection to the Riak server failed. This test cannot be performed...")


TEST_DATA = [
    ("alert", random_model_obj(Alert)),
    ("emptyresult", random_model_obj(EmptyResult)),
    ("error", random_model_obj(Error)),
    ("file", random_model_obj(File)),
    ("filescore", random_model_obj(FileScore)),
    ("result", random_model_obj(Result)),
    ("service", random_model_obj(Service)),
    ("signature", random_model_obj(Signature)),
    ("submission", random_model_obj(Submission)),
    ("submission_tags", random_model_obj(SubmissionTags)),
    ("submission_tree", random_model_obj(SubmissionTree)),
    ("tc_signature", random_model_obj(TCSignature)),
    ("user", random_model_obj(User)),
    ("user_favorites", random_model_obj(UserFavorites)),
    ("user_options", random_model_obj(UserOptions)),
    ("vm", random_model_obj(VM)),
    ("workflow", random_model_obj(Workflow)),
    ("alert_min", random_minimal_obj(Alert)),
    ("emptyresult_min", random_minimal_obj(EmptyResult)),
    ("error_min", random_minimal_obj(Error)),
    ("file_min", random_minimal_obj(File)),
    ("filescore_min", random_minimal_obj(FileScore)),
    ("result_min", random_minimal_obj(Result)),
    ("service_min", random_minimal_obj(Service)),
    ("signature_min", random_minimal_obj(Signature)),
    ("submission_min", random_minimal_obj(Submission)),
    ("submission_tags_min", random_model_obj(SubmissionTags)),
    ("submission_tree_min", random_minimal_obj(SubmissionTree)),
    ("tc_signature_min", random_minimal_obj(TCSignature)),
    ("user_min", random_minimal_obj(User)),
    ("user_favorites_min", random_minimal_obj(UserFavorites)),
    ("user_options_min", random_minimal_obj(UserOptions)),
    ("vm_min", random_minimal_obj(VM)),
    ("workflow_min", random_minimal_obj(Workflow))
]


# noinspection PyBroadException
def _setup_collection(ds, name, doc):
    try:
        ds.register(name, model_class=doc.__class__)
        collection = ds.__getattr__(name)
        # Save test document
        collection.save("document_id", doc)

        # Commit saved data
        collection.commit()
        return collection
    except Exception as e:
        pytest.fail(f"Failed to register '{name}' collection. [{str(e)}]")


def _assert_key_exists(key, data):
    if "." in key:
        main, sub = key.split(".", 1)
        if main not in data:
            return False
        return _assert_key_exists(sub, data[main])
    if key in data:
        return True
    return False


def _get_value(key, data):
    while "." in key:
        main, key = key.split(".", 1)
        data = data[main]

    if isinstance(data, list):
        if len(data) == 0:
            return None
        data = data[0]

    value = data[key]
    if value is None:
        return value
    elif isinstance(value, list):
        if len(value) > 0:
            return str(value[0])
        else:
            return None
    elif isinstance(value, bool):
        return str(value).lower()
    elif isinstance(value, dict):
        return _get_value(list(value.keys())[0], value)
    else:
        value = str(value)
        if " " in value or (":" in value and value.endswith("Z")):
            value = f'"{str(value)}"'

        return value


def _perform_single_collection_test(ds: BaseStore, idx_name: str, doc: Model):
    c = _setup_collection(ds, idx_name, doc)
    field_list = doc.flat_fields()
    doc_data = doc.as_primitives()

    # Did the document we created actually exists
    search_all_result = c.search("id:*")
    assert search_all_result["total"] == 1

    # Are all stored field returned by default?
    res_data = search_all_result['items'][0].as_primitives()
    stored_fields = [name for name, field in field_list.items() if field.store]
    for stored_key in stored_fields:
        assert _assert_key_exists(stored_key, res_data)

    for name, field in field_list.items():
        if isinstance(field, Mapping):
            continue

        if not field.index:
            # Test non-indexed field searches, should fail of return no results
            if isinstance(ds, ESStore):
                with pytest.raises(RequestError):
                    c.search(f"{name}:{_get_value(name, doc_data)}", rows=0)
            else:
                value = _get_value(name, doc_data)
                if value:
                    query = f"{name}:{value}"
                    if c.search(query, rows=0)["total"] != 0:
                        pytest.fail(f"Search query ({query}) was able to find documents using a non-indexed field.")
        else:
            # Test indexed field searches lead to results
            value = _get_value(name, doc_data)
            if not value:
                # you can't search for empty field, you have to exclude all non empties...
                query = f"-{name}:*"
            else:
                query = f'{name}:{value}'
            if c.search(query, rows=0)["total"] != 1:
                pytest.fail(f"Search query ({query}) did not yield any results.")

        if field.copyto:
            # Test copyto field as default search
            query = _get_value(name, doc_data)
            if query:
                if c.search(query, rows=0)["total"] != 1:
                    pytest.fail(f"Search query ({query}) did not yield any results.")


# noinspection PyShadowingNames
@pytest.mark.parametrize("collection_name,document", TEST_DATA, ids=[d[0] for d in TEST_DATA])
def test_solr_models(solr_datastore: SolrStore, collection_name: str, document: Model):
    if solr_datastore:
        _perform_single_collection_test(solr_datastore, collection_name, document)


# noinspection PyShadowingNames
@pytest.mark.parametrize("collection_name,document", TEST_DATA, ids=[d[0] for d in TEST_DATA])
def test_es_models(es_datastore: SolrStore, collection_name: str, document: Model):
    if es_datastore:
        _perform_single_collection_test(es_datastore, collection_name, document)


# noinspection PyShadowingNames
@pytest.mark.parametrize("collection_name,document", TEST_DATA, ids=[d[0] for d in TEST_DATA])
def test_riak_models(riak_datastore: SolrStore, collection_name: str, document: Model):
    if riak_datastore:
        _perform_single_collection_test(riak_datastore, collection_name, document)
