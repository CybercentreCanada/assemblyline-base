
import pytest

from elasticsearch import RequestError
from retrying import retry

from assemblyline.datastore import BaseStore
from assemblyline.datastore.stores.es_store import ESStore
from assemblyline.datastore.stores.riak_store import RiakStore
from assemblyline.datastore.stores.solr_store import SolrStore
from assemblyline.odm import Model, Mapping
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.filescore import FileScore
from assemblyline.odm.models.node import Node
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.signature import Signature
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.submission_tree import SubmissionTree
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_options import UserOptions
from assemblyline.odm.models.workflow import Workflow
from assemblyline.odm.randomizer import random_model_obj


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
    ("error", random_model_obj(Error)),
    ("file", random_model_obj(File)),
    ("filescore", random_model_obj(FileScore)),
    ("node", random_model_obj(Node)),
    ("result", random_model_obj(Result)),
    ("signature", random_model_obj(Signature)),
    ("submission", random_model_obj(Submission)),
    ("submission_tree", random_model_obj(SubmissionTree)),
    ("user", random_model_obj(User)),
    ("user_options", random_model_obj(UserOptions)),
    ("workflow", random_model_obj(Workflow))
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
        data = data[0]

    value = data[key]
    if isinstance(value, list):
        return str(value[0])
    elif isinstance(value, bool):
        return str(value).lower()
    elif isinstance(value, dict):
        return _get_value(list(value.keys())[0], value)
    else:
        value = str(value)
        if " " in value or (":" in value and value.endswith("Z")):
            value = f'"{str(value)}"'

        return value


def _perform_single_collection_test(ds: BaseStore, name: str, doc: Model):
    c = _setup_collection(ds, name, doc)
    field_list = doc.flat_fields()
    doc_data = doc.as_primitives()

    # Did the document we created actually exists
    search_all_result = c.search("*:*")
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
                query = f"{name}:{_get_value(name, doc_data)}"
                if c.search(query, rows=0)["total"] != 0:
                    pytest.fail(f"Search query ({query}) was able to find documents using a non-indexed field.")
        else:
            # Test indexed field searches lead to results
            value = _get_value(name, doc_data)
            if not value:
                # you can't search for empty field, you have to exclude all non empties...
                query = f"-{name}:['' TO *]"
            else:
                query = f"{name}:{value}"
            if c.search(query, rows=0)["total"] != 1:
                pytest.fail(f"Search query ({query}) did not yield any results.")

        if field.copyto:
            # Test copyto field as default search
            query = _get_value(name, doc_data)
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
