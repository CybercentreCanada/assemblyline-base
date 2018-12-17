import pytest

from retrying import retry

from assemblyline.datastore import BaseStore
from assemblyline.datastore.stores.es_store import ESStore
from assemblyline.datastore.stores.riak_store import RiakStore
from assemblyline.datastore.stores.solr_store import SolrStore
from assemblyline.odm import Model
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


def _perform_single_collection_test(ds: BaseStore, name: str, doc: Model):
    c = _setup_collection(ds, name, doc)
    assert c.search("*:*")["total"] == 1


@pytest.mark.parametrize("collection_name,document", TEST_DATA, ids=[d[0] for d in TEST_DATA])
def test_solr_models(solr_datastore: SolrStore, collection_name: str, document: Model):
    if solr_datastore:
        _perform_single_collection_test(solr_datastore, collection_name, document)


@pytest.mark.parametrize("collection_name,document", TEST_DATA, ids=[d[0] for d in TEST_DATA])
def test_es_models(es_datastore: SolrStore, collection_name: str, document: Model):
    if es_datastore:
        _perform_single_collection_test(es_datastore, collection_name, document)


@pytest.mark.parametrize("collection_name,document", TEST_DATA, ids=[d[0] for d in TEST_DATA])
def test_riak_models(riak_datastore: SolrStore, collection_name: str, document: Model):
    if riak_datastore:
        _perform_single_collection_test(riak_datastore, collection_name, document)
