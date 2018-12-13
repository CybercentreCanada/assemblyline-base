import pytest

from retrying import retry

from assemblyline.datastore import Collection, BaseStore
from assemblyline.datastore.stores.es_store import ESStore
from assemblyline.datastore.stores.riak_store import RiakStore
from assemblyline.datastore.stores.solr_store import SolrStore
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

TEST_DATA = {
    "alert": random_model_obj(Alert),
    "error": random_model_obj(Error),
    "file": random_model_obj(File),
    "filescore": random_model_obj(FileScore),
    "node": random_model_obj(Node),
    "result": random_model_obj(Result),
    "signature": random_model_obj(Signature),
    "submission": random_model_obj(Submission),
    "submission_tree": random_model_obj(SubmissionTree),
    "user": random_model_obj(User),
    "user_options": random_model_obj(UserOptions),
    "workflow": random_model_obj(Workflow)
}



@retry(stop_max_attempt_number=10, wait_random_min=100, wait_random_max=500)
def setup_store(docstore, request):
    try:
        ret_val = docstore.ping()
        if ret_val:
            return docstore
    except ConnectionError:
        pass
    raise SetupException("Could not setup Datastore: %s" % docstore.__class__.__name__)


@pytest.fixture(scope='module')
def solr_connection(request):
    try:
        document_store = setup_store(SolrStore(['127.0.0.1']), request)
    except SetupException:
        document_store = None

    if document_store:
        return document_store

    return pytest.skip("Connection to the SOLR server failed. This test cannot be performed...")


@pytest.fixture(scope='module')
def es_connection(request):
    try:
        document_store = setup_store(ESStore(['127.0.0.1']), request)
    except SetupException:
        document_store = None

    if document_store:
        return document_store

    return pytest.skip("Connection to the Elasticsearch server failed. This test cannot be performed...")


@pytest.fixture(scope='module')
def riak_connection(request):
    try:
        document_store = setup_store(RiakStore(['127.0.0.1']), request)
    except SetupException:
        document_store = None

    if document_store:
        return document_store

    return pytest.skip("Connection to the Riak server failed. This test cannot be performed...")


def _perform_single_datastore_tests(ds: BaseStore):
    for collection_name, document in TEST_DATA.items():
        ds.register(collection_name, document.__class__)
        collection = ds.__getattr__(collection_name)
        try:
            # Save test document
            collection.save("document_id", document)

            # Commit saved data
            collection.commit()
        finally:
            collection.wipe()


# noinspection PyShadowingNames
def test_solr(solr_connection: SolrStore):
    if solr_connection:
        _perform_single_datastore_tests(solr_connection)


# noinspection PyShadowingNames
def test_es(es_connection: ESStore):
    if es_connection:
        _perform_single_datastore_tests(es_connection)


# noinspection PyShadowingNames
def test_riak(riak_connection: RiakStore):
    if riak_connection:
        _perform_single_datastore_tests(riak_connection)

