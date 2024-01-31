import pytest

from retrying import retry

from assemblyline.datastore.store import ESStore
from assemblyline.datastore.exceptions import SearchException
from assemblyline.odm import Model, Mapping, Classification
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.badlist import Badlist
from assemblyline.odm.models.cached_file import CachedFile
from assemblyline.odm.models.emptyresult import EmptyResult
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.filescore import FileScore
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.service_delta import ServiceDelta
from assemblyline.odm.models.signature import Signature
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.submission_summary import SubmissionSummary
from assemblyline.odm.models.submission_tree import SubmissionTree
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_favorites import UserFavorites
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline.odm.models.safelist import Safelist
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
def es_datastore():
    try:
        document_store = setup_store(ESStore(['http://elastic:devpass@127.0.0.1:9200']))
    except SetupException:
        document_store = None

    if document_store:
        return document_store

    return pytest.skip("Connection to the Elasticsearch server failed. This test cannot be performed...")


TEST_DATA = [
    ("alert", random_model_obj(Alert)),
    ("badlist", random_model_obj(Badlist)),
    ("cached_file", random_model_obj(CachedFile)),
    ("emptyresult", random_model_obj(EmptyResult)),
    ("error", random_model_obj(Error)),
    ("file", random_model_obj(File)),
    ("filescore", random_model_obj(FileScore)),
    ("heuristic", random_model_obj(Heuristic)),
    ("result", random_model_obj(Result)),
    ("service", random_model_obj(Service)),
    ("service_delta", random_model_obj(ServiceDelta)),
    ("signature", random_model_obj(Signature)),
    ("submission", random_model_obj(Submission)),
    ("submission_summary", random_model_obj(SubmissionSummary)),
    ("submission_tree", random_model_obj(SubmissionTree)),
    ("user", random_model_obj(User)),
    ("user_favorites", random_model_obj(UserFavorites)),
    ("user_settings", random_model_obj(UserSettings)),
    ("safelist", random_model_obj(Safelist)),
    ("workflow", random_model_obj(Workflow)),
    ("alert_min", random_minimal_obj(Alert)),
    ("badlist_min", random_minimal_obj(Badlist)),
    ("cached_file_min", random_minimal_obj(CachedFile)),
    ("emptyresult_min", random_minimal_obj(EmptyResult)),
    ("error_min", random_minimal_obj(Error)),
    ("file_min", random_minimal_obj(File)),
    ("filescore_min", random_minimal_obj(FileScore)),
    ("heuristic_min", random_minimal_obj(Heuristic)),
    ("result_min", random_minimal_obj(Result)),
    ("service_min", random_minimal_obj(Service)),
    ("service_delta_min", random_minimal_obj(ServiceDelta)),
    ("signature_min", random_minimal_obj(Signature)),
    ("submission_min", random_minimal_obj(Submission)),
    ("submission_summary_min", random_minimal_obj(SubmissionSummary)),
    ("submission_tree_min", random_minimal_obj(SubmissionTree)),
    ("user_min", random_minimal_obj(User)),
    ("user_favorites_min", random_minimal_obj(UserFavorites)),
    ("user_settings_min", random_minimal_obj(UserSettings)),
    ("safelist_min", random_minimal_obj(Safelist)),
    ("workflow_min", random_minimal_obj(Workflow))
]


# noinspection PyBroadException
def _setup_collection(ds, name, doc):
    try:
        # Reuse default collection for minimal objects
        name = name.replace('_min', '')

        ds.register(name, model_class=doc.__class__)
        collection = ds.__getattr__(name)

        # Make sure the collection is empty
        collection.delete_by_query("id:*")

        # Save test document
        collection.save("document_id", doc)

        # Commit saved data
        collection.commit()
        return collection
    except Exception as e:
        pytest.fail(f"Failed to register '{name}' collection. [{str(e)}]")


def _assert_key_exists(key, data):
    if data is None:
        # Field is stored but optional... This is fine
        return True

    if "." in key:
        main, sub = key.split(".", 1)
        if main not in data:
            return False
        return _assert_key_exists(sub, data[main])
    if isinstance(data, list):
        if all(key in x for x in data):
            return True
    elif key in data:
        return True
    return False


def _get_value(key, data):
    while "." in key:
        if data is None:
            return data
        main, key = key.split(".", 1)

        if isinstance(data, list):
            for x in data:
                value = _get_value(f"{main}.{key}", x)
                if value is not None:
                    return value
            return None

        try:
            data = data[main]
        except TypeError:
            pass

    if data is None:
        return data

    if isinstance(data, list):
        for x in data:
            value = _get_value(key, x)
            if value is not None:
                return value
        return None

    value = data[key]
    if value is None:
        return value
    elif isinstance(value, list):
        if len(value) > 0:
            value = str(value[0])
            if " " in value or ":" in value or "/" in value:
                value = f'"{value}"'

            if "\\" in value:
                # Escape backslashes for queries
                value.replace("\\", "\\\\")

            return value
        else:
            return None
    elif isinstance(value, bool):
        return str(value).lower()
    elif isinstance(value, dict):
        return _get_value(list(value.keys())[0], value)
    else:
        value = str(value)
        if " " in value or ":" in value or "/" in value:
            value = f'"{value}"'

        if "\\" in value:
            # Escape backslashes for queries
            value.replace("\\", "\\\\")

        return value


def _perform_single_collection_test(ds: ESStore, idx_name: str, doc: Model):
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
            with pytest.raises(SearchException):
                c.search(f"{name}:{_get_value(name, doc_data)}", rows=0)
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

        if isinstance(field, Classification) and "." not in name:
            if c.search("__access_lvl__:[0 TO 200]", rows=0)["total"] != 1:
                pytest.fail("Search query on field __access_lvl__ failed.")
            if c.search("__access_grp1__:*", rows=0)["total"] != 1:
                pytest.fail("Search query on field __access_grp1__ failed.")
            if c.search("__access_grp2__:*", rows=0)["total"] != 1:
                pytest.fail("Search query on field __access_grp2__ failed.")


# noinspection PyShadowingNames
@pytest.mark.parametrize("collection_name,document", TEST_DATA, ids=[d[0] for d in TEST_DATA])
def test_es_models(es_datastore: ESStore, collection_name: str, document: Model):
    if es_datastore:
        _perform_single_collection_test(es_datastore, collection_name, document)
