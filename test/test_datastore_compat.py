from types import SimpleNamespace
from unittest.mock import Mock

import elasticsearch
import pytest
from elastic_transport import ApiResponseMeta, NodeConfig

from assemblyline.datastore.collection import ESCollection
from assemblyline.datastore.compat import (
    SearchBackend,
    SearchBackendCompatibilityError,
    SearchBackendException,
    SearchClientAdapter,
    UnsupportedSearchBackendOperation,
)
from assemblyline.datastore.exceptions import VersionConflictException
from assemblyline.datastore.store import ESStore


def make_response_meta(status):
    return ApiResponseMeta(status, "1.1", {}, 0.0, NodeConfig("http", "localhost", 9200))


def make_raw_client():
    return SimpleNamespace(
        bulk=Mock(return_value={"errors": False}),
        close=Mock(),
        delete=Mock(return_value={"result": "deleted"}),
        exists=Mock(return_value=True),
        get=Mock(return_value={"_id": "id", "_source": {"id": "id"}}),
        index=Mock(return_value={"result": "created"}),
        info=Mock(return_value={"version": {"number": "8.10.2"}}),
        mget=Mock(return_value={"docs": []}),
        open_point_in_time=Mock(return_value={"id": "es-pit"}),
        ping=Mock(return_value=True),
        search=Mock(return_value={"hits": {"hits": []}}),
        update=Mock(return_value={"result": "updated"}),
        close_point_in_time=Mock(return_value={"succeeded": True, "num_freed": 1}),
        create_pit=Mock(return_value={"pit_id": "os-pit"}),
        delete_pit=Mock(return_value={"pits": [{"pit_id": "os-pit", "successful": True}]}),
        cat=SimpleNamespace(nodes=Mock()),
        cluster=SimpleNamespace(health=Mock()),
        ilm=SimpleNamespace(get_lifecycle=Mock()),
        indices=SimpleNamespace(
            clear_cache=Mock(return_value={"_shards": {"successful": 1}}),
            create=Mock(return_value={"acknowledged": True}),
            exists=Mock(return_value=True),
            exists_alias=Mock(return_value=False),
            get=Mock(return_value={"alert": {"mappings": {"properties": {}}}}),
            put_alias=Mock(return_value={"acknowledged": True}),
            refresh=Mock(return_value={"_shards": {"successful": 1}}),
            clone=Mock(return_value={"acknowledged": True}),
        ),
        nodes=SimpleNamespace(stats=Mock()),
        security=SimpleNamespace(put_role=Mock(), put_user=Mock()),
        tasks=SimpleNamespace(get=Mock()),
    )


def test_elasticsearch_adapter_preserves_es8_keywords():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.ELASTICSEARCH)

    adapter.indices.create(index="alert_hot", mappings={"properties": {}}, settings={"index": {"number_of_shards": 1}})
    raw.indices.create.assert_called_once_with(
        index="alert_hot",
        mappings={"properties": {}},
        settings={"index": {"number_of_shards": 1}},
    )

    adapter.index(index="alert", id="1", document='{"id": "1"}', op_type="index")
    raw.index.assert_called_once_with(index="alert", id="1", document='{"id": "1"}', op_type="index")

    adapter.bulk(operations='{"delete": {"_id": "1"}}')
    raw.bulk.assert_called_once_with(operations='{"delete": {"_id": "1"}}')

    adapter.mget(index="alert", ids=["1", "2"])
    raw.mget.assert_called_once_with(index="alert", ids=["1", "2"])

    adapter.search(index="alert", query={"match_all": {}}, from_=1, size=10)
    raw.search.assert_called_once_with(index="alert", query={"match_all": {}}, from_=1, size=10)


def test_elasticsearch_pit_open_call_is_forwarded_unchanged():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.ELASTICSEARCH)

    response = adapter.open_point_in_time(index="alert", keep_alive="1m", preference="_local")

    assert response == {"id": "es-pit"}
    raw.open_point_in_time.assert_called_once_with(index="alert", keep_alive="1m", preference="_local")


def test_elasticsearch_pit_close_call_is_forwarded_unchanged():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.ELASTICSEARCH)

    response = adapter.close_point_in_time(id="es-pit")

    assert response == {"succeeded": True, "num_freed": 1}
    raw.close_point_in_time.assert_called_once_with(id="es-pit")


def test_opensearch_index_document_translates_to_body():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    adapter.index(index="alert", id="1", document='{"id": "1"}', op_type="index")

    raw.index.assert_called_once_with(index="alert", id="1", body='{"id": "1"}', op_type="index")


def test_opensearch_bulk_translates_operations_to_body():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    adapter.bulk(operations='{"create": {"_id": "1"}}')

    raw.bulk.assert_called_once_with(body='{"create": {"_id": "1"}}')


def test_opensearch_mget_ids_translates_to_body():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    adapter.mget(index="alert", ids=["1", "2"])

    raw.mget.assert_called_once_with(index="alert", body={"ids": ["1", "2"]})


def test_opensearch_index_create_combines_mappings_and_settings_under_body():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    adapter.indices.create(index="alert_hot", mappings={"properties": {}}, settings={"index": {"number_of_shards": 1}})

    raw.indices.create.assert_called_once_with(
        index="alert_hot",
        body={"mappings": {"properties": {}}, "settings": {"index": {"number_of_shards": 1}}},
    )


def test_opensearch_index_create_rewrites_unsupported_wildcard_mappings():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)
    mappings = {
        "properties": {
            "result_key": {"type": "wildcard"},
            "name": {"type": "keyword"},
        },
        "dynamic_templates": [
            {
                "metadata.*_wildcard_tpl": {
                    "path_match": "metadata.*",
                    "mapping": {"type": "wildcard", "copy_to": "__text__"},
                }
            }
        ],
    }

    adapter.indices.create(index="alert_hot", mappings=mappings)

    raw.indices.create.assert_called_once_with(
        index="alert_hot",
        body={
            "mappings": {
                "properties": {
                    "result_key": {"type": "keyword"},
                    "name": {"type": "keyword"},
                },
                "dynamic_templates": [
                    {
                        "metadata.*_wildcard_tpl": {
                            "path_match": "metadata.*",
                            "mapping": {"type": "keyword", "copy_to": "__text__"},
                        }
                    }
                ],
            }
        },
    )
    assert mappings["properties"]["result_key"]["type"] == "wildcard"
    assert mappings["dynamic_templates"][0]["metadata.*_wildcard_tpl"]["mapping"]["type"] == "wildcard"


def test_opensearch_indices_get_is_supported_for_mapping_validation():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    adapter.indices.get(index="alert")

    raw.indices.get.assert_called_once_with(index="alert")


def test_opensearch_search_translates_query_structure_to_body():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    adapter.search(
        index="alert",
        query={"query_string": {"query": "id:*"}},
        from_=2,
        size=25,
        sort=[{"id": "asc"}],
        _source=["id"],
        track_total_hits=True,
    )

    raw.search.assert_called_once_with(
        index="alert",
        track_total_hits=True,
        body={
            "query": {"query_string": {"query": "id:*"}},
            "from": 2,
            "size": 25,
            "sort": [{"id": "asc"}],
            "_source": ["id"],
        },
    )


def test_opensearch_pit_search_translates_paging_fields_to_body():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)
    sort = [{"_shard_doc": "desc"}]

    adapter.search(
        pit={"id": "os-pit", "keep_alive": "1m"},
        query={"match_all": {}},
        search_after=[10, "doc"],
        size=100,
        sort=sort,
        _source=["id", "event"],
    )

    raw.search.assert_called_once_with(
        body={
            "pit": {"id": "os-pit", "keep_alive": "1m"},
            "query": {"match_all": {}},
            "search_after": [10, "doc"],
            "size": 100,
            "sort": [{"_doc": "desc"}],
            "_source": ["id", "event"],
        },
    )
    assert sort == [{"_shard_doc": "desc"}]


def test_opensearch_pit_open_call_translates_to_create_pit_api():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    adapter.open_point_in_time(index="alert", keep_alive="1m", preference="_local")

    raw.create_pit.assert_called_once_with(index="alert", params={"keep_alive": "1m", "preference": "_local"})


def test_opensearch_pit_open_response_normalizes_pit_id_to_id():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    response = adapter.open_point_in_time(index="alert", keep_alive="1m")

    assert response == {"id": "os-pit"}


def test_opensearch_pit_close_call_translates_to_delete_pit_body():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    response = adapter.close_point_in_time(id="os-pit")

    assert response == {"pits": [{"pit_id": "os-pit", "successful": True}]}
    raw.delete_pit.assert_called_once_with(body={"pit_id": ["os-pit"]})


def test_opensearch_pit_exceptions_are_wrapped():
    raw = make_raw_client()
    original = Exception("pit failed")
    original.status_code = 503
    raw.create_pit.side_effect = original
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    with pytest.raises(SearchBackendException) as exc:
        adapter.open_point_in_time(index="alert", keep_alive="1m")

    assert exc.value.status_code == 503
    assert exc.value.original is original


def test_missing_opensearch_pit_support_fails_clearly():
    raw = make_raw_client()
    delattr(raw, "create_pit")
    delattr(raw, "delete_pit")
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    with pytest.raises(SearchBackendCompatibilityError, match="create_pit"):
        adapter.open_point_in_time(index="alert", keep_alive="1m")

    with pytest.raises(SearchBackendCompatibilityError, match="delete_pit"):
        adapter.close_point_in_time(id="os-pit")


def test_opensearch_update_translates_script_to_body():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    adapter.update(index="alert", id="1", script={"source": "ctx._source.count += 1"}, retry_on_conflict=3)

    raw.update.assert_called_once_with(
        index="alert",
        id="1",
        body={"script": {"source": "ctx._source.count += 1"}},
        retry_on_conflict=3,
    )


def test_exceptions_normalize_to_status_and_internal_type():
    original = Exception("missing")
    original.status_code = 404

    normalized = SearchClientAdapter.normalize_exception(original)

    assert isinstance(normalized, SearchBackendException)
    assert normalized.status_code == 404
    assert normalized.message == "missing"
    assert normalized.original is original


def test_opensearch_client_exceptions_are_wrapped():
    raw = make_raw_client()
    original = Exception("too busy")
    original.status_code = 429
    raw.search.side_effect = original
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    with pytest.raises(SearchBackendException) as exc:
        adapter.search(index="alert", query={"match_all": {}})

    assert exc.value.status_code == 429
    assert exc.value.original is original


def test_unsupported_opensearch_operations_fail_clearly():
    adapter = SearchClientAdapter(make_raw_client(), SearchBackend.OPENSEARCH)

    with pytest.raises(UnsupportedSearchBackendOperation):
        adapter.indices.delete(index="alert")

    with pytest.raises(UnsupportedSearchBackendOperation):
        adapter.cluster.health()


def test_elasticsearch_delegates_existing_unsupported_operation_to_raw_client():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.ELASTICSEARCH)

    adapter.indices.clear_cache(index="alert")

    raw.indices.clear_cache.assert_called_once_with(index="alert")


def test_opensearch_rejects_same_unsupported_operation_clearly():
    adapter = SearchClientAdapter(make_raw_client(), SearchBackend.OPENSEARCH)

    with pytest.raises(UnsupportedSearchBackendOperation, match="indices.clear_cache"):
        adapter.indices.clear_cache(index="alert")


def test_elasticsearch_adapter_preserves_not_found_exception():
    raw = make_raw_client()
    not_found = elasticsearch.NotFoundError("missing", make_response_meta(404), {"error": {"type": "not_found"}})
    raw.get.side_effect = not_found
    adapter = SearchClientAdapter(raw, SearchBackend.ELASTICSEARCH)

    with pytest.raises(elasticsearch.NotFoundError) as exc:
        adapter.get(index="alert", id="missing")

    assert exc.value is not_found


def test_elasticsearch_conflict_status_extraction_and_retry_exception():
    conflict = elasticsearch.ConflictError("conflict", make_response_meta(409), {"updated": 2, "deleted": 1})
    store = object.__new__(ESStore)

    assert SearchClientAdapter.get_exception_status(conflict) == 409
    with pytest.raises(VersionConflictException):
        store.with_retries(Mock(side_effect=conflict), index="alert", raise_conflicts=True)


def test_opensearch_normalized_status_extraction():
    original = Exception("conflict")
    original.status_code = 409

    normalized = SearchClientAdapter.normalize_exception(original)

    assert SearchClientAdapter.get_exception_status(normalized) == 409
    assert normalized.status_code == 409


def test_unexpected_backend_exception_is_not_ignored():
    store = object.__new__(ESStore)
    unexpected = SearchBackendException("unexpected", status_code=500)

    with pytest.raises(SearchBackendException) as exc:
        store.with_retries(Mock(side_effect=unexpected), index="alert")

    assert exc.value is unexpected


def test_collection_update_does_not_ignore_unexpected_backend_exception():
    collection = object.__new__(ESCollection)
    collection._validate_operations = Mock(return_value=[])
    collection._create_scripts_from_operations = Mock(return_value={"source": "ctx._source.count += 1"})
    collection.get_index_list = Mock(return_value=["alert"])
    collection.datastore = SimpleNamespace(client=SimpleNamespace(update=Mock()))
    collection.with_retries = Mock(side_effect=SearchBackendException("unexpected", status_code=500))

    with pytest.raises(SearchBackendException):
        collection.update("missing", [], index_type=None)
