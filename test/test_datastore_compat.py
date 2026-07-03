from types import SimpleNamespace
from unittest.mock import Mock

import elasticsearch
import pytest
from elastic_transport import ApiResponseMeta, NodeConfig

from assemblyline.common import forge
from assemblyline.datastore.collection import ESCollection
from assemblyline.datastore.compat import (
    SearchBackend,
    SearchBackendCompatibilityError,
    SearchBackendException,
    SearchClientAdapter,
    UnsupportedSearchBackendOperation,
    create_search_client,
)
from assemblyline.datastore.exceptions import DataStoreException, UnsupportedElasticVersion, VersionConflictException
from assemblyline.datastore.store import ESStore
from assemblyline.odm.models.config import Config


def make_response_meta(status):
    return ApiResponseMeta(status, "1.1", {}, 0.0, NodeConfig("http", "localhost", 9200))


def make_raw_client():
    return SimpleNamespace(
        bulk=Mock(return_value={"errors": False}),
        close=Mock(),
        delete=Mock(return_value={"result": "deleted"}),
        delete_by_query=Mock(return_value={"task": "node:1"}),
        exists=Mock(return_value=True),
        get=Mock(return_value={"_id": "id", "_source": {"id": "id"}}),
        index=Mock(return_value={"result": "created"}),
        info=Mock(return_value={"version": {"number": "8.10.2"}}),
        mget=Mock(return_value={"docs": []}),
        open_point_in_time=Mock(return_value={"id": "es-pit"}),
        ping=Mock(return_value=True),
        search=Mock(return_value={"hits": {"hits": []}}),
        update=Mock(return_value={"result": "updated"}),
        update_by_query=Mock(return_value={"task": "node:2"}),
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
        tasks=SimpleNamespace(get=Mock(return_value={"completed": True, "response": {"updated": 1}})),
    )


def make_store_client(version_number, distribution=None):
    version_info = {"number": version_number}
    if distribution is not None:
        version_info["distribution"] = distribution
    raw = make_raw_client()
    raw.info.return_value = {"version": version_info}
    backend = SearchBackend.OPENSEARCH if distribution == "opensearch" else SearchBackend.ELASTICSEARCH
    return SearchClientAdapter(raw, backend)


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

    adapter.delete_by_query(
        index="alert",
        query={"match_all": {}},
        wait_for_completion=False,
        conflicts="proceed",
        sort="id:asc",
        max_docs=10,
    )
    raw.delete_by_query.assert_called_once_with(
        index="alert",
        query={"match_all": {}},
        wait_for_completion=False,
        conflicts="proceed",
        sort="id:asc",
        max_docs=10,
    )

    adapter.update_by_query(
        index="alert",
        query={"match_all": {}},
        script={"source": "ctx._source.count += 1"},
        wait_for_completion=False,
        conflicts="proceed",
        max_docs=10,
    )
    raw.update_by_query.assert_called_once_with(
        index="alert",
        query={"match_all": {}},
        script={"source": "ctx._source.count += 1"},
        wait_for_completion=False,
        conflicts="proceed",
        max_docs=10,
    )

    adapter.tasks.get(task_id="node:1", wait_for_completion=True, timeout="5s")
    raw.tasks.get.assert_called_once_with(task_id="node:1", wait_for_completion=True, timeout="5s")


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


def test_opensearch_search_omits_null_body_fields():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    adapter.search(
        pit={"id": "os-pit", "keep_alive": "1m"},
        query={"match_all": {}},
        search_after=None,
        from_=0,
        size=100,
    )

    raw.search.assert_called_once_with(
        body={
            "pit": {"id": "os-pit", "keep_alive": "1m"},
            "query": {"match_all": {}},
            "from": 0,
            "size": 100,
        },
    )


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


def test_opensearch_delete_by_query_translates_query_and_supported_params():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    response = adapter.delete_by_query(
        index="alert",
        query={"term": {"workflow_id": "wf1"}},
        wait_for_completion=False,
        conflicts="proceed",
        sort="id:asc",
        max_docs=5,
    )

    assert response == {"task": "node:1"}
    raw.delete_by_query.assert_called_once_with(
        index="alert",
        body={"query": {"term": {"workflow_id": "wf1"}}, "max_docs": 5},
        params={"wait_for_completion": "false", "conflicts": "proceed", "sort": "id:asc"},
    )


def test_opensearch_update_by_query_translates_query_script_and_supported_params():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    response = adapter.update_by_query(
        index="alert",
        query={"term": {"workflow_id": "wf1"}},
        script={"source": "ctx._source.workflow_completed = true", "lang": "painless"},
        wait_for_completion=False,
        conflicts="proceed",
        max_docs=5,
    )

    assert response == {"task": "node:2"}
    raw.update_by_query.assert_called_once_with(
        index="alert",
        body={
            "query": {"term": {"workflow_id": "wf1"}},
            "script": {"source": "ctx._source.workflow_completed = true", "lang": "painless"},
            "max_docs": 5,
        },
        params={"wait_for_completion": "false", "conflicts": "proceed"},
    )


def test_opensearch_tasks_get_translates_params_and_preserves_response():
    raw = make_raw_client()
    raw.tasks.get.return_value = {
        "completed": True,
        "response": {"deleted": 2, "version_conflicts": 1},
    }
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    response = adapter.tasks.get(task_id="node:1", wait_for_completion=True, timeout="5s")

    assert response["response"]["deleted"] == 2
    assert response["response"]["version_conflicts"] == 1
    raw.tasks.get.assert_called_once_with(
        task_id="node:1",
        params={"wait_for_completion": "true"},
    )


def test_opensearch_tasks_get_preserves_task_errors():
    raw = make_raw_client()
    raw.tasks.get.return_value = {"completed": True, "error": {"type": "script_exception", "reason": "compile error"}}
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    response = adapter.tasks.get(task_id="node:1", wait_for_completion=True)

    assert response["error"]["type"] == "script_exception"


def test_opensearch_query_task_exceptions_are_wrapped():
    raw = make_raw_client()
    original = Exception("query task failed")
    original.status_code = 400
    raw.update_by_query.side_effect = original
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    with pytest.raises(SearchBackendException) as exc:
        adapter.update_by_query(index="alert", query={"match_all": {}})

    assert exc.value.status_code == 400
    assert exc.value.original is original


def test_opensearch_query_task_duplicate_body_fields_fail_clearly():
    adapter = SearchClientAdapter(make_raw_client(), SearchBackend.OPENSEARCH)

    with pytest.raises(SearchBackendCompatibilityError, match="query"):
        adapter.delete_by_query(index="alert", body={"query": {"match_all": {}}}, query={"term": {"id": "1"}})

    with pytest.raises(SearchBackendCompatibilityError, match="script"):
        adapter.update_by_query(index="alert", body={"script": {"source": "ctx.op = 'noop'"}}, script={"source": ""})


def test_opensearch_query_task_unsupported_arguments_fail_clearly():
    adapter = SearchClientAdapter(make_raw_client(), SearchBackend.OPENSEARCH)

    with pytest.raises(SearchBackendCompatibilityError, match="unsupported"):
        adapter.delete_by_query(index="alert", query={"match_all": {}}, unsupported=True)

    with pytest.raises(SearchBackendCompatibilityError, match="unsupported"):
        adapter.update_by_query(index="alert", query={"match_all": {}}, script={}, unsupported=True)

    with pytest.raises(SearchBackendCompatibilityError, match="unsupported"):
        adapter.tasks.get(task_id="node:1", unsupported=True)


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

    with pytest.raises(UnsupportedSearchBackendOperation, match="indices.delete"):
        adapter.indices.delete(index="alert")

    with pytest.raises(UnsupportedSearchBackendOperation, match="cluster.health"):
        adapter.cluster.health()

    unsupported_calls = [
        (lambda: adapter.security.put_role(name="role"), "security.put_role"),
        (lambda: adapter.security.put_user(username="user"), "security.put_user"),
        (lambda: adapter.ilm.get_lifecycle(name="policy"), "ilm.get_lifecycle"),
        (lambda: adapter.reindex(source={"index": "old"}, dest={"index": "new"}), "reindex"),
        (lambda: adapter.indices.clone(index="old", target="new"), "indices.clone"),
        (lambda: adapter.indices.split(index="old", target="new"), "indices.split"),
        (lambda: adapter.indices.shrink(index="old", target="new"), "indices.shrink"),
        (lambda: adapter.indices.exists_template(name="template"), "indices.exists_template"),
        (lambda: adapter.indices.delete_template(name="template"), "indices.delete_template"),
    ]

    for operation, message in unsupported_calls:
        with pytest.raises(UnsupportedSearchBackendOperation, match=message):
            operation()


def test_elasticsearch_delegates_existing_unsupported_operation_to_raw_client():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.ELASTICSEARCH)

    adapter.indices.clear_cache(index="alert")

    raw.indices.clear_cache.assert_called_once_with(index="alert")


def test_opensearch_indices_clear_cache_delegates_basic_commit_call():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    response = adapter.indices.clear_cache(index="alert")

    assert response == {"_shards": {"successful": 1}}
    raw.indices.clear_cache.assert_called_once_with(index="alert")


def test_opensearch_indices_clear_cache_moves_supported_flags_to_params():
    raw = make_raw_client()
    adapter = SearchClientAdapter(raw, SearchBackend.OPENSEARCH)

    adapter.indices.clear_cache(index="alert", fielddata=True, fields="id", request=True)

    raw.indices.clear_cache.assert_called_once_with(
        index="alert",
        params={"fielddata": True, "fields": "id", "request": True},
    )


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


def test_store_task_wait_raises_task_error():
    store = object.__new__(ESStore)
    store.client = SimpleNamespace(tasks=SimpleNamespace(get=Mock()))
    store.with_retries = Mock(return_value={
        "completed": True,
        "error": {"type": "script_exception", "reason": "compile error"},
    })

    with pytest.raises(DataStoreException, match="compile error"):
        store._get_task_results({"task": "node:1"})


def test_create_search_client_selects_elasticsearch_client(monkeypatch):
    client_class = Mock(return_value=make_raw_client())
    monkeypatch.setattr("assemblyline.datastore.compat.elasticsearch.Elasticsearch", client_class)

    adapter = create_search_client(
        SearchBackend.ELASTICSEARCH,
        ["http://elastic:9200"],
        max_retries=3,
        request_timeout=30,
        ca_certs="/tmp/ca.pem",
        verify_certs=True,
    )

    assert adapter.backend == SearchBackend.ELASTICSEARCH
    client_class.assert_called_once_with(
        hosts=["http://elastic:9200"],
        max_retries=3,
        request_timeout=30,
        ca_certs="/tmp/ca.pem",
        verify_certs=True,
    )


def test_create_search_client_selects_opensearch_client(monkeypatch):
    client_class = Mock(return_value=make_raw_client())
    monkeypatch.setattr("assemblyline.datastore.compat._load_opensearch_client", Mock(return_value=client_class))

    adapter = create_search_client(
        SearchBackend.OPENSEARCH,
        ["http://opensearch:9200"],
        max_retries=2,
        request_timeout=45,
        ca_certs=None,
        verify_certs=False,
    )

    assert adapter.backend == SearchBackend.OPENSEARCH
    client_class.assert_called_once_with(
        hosts=["http://opensearch:9200"],
        max_retries=2,
        timeout=45,
        ca_certs=None,
        verify_certs=False,
    )


def test_store_elasticsearch_version_validation_keeps_existing_minimum(monkeypatch):
    client = make_store_client("8.10.2")
    factory = Mock(return_value=client)
    monkeypatch.setattr("assemblyline.datastore.store.create_search_client", factory)

    store = ESStore(["http://elastic:9200"], backend=SearchBackend.ELASTICSEARCH)

    assert store.backend == SearchBackend.ELASTICSEARCH
    assert str(store.es_version) == "8.10.2"
    factory.assert_called_once()
    assert factory.call_args.args[0] == SearchBackend.ELASTICSEARCH


def test_store_elasticsearch_rejects_unsupported_version(monkeypatch):
    monkeypatch.setattr(
        "assemblyline.datastore.store.create_search_client",
        Mock(return_value=make_store_client("7.9.3")),
    )

    with pytest.raises(UnsupportedElasticVersion, match="Elastic version 7.9.3"):
        ESStore(["http://elastic:9200"], backend=SearchBackend.ELASTICSEARCH)


def test_store_opensearch_version_validation_uses_distribution(monkeypatch):
    client = make_store_client("2.12.0", distribution="opensearch")
    factory = Mock(return_value=client)
    monkeypatch.setattr("assemblyline.datastore.store.create_search_client", factory)

    store = ESStore(["http://opensearch:9200"], backend=SearchBackend.OPENSEARCH)

    assert store.backend == SearchBackend.OPENSEARCH
    assert str(store.es_version) == "2.12.0"
    factory.assert_called_once()
    assert factory.call_args.args[0] == SearchBackend.OPENSEARCH


def test_store_opensearch_rejects_non_opensearch_product(monkeypatch):
    monkeypatch.setattr(
        "assemblyline.datastore.store.create_search_client",
        Mock(return_value=make_store_client("8.10.2")),
    )

    with pytest.raises(UnsupportedElasticVersion, match="OpenSearch backend selected"):
        ESStore(["http://elastic:9200"], backend=SearchBackend.OPENSEARCH)


def test_store_opensearch_rejects_unsupported_version(monkeypatch):
    monkeypatch.setattr(
        "assemblyline.datastore.store.create_search_client",
        Mock(return_value=make_store_client("2.11.1", distribution="opensearch")),
    )

    with pytest.raises(UnsupportedElasticVersion, match="OpenSearch version 2.11.1"):
        ESStore(["http://opensearch:9200"], backend=SearchBackend.OPENSEARCH)


def test_store_opensearch_switch_user_keeps_service_identity(monkeypatch):
    client = make_store_client("2.12.0", distribution="opensearch")
    factory = Mock(return_value=client)
    monkeypatch.setattr("assemblyline.datastore.store.create_search_client", factory)

    store = ESStore(["http://service:secret@opensearch:9200"], backend=SearchBackend.OPENSEARCH)

    store.switch_user("plumber")

    assert store.client is client
    assert store.get_hosts() == ["http://service:secret@opensearch:9200"]
    client.raw_client.security.put_role.assert_not_called()
    client.raw_client.security.put_user.assert_not_called()
    client.raw_client.close.assert_not_called()
    assert factory.call_count == 1


def test_forge_get_datastore_defaults_to_elasticsearch(monkeypatch):
    created = []

    class FakeStore:
        def __init__(self, hosts, backend, archive_access=False, archive_alernate_dtl=0):
            created.append((hosts, backend, archive_access, archive_alernate_dtl))

        def register(self, *args, **kwargs):
            pass

    monkeypatch.setattr("assemblyline.datastore.store.ESStore", FakeStore)

    datastore = forge.get_datastore(config=Config())

    assert datastore.ds.__class__ is FakeStore
    assert created[0][1] == "elasticsearch"


def test_forge_get_datastore_uses_explicit_opensearch(monkeypatch):
    config_data = Config().as_primitives()
    config_data["datastore"]["type"] = "opensearch"
    config_data["datastore"]["hosts"] = ["http://opensearch:9200"]
    created = []

    class FakeStore:
        def __init__(self, hosts, backend, archive_access=False, archive_alernate_dtl=0):
            created.append((hosts, backend, archive_access, archive_alernate_dtl))

        def register(self, *args, **kwargs):
            pass

    monkeypatch.setattr("assemblyline.datastore.store.ESStore", FakeStore)

    datastore = forge.get_datastore(config=Config(config_data), archive_access=True)

    assert datastore.ds.__class__ is FakeStore
    assert created[0][0] == ["http://opensearch:9200"]
    assert created[0][1] == "opensearch"
    assert created[0][2] is True


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
