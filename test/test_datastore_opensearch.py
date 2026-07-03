import json
import os
import uuid
from copy import deepcopy

import pytest

from assemblyline.common import forge
from assemblyline.datastore.compat import SearchBackend, SearchBackendException
from assemblyline.datastore.exceptions import DataStoreException
from assemblyline.datastore.support.build import build_mapping
from assemblyline.odm.models.config import Config
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.file import File
from assemblyline.odm.models.result import Section
from assemblyline.odm.models.submission import Submission


INDEX_SETTINGS = {
    "index": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
    "analysis": {
        "analyzer": {
            "text_whitespace": {
                "type": "whitespace",
            },
        },
        "normalizer": {
            "lowercase_normalizer": {
                "type": "custom",
                "char_filter": [],
                "filter": ["lowercase"],
            },
        },
    },
}

BASE_PROPERTIES = {
    "id": {
        "type": "keyword",
        "store": True,
        "doc_values": True,
        "copy_to": "__text__",
    },
    "__text__": {
        "type": "text",
        "store": False,
    },
    "keyword_s": {
        "type": "keyword",
        "store": True,
        "normalizer": "lowercase_normalizer",
    },
    "text_t": {
        "type": "text",
        "store": True,
        "analyzer": "text_whitespace",
    },
    "date_dt": {
        "type": "date",
        "format": "date_optional_time||epoch_millis",
        "store": True,
    },
    "ip_ip": {
        "type": "ip",
        "store": True,
    },
    "nested_items": {
        "type": "nested",
        "properties": {
            "name": {"type": "keyword"},
            "count": {"type": "integer"},
        },
    },
    "object_data": {
        "type": "object",
        "properties": {
            "flag": {"type": "keyword"},
            "count": {"type": "integer"},
        },
    },
    "wildcard_w": {
        "type": "wildcard",
    },
    "count_i": {
        "type": "integer",
        "store": True,
    },
}


def _model_mapping(*fields):
    properties, dynamic_templates = build_mapping(fields, allow_refuse_implicit=False)
    return {
        "dynamic": True,
        "properties": properties,
        "dynamic_templates": dynamic_templates,
    }


def _contains_mapping_type(mapping, mapping_type):
    if isinstance(mapping, dict):
        if mapping.get("type") == mapping_type:
            return True
        return any(_contains_mapping_type(value, mapping_type) for value in mapping.values())
    if isinstance(mapping, list):
        return any(_contains_mapping_type(value, mapping_type) for value in mapping)
    return False


def _template(mapping, name):
    return next(template[name] for template in mapping["dynamic_templates"] if name in template)


def _test_mappings():
    actual_model_mappings = _model_mapping(
        Submission.fields()["metadata"],
        Section.fields()["safelisted_tags"],
    )
    mappings = deepcopy(actual_model_mappings)
    mappings["properties"].update(deepcopy(BASE_PROPERTIES))
    return mappings


INDEX_MAPPINGS = _test_mappings()

ALERT_METADATA_MAPPINGS = _model_mapping(Alert.fields()["metadata"])
SUBMISSION_METADATA_MAPPINGS = _model_mapping(Submission.fields()["metadata"])
SAFELISTED_TAGS_MAPPINGS = _model_mapping(Section.fields()["safelisted_tags"])

EXPECTED_METADATA_TEMPLATE = {
    "path_match": "metadata.*",
    "mapping": {
        "type": "wildcard",
        "copy_to": "__text__",
    },
}

EXPECTED_SAFELISTED_TAGS_TEMPLATE = {
    "path_match": "safelisted_tags.*",
    "mapping": {
        "type": "keyword",
    },
}

OPENSEARCH_METADATA_TEMPLATE = {
    "path_match": "metadata.*",
    "mapping": {
        "type": "keyword",
        "copy_to": "__text__",
    },
}


def _create_index(client, index, alias=None):
    response = client.indices.create(index=index, mappings=INDEX_MAPPINGS, settings=INDEX_SETTINGS)
    assert response["acknowledged"] is True
    if alias:
        assert client.indices.put_alias(index=index, name=alias)["acknowledged"] is True


def _refresh(client, index):
    response = client.indices.refresh(index=index)
    assert response["_shards"]["failed"] == 0


def _hit_ids(response):
    return [hit["_source"]["id"] for hit in response["hits"]["hits"]]


def _sample_doc(doc_id, **overrides):
    doc = {
        "id": doc_id,
        "keyword_s": "Alpha",
        "text_t": "hello OpenSearch",
        "date_dt": "2026-07-03T12:00:00.000Z",
        "ip_ip": "192.0.2.10",
        "nested_items": [{"name": "one", "count": 1}],
        "object_data": {"flag": "blue", "count": 7},
        "metadata": {"campaign": "Alpha-2026", "submitter_team": "Blue Team"},
        "safelisted_tags": {"network.static.ip": ["192.0.2.10"], "file.name": ["safe.exe"]},
        "wildcard_w": "service/example/path",
        "count_i": 10,
    }
    doc.update(overrides)
    return doc


def test_opensearch_connection_info_and_ping(opensearch_client):
    info = opensearch_client.info()

    assert opensearch_client.ping() is True
    assert info["version"]["distribution"] == "opensearch"
    assert info["version"]["number"].startswith("2.12.")


def test_opensearch_index_mapping_alias_and_refresh(opensearch_client):
    index = opensearch_client.make_index_name("mapping")
    alias = opensearch_client.make_index_name("mapping_alias")

    assert opensearch_client.indices.exists(index=index) is False
    _create_index(opensearch_client, index, alias=alias)

    assert opensearch_client.indices.exists(index=index) is True
    assert opensearch_client.indices.exists_alias(name=alias) is True
    _refresh(opensearch_client, alias)

    index_data = opensearch_client.indices.get(index=index)[index]
    properties = index_data["mappings"]["properties"]
    settings = index_data["settings"]["index"]

    assert settings["number_of_shards"] == "1"
    assert settings["number_of_replicas"] == "0"
    assert properties["keyword_s"]["type"] == "keyword"
    assert properties["keyword_s"]["normalizer"] == "lowercase_normalizer"
    assert properties["text_t"]["type"] == "text"
    assert properties["text_t"]["analyzer"] == "text_whitespace"
    assert properties["date_dt"]["type"] == "date"
    assert properties["ip_ip"]["type"] == "ip"
    assert properties["nested_items"]["type"] == "nested"
    assert properties["object_data"].get("type", "object") == "object"
    assert properties["wildcard_w"]["type"] == "keyword"
    assert _template(index_data["mappings"], "metadata.*_wildcard_tpl") == OPENSEARCH_METADATA_TEMPLATE
    assert _template(index_data["mappings"], "safelisted_tags.*_wildcard_tpl") == EXPECTED_SAFELISTED_TAGS_TEMPLATE


def test_opensearch_supported_model_mappings_do_not_use_native_flattened():
    # OpenSearch flat_object is not behaviorally equivalent to Elasticsearch flattened.
    assert _template(ALERT_METADATA_MAPPINGS, "metadata.*_wildcard_tpl") == EXPECTED_METADATA_TEMPLATE
    assert _template(SUBMISSION_METADATA_MAPPINGS, "metadata.*_wildcard_tpl") == EXPECTED_METADATA_TEMPLATE
    assert _template(SAFELISTED_TAGS_MAPPINGS, "safelisted_tags.*_wildcard_tpl") == EXPECTED_SAFELISTED_TAGS_TEMPLATE
    assert not _contains_mapping_type(ALERT_METADATA_MAPPINGS, "flattened")
    assert not _contains_mapping_type(SUBMISSION_METADATA_MAPPINGS, "flattened")
    assert not _contains_mapping_type(SAFELISTED_TAGS_MAPPINGS, "flattened")
    assert not _contains_mapping_type(INDEX_MAPPINGS, "flattened")


def test_opensearch_crud_and_version_fields(opensearch_client):
    index = opensearch_client.make_index_name("crud")
    _create_index(opensearch_client, index)

    doc = _sample_doc("doc-1")
    created = opensearch_client.index(index=index, id="doc-1", document=json.dumps(doc), op_type="create", refresh=True)
    assert created["result"] == "created"
    assert "_seq_no" in created
    assert "_primary_term" in created

    assert opensearch_client.exists(index=index, id="doc-1", _source=False) is True
    fetched = opensearch_client.get(index=index, id="doc-1")
    assert fetched["_source"]["keyword_s"] == "Alpha"

    updated = opensearch_client.update(
        index=index,
        id="doc-1",
        script={"lang": "painless", "source": "ctx._source.count_i += params.value", "params": {"value": 5}},
        refresh=True,
    )
    assert updated["result"] == "updated"
    assert opensearch_client.get(index=index, id="doc-1")["_source"]["count_i"] == 15

    deleted = opensearch_client.delete(index=index, id="doc-1", refresh=True)
    assert deleted["result"] == "deleted"
    assert opensearch_client.exists(index=index, id="doc-1", _source=False) is False


def test_opensearch_mget_bulk_and_bulk_errors(opensearch_client):
    index = opensearch_client.make_index_name("bulk")
    _create_index(opensearch_client, index)

    operations = "\n".join([
        json.dumps({"create": {"_index": index, "_id": "doc-1"}}),
        json.dumps(_sample_doc("doc-1")),
        json.dumps({"create": {"_index": index, "_id": "doc-2"}}),
        json.dumps(_sample_doc("doc-2", keyword_s="Beta", count_i=20)),
        json.dumps({"update": {"_index": index, "_id": "doc-2"}}),
        json.dumps({"doc": {"count_i": 25}}),
    ])
    result = opensearch_client.bulk(operations=operations, refresh=True)
    assert result["errors"] is False

    docs = opensearch_client.mget(index=index, ids=["doc-1", "doc-2", "missing"])["docs"]
    assert [doc["found"] for doc in docs] == [True, True, False]
    assert docs[1]["_source"]["count_i"] == 25

    duplicate = "\n".join([
        json.dumps({"create": {"_index": index, "_id": "doc-1"}}),
        json.dumps(_sample_doc("doc-1")),
    ])
    duplicate_result = opensearch_client.bulk(operations=duplicate, refresh=True)
    assert duplicate_result["errors"] is True
    assert duplicate_result["items"][0]["create"]["status"] == 409

    delete_result = opensearch_client.bulk(
        operations=json.dumps({"delete": {"_index": index, "_id": "doc-1"}}),
        refresh=True,
    )
    assert delete_result["errors"] is False
    assert opensearch_client.exists(index=index, id="doc-1", _source=False) is False


def test_opensearch_actual_metadata_and_safelisted_tag_behavior(opensearch_client):
    index = opensearch_client.make_index_name("metadata")
    _create_index(opensearch_client, index)

    doc = _sample_doc(
        "doc-1",
        metadata={
            "campaign": "Alpha-2026",
            "submitter_team": "Blue Team",
            "ingest_id": "INGEST-42",
        },
        safelisted_tags={
            "network.static.ip": ["192.0.2.10"],
            "file.name": ["safe.exe"],
        },
    )
    created = opensearch_client.index(index=index, id="doc-1", document=json.dumps(doc), refresh=True)
    assert created["result"] == "created"

    fetched = opensearch_client.get(index=index, id="doc-1")
    assert fetched["_source"]["metadata"] == doc["metadata"]

    exact = opensearch_client.search(
        index=index,
        query={"term": {"metadata.campaign": "Alpha-2026"}},
        _source=["id", "metadata"],
    )
    assert [hit["_source"]["id"] for hit in exact["hits"]["hits"]] == ["doc-1"]

    wildcard = opensearch_client.search(
        index=index,
        query={"wildcard": {"metadata.campaign": "Alpha-*"}},
        _source=["id"],
    )
    assert [hit["_source"]["id"] for hit in wildcard["hits"]["hits"]] == ["doc-1"]

    exists = opensearch_client.search(
        index=index,
        query={"exists": {"field": "metadata.submitter_team"}},
        _source=["id"],
    )
    assert [hit["_source"]["id"] for hit in exists["hits"]["hits"]] == ["doc-1"]

    copied_text = opensearch_client.search(
        index=index,
        query={"query_string": {"default_field": "__text__", "query": '"Blue Team"'}},
        _source=["id"],
    )
    assert [hit["_source"]["id"] for hit in copied_text["hits"]["hits"]] == ["doc-1"]

    safelisted_tag = opensearch_client.search(
        index=index,
        query={"term": {"safelisted_tags.network.static.ip": "192.0.2.10"}},
        _source=["id"],
    )
    assert [hit["_source"]["id"] for hit in safelisted_tag["hits"]["hits"]] == ["doc-1"]

    properties = opensearch_client.indices.get(index=index)[index]["mappings"]["properties"]
    assert properties["metadata"]["properties"]["campaign"]["type"] == "keyword"
    assert properties["metadata"]["properties"]["campaign"]["copy_to"] == ["__text__"]
    assert properties["metadata"]["properties"]["submitter_team"]["type"] == "keyword"
    assert properties["safelisted_tags"]["properties"]["network"]["properties"]["static"]["properties"]["ip"]["type"] == "keyword"


def test_opensearch_metadata_keyword_translation_edge_cases(opensearch_client):
    index = opensearch_client.make_index_name("metadata_edges")
    _create_index(opensearch_client, index)

    near_keyword_limit = "n" * 32766
    doc = _sample_doc(
        "doc-edge",
        metadata={
            "plain": "simple",
            "mixed_case": "MiXeDCase",
            "punctuation": "big-bad value",
            "url": "https://example.com/a/b?x=1&token=Alpha",
            "path": r"C:\Users\Alice\AppData\Local\Temp\payload.exe",
            "command": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
            "unicode": "caf\u00e9 \u2603",
            "long_257": "l" * 257,
            "near_limit": near_keyword_limit,
            "secondary": "Beta-2026",
            "regex_value": "abbbc",
        },
    )
    created = opensearch_client.index(index=index, id="doc-edge", document=json.dumps(doc), refresh=True)
    assert created["result"] == "created"

    fetched = opensearch_client.get(index=index, id="doc-edge")
    assert fetched["_source"]["metadata"] == doc["metadata"]

    assert _hit_ids(opensearch_client.search(
        index=index,
        query={"term": {"metadata.plain": "simple"}},
        _source=["id"],
    )) == ["doc-edge"]
    assert _hit_ids(opensearch_client.search(
        index=index,
        query={"term": {"metadata.long_257": "l" * 257}},
        _source=["id"],
    )) == ["doc-edge"]
    assert _hit_ids(opensearch_client.search(
        index=index,
        query={"term": {"metadata.near_limit": near_keyword_limit}},
        _source=["id"],
    )) == ["doc-edge"]
    assert _hit_ids(opensearch_client.search(
        index=index,
        query={"wildcard": {"metadata.secondary": "*-2026"}},
        _source=["id"],
    )) == ["doc-edge"]
    assert _hit_ids(opensearch_client.search(
        index=index,
        query={"wildcard": {"metadata.secondary": "Beta-*"}},
        _source=["id"],
    )) == ["doc-edge"]
    assert _hit_ids(opensearch_client.search(
        index=index,
        query={"wildcard": {"metadata.url": "*example.com/a/b*"}},
        _source=["id"],
    )) == ["doc-edge"]
    assert _hit_ids(opensearch_client.search(
        index=index,
        query={"query_string": {"query": r"metadata.punctuation:big\-bad\ value"}},
        _source=["id"],
    )) == ["doc-edge"]
    assert _hit_ids(opensearch_client.search(
        index=index,
        query={"regexp": {"metadata.regex_value": "ab+c"}},
        _source=["id"],
    )) == ["doc-edge"]
    assert _hit_ids(opensearch_client.search(
        index=index,
        query={"exists": {"field": "metadata.command"}},
        _source=["id"],
    )) == ["doc-edge"]
    assert _hit_ids(opensearch_client.search(
        index=index,
        query={"query_string": {"default_field": "__text__", "query": "EncodedCommand"}},
        _source=["id"],
    )) == ["doc-edge"]

    assert opensearch_client.search(
        index=index,
        query={"term": {"metadata.mixed_case": "mixedcase"}},
        _source=["id"],
    )["hits"]["total"]["value"] == 0
    assert _hit_ids(opensearch_client.search(
        index=index,
        query={"term": {"metadata.mixed_case": "MiXeDCase"}},
        _source=["id"],
    )) == ["doc-edge"]

    metadata_mapping = opensearch_client.indices.get(index=index)[index]["mappings"]["properties"]["metadata"]["properties"]
    for key in ("plain", "mixed_case", "url", "path", "command", "unicode", "long_257", "near_limit", "secondary"):
        assert metadata_mapping[key]["type"] == "keyword"
        assert metadata_mapping[key]["copy_to"] == ["__text__"]
        assert "ignore_above" not in metadata_mapping[key]
        assert "normalizer" not in metadata_mapping[key]
        assert metadata_mapping[key].get("doc_values", True) is True

    settings = opensearch_client.indices.get(index=index)[index]["settings"]["index"]
    assert "allow_expensive_queries" not in settings.get("search", {})

    too_long_doc = _sample_doc("doc-too-long", metadata={"too_long": "x" * 32767})
    with pytest.raises(SearchBackendException) as err:
        opensearch_client.index(index=index, id="doc-too-long", document=json.dumps(too_long_doc), refresh=True)

    assert err.value.status_code == 400
    _refresh(opensearch_client, index)
    assert opensearch_client.exists(index=index, id="doc-too-long", _source=False) is False


def test_opensearch_search_queries_filters_sort_source_aggregation_and_totals(opensearch_client):
    index = opensearch_client.make_index_name("search")
    _create_index(opensearch_client, index)

    operations = "\n".join([
        json.dumps({"create": {"_index": index, "_id": "doc-1"}}),
        json.dumps(_sample_doc("doc-1", keyword_s="Alpha", count_i=10, ip_ip="192.0.2.10")),
        json.dumps({"create": {"_index": index, "_id": "doc-2"}}),
        json.dumps(_sample_doc("doc-2", keyword_s="Beta", count_i=20, ip_ip="192.0.2.20")),
        json.dumps({"create": {"_index": index, "_id": "doc-3"}}),
        json.dumps(_sample_doc("doc-3", keyword_s="Alpha", count_i=30, ip_ip="192.0.2.30")),
    ])
    assert opensearch_client.bulk(operations=operations, refresh=True)["errors"] is False

    response = opensearch_client.search(
        index=index,
        query={
            "bool": {
                "must": {"query_string": {"query": "text_t:OpenSearch"}},
                "filter": [{"range": {"count_i": {"gte": 10}}}],
            }
        },
        sort=[{"count_i": "desc"}],
        _source=["id", "keyword_s", "count_i"],
        aggregations={"keywords": {"terms": {"field": "keyword_s"}}},
        track_total_hits=True,
        size=2,
    )

    assert response["hits"]["total"]["value"] == 3
    assert [hit["_source"]["id"] for hit in response["hits"]["hits"]] == ["doc-3", "doc-2"]
    assert set(response["hits"]["hits"][0]["_source"].keys()) == {"id", "keyword_s", "count_i"}
    assert response["aggregations"]["keywords"]["buckets"][0]["doc_count"] == 2


def test_opensearch_point_in_time_search_after_and_close(opensearch_client):
    index = opensearch_client.make_index_name("pit")
    _create_index(opensearch_client, index)

    operations = "\n".join([
        json.dumps({"create": {"_index": index, "_id": "doc-1"}}),
        json.dumps(_sample_doc("doc-1", count_i=1)),
        json.dumps({"create": {"_index": index, "_id": "doc-2"}}),
        json.dumps(_sample_doc("doc-2", count_i=2)),
        json.dumps({"create": {"_index": index, "_id": "doc-3"}}),
        json.dumps(_sample_doc("doc-3", count_i=3)),
    ])
    assert opensearch_client.bulk(operations=operations, refresh=True)["errors"] is False

    pit = opensearch_client.open_point_in_time(index=index, keep_alive="1m")
    assert set(pit) == {"id"}

    try:
        first_page = opensearch_client.search(
            pit={"id": pit["id"], "keep_alive": "1m"},
            query={"match_all": {}},
            sort=[{"count_i": "asc"}, {"_shard_doc": "desc"}],
            _source=["id", "count_i"],
            size=2,
        )
        assert [hit["_source"]["id"] for hit in first_page["hits"]["hits"]] == ["doc-1", "doc-2"]
        assert "pit_id" in first_page

        second_page = opensearch_client.search(
            pit={"id": first_page["pit_id"], "keep_alive": "1m"},
            query={"match_all": {}},
            search_after=first_page["hits"]["hits"][-1]["sort"],
            sort=[{"count_i": "asc"}, {"_shard_doc": "desc"}],
            _source=["id", "count_i"],
            size=2,
        )
        assert [hit["_source"]["id"] for hit in second_page["hits"]["hits"]] == ["doc-3"]
    finally:
        response = opensearch_client.close_point_in_time(id=pit["id"])
        assert response["pits"][0]["successful"] is True


def test_opensearch_full_datastore_construction_via_forge(request):
    host = os.environ.get('AL_TEST_OPENSEARCH_HOST', 'http://127.0.0.1:9201')
    collection_name = f"al_os_forge_{uuid.uuid4().hex}"
    config_data = Config().as_primitives()
    config_data["datastore"]["type"] = "opensearch"
    config_data["datastore"]["hosts"] = [host]
    config_data["datastore"]["archive"]["enabled"] = False

    datastore = forge.get_datastore(config=Config(config_data))

    def cleanup():
        try:
            if datastore.ds.client:
                datastore.ds.client.raw_client.indices.delete(index=f"{collection_name}*", ignore_unavailable=True)
        finally:
            if not datastore.ds.is_closed():
                datastore.ds.close()

    request.addfinalizer(cleanup)

    assert datastore.ds.backend == SearchBackend.OPENSEARCH
    assert datastore.ds.client.info()["version"]["distribution"] == "opensearch"
    assert datastore.ds.ping() is True

    datastore.ds.register(collection_name)
    collection = datastore.ds.__getattr__(collection_name)
    assert collection.save("doc-1", {"keyword_s": "Alpha", "text_t": "hello OpenSearch"}, refresh=True)
    assert collection.get("doc-1", as_obj=False)["keyword_s"] == "Alpha"

    search = collection.search("keyword_s:Alpha", rows=10, fl="id,keyword_s", as_obj=False, track_total_hits=True)
    assert search["total"] == 1
    assert search["items"] == [{"id": "doc-1", "keyword_s": "Alpha"}]

    pit_page = collection.search("id:*", rows=1, fl="id", as_obj=False, deep_paging_id="start")
    assert pit_page["items"] == [{"id": "doc-1"}]

    assert collection.delete("doc-1")
    datastore.ds.client.indices.refresh(index=collection_name)
    assert collection.search("id:doc-1", rows=10, fl="id", as_obj=False, track_total_hits=True)["total"] == 0

    datastore.ds.client.raw_client.indices.delete(index=f"{collection_name}*", ignore_unavailable=True)
    datastore.ds.close()
    assert datastore.ds.is_closed()


def test_opensearch_runtime_smoke_uses_factory_models_commit_pit_and_delete(request):
    host = os.environ.get('AL_TEST_OPENSEARCH_HOST', 'http://127.0.0.1:9201')
    config_data = Config().as_primitives()
    config_data["datastore"]["type"] = "opensearch"
    config_data["datastore"]["hosts"] = [host]
    config_data["datastore"]["archive"]["enabled"] = False

    datastore = forge.get_datastore(config=Config(config_data))
    doc_id = "0" * 64

    def cleanup():
        try:
            if datastore.ds.client:
                datastore.ds.client.raw_client.indices.delete(index="file_hot", ignore_unavailable=True)
        finally:
            if not datastore.ds.is_closed():
                datastore.ds.close()

    request.addfinalizer(cleanup)

    assert datastore.ds.backend == SearchBackend.OPENSEARCH
    assert datastore.ds.client.info()["version"]["distribution"] == "opensearch"
    assert datastore.ds.ping() is True

    file_collection = datastore.file
    assert datastore.submission.name == "submission"
    assert datastore.alert.name == "alert"

    document = File({
        "ascii": "hello world.",
        "classification": "U",
        "entropy": 0.0,
        "hex": "68656c6c6f20776f726c642e",
        "magic": "ASCII text",
        "md5": "0" * 32,
        "sha1": "0" * 40,
        "sha256": doc_id,
        "size": 12,
        "ssdeep": "3:abc:abc",
        "type": "unknown",
    })
    assert file_collection.save(doc_id, document)
    assert file_collection.commit()

    fetched = file_collection.get(doc_id)
    assert fetched.sha256 == doc_id
    assert fetched.type == "unknown"

    search = file_collection.search("sha256:" + doc_id, rows=10, fl="id,sha256,type", as_obj=False,
                                    track_total_hits=True)
    assert search["total"] == 1
    assert search["items"] == [{"id": doc_id, "sha256": doc_id, "type": "unknown"}]

    pit_page = file_collection.search("sha256:" + doc_id, rows=1, fl="id", as_obj=False, deep_paging_id="start")
    assert pit_page["items"] == [{"id": doc_id}]

    assert file_collection.delete(doc_id)
    assert file_collection.commit()
    assert file_collection.search("sha256:" + doc_id, rows=10, fl="id", as_obj=False,
                                  track_total_hits=True)["total"] == 0

    datastore.ds.close()
    assert datastore.ds.is_closed()


def _opensearch_datastore(request, collection_name):
    host = os.environ.get('AL_TEST_OPENSEARCH_HOST', 'http://127.0.0.1:9201')
    config_data = Config().as_primitives()
    config_data["datastore"]["type"] = "opensearch"
    config_data["datastore"]["hosts"] = [host]
    config_data["datastore"]["archive"]["enabled"] = False

    datastore = forge.get_datastore(config=Config(config_data))
    datastore.ds.task_wait_timeout = 30

    def cleanup():
        try:
            if datastore.ds.client:
                datastore.ds.client.raw_client.indices.delete(index=f"{collection_name}*", ignore_unavailable=True)
        finally:
            if not datastore.ds.is_closed():
                datastore.ds.close()

    request.addfinalizer(cleanup)
    datastore.ds.register(collection_name)
    return datastore, datastore.ds.__getattr__(collection_name)


def test_opensearch_delete_by_query_async_task_via_datastore(request):
    collection_name = f"al_os_dbq_{uuid.uuid4().hex}"
    datastore, collection = _opensearch_datastore(request, collection_name)

    for doc_id, group in (("delete-1", "delete"), ("delete-2", "delete"), ("keep-1", "keep")):
        assert collection.save(doc_id, {"group": group, "count": 1})
    assert collection.commit()

    deleted = collection.delete_by_query("group:delete")
    assert deleted == 2
    assert collection.commit()

    remaining = collection.search("id:*", rows=10, fl="id,group", as_obj=False, track_total_hits=True)
    assert remaining["total"] == 1
    assert remaining["items"] == [{"id": "keep-1", "group": "keep"}]

    task = datastore.ds.client.delete_by_query(
        index=collection_name,
        query={"term": {"group": "missing"}},
        wait_for_completion=False,
        conflicts="proceed",
    )
    task_response = datastore.ds._get_task_results(task)
    assert task_response["deleted"] == 0
    assert task_response["version_conflicts"] == 0


def test_opensearch_update_by_query_async_task_and_ui_style_update(request):
    collection_name = f"al_os_ubq_{uuid.uuid4().hex}"
    _, collection = _opensearch_datastore(request, collection_name)

    for doc_id, group in (("update-1", "update"), ("update-2", "update"), ("keep-1", "keep")):
        assert collection.save(doc_id, {"group": group, "count": 1, "owner": "old"})
    assert collection.commit()

    updated = collection.update_by_query("group:update", [(collection.UPDATE_INC, "count", 4)])
    assert updated == 2
    assert collection.commit()

    update_docs = collection.search("group:update", rows=10, fl="id,count,owner", as_obj=False, track_total_hits=True)
    assert update_docs["total"] == 2
    assert {item["count"] for item in update_docs["items"]} == {5}

    keep_doc = collection.get("keep-1", as_obj=False)
    assert keep_doc["count"] == 1
    assert keep_doc["owner"] == "old"

    ui_style_updated = collection.update_by_query(
        "id:update-1",
        [(collection.UPDATE_SET, "owner", "analyst")],
        filters=["group:update"],
    )
    assert ui_style_updated == 1
    assert collection.commit()
    assert collection.get("update-1", as_obj=False)["owner"] == "analyst"
    assert collection.get("update-2", as_obj=False)["owner"] == "old"


def test_opensearch_update_by_query_task_failure_is_visible(request):
    collection_name = f"al_os_ubq_fail_{uuid.uuid4().hex}"
    _, collection = _opensearch_datastore(request, collection_name)

    assert collection.save("bad-1", {"group": "bad", "count": 1})
    assert collection.commit()

    with pytest.raises(DataStoreException, match="failed"):
        collection._update_async(
            collection_name,
            {"lang": "painless", "source": "ctx._source.count += "},
            {"term": {"group": "bad"}},
        )


def test_opensearch_task_cleanup_uses_service_identity(request):
    host = os.environ.get('AL_TEST_OPENSEARCH_HOST', 'http://127.0.0.1:9201')
    config_data = Config().as_primitives()
    config_data["datastore"]["type"] = "opensearch"
    config_data["datastore"]["hosts"] = [host]
    config_data["datastore"]["archive"]["enabled"] = False

    datastore = forge.get_datastore(config=Config(config_data))
    datastore.ds.task_wait_timeout = 30
    collection_name = f"al_os_task_cleanup_{uuid.uuid4().hex}"

    def cleanup():
        try:
            if datastore.ds.client:
                datastore.ds.client.raw_client.indices.delete(index=collection_name, ignore_unavailable=True)
        finally:
            if not datastore.ds.is_closed():
                datastore.ds.close()

    request.addfinalizer(cleanup)

    datastore.ds.register(collection_name)
    collection = datastore.ds.__getattr__(collection_name)
    for doc_id in ("delete-1", "delete-2", "keep-1"):
        assert collection.save(doc_id, {"group": "delete" if doc_id.startswith("delete") else "keep"})
    assert collection.commit()

    task = datastore.ds.client.delete_by_query(
        index=collection_name,
        query={"term": {"group": "delete"}},
        wait_for_completion=False,
        conflicts="proceed",
    )
    task_response = datastore.ds._get_task_results(task)
    assert task_response["deleted"] == 2

    datastore.ds.client.indices.refresh(index=".tasks")
    assert datastore.ds.client.exists(index=".tasks", id=task["task"], _source=False) is True

    datastore.ds.switch_user("plumber")
    deleted_tasks = datastore.task_cleanup()

    datastore.ds.client.indices.refresh(index=".tasks")
    assert deleted_tasks >= 1
    assert datastore.ds.client.exists(index=".tasks", id=task["task"], _source=False) is False
    assert collection.get("keep-1", as_obj=False)["group"] == "keep"
