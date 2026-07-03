import json
from copy import deepcopy

import pytest

from assemblyline.datastore.support.build import build_mapping
from assemblyline.odm.models.alert import Alert
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
