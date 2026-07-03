from __future__ import annotations

from copy import deepcopy
from enum import Enum
from typing import Any, Callable, Optional

try:
    import elasticsearch
except ImportError:
    elasticsearch = None


class SearchBackend(str, Enum):
    ELASTICSEARCH = "elasticsearch"
    OPENSEARCH = "opensearch"


class SearchBackendException(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None, original: Optional[Exception] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.original = original


class UnsupportedSearchBackendOperation(NotImplementedError):
    pass


class SearchBackendCompatibilityError(UnsupportedSearchBackendOperation):
    pass


def _load_opensearch_client():
    try:
        from opensearchpy import OpenSearch
    except ImportError as err:
        raise ImportError("OpenSearch backend requires the optional 'opensearch-py' package.") from err
    return OpenSearch


def create_search_client(
    backend: str,
    hosts,
    *,
    max_retries: int,
    request_timeout: int,
    ca_certs: Optional[str],
    verify_certs: bool,
) -> "SearchClientAdapter":
    backend = SearchBackend(backend)
    if backend == SearchBackend.ELASTICSEARCH:
        if elasticsearch is None:
            raise ImportError("Elasticsearch backend requires the 'elasticsearch' package.")
        raw_client = elasticsearch.Elasticsearch(
            hosts=hosts,
            max_retries=max_retries,
            request_timeout=request_timeout,
            ca_certs=ca_certs,
            verify_certs=verify_certs,
        )
    elif backend == SearchBackend.OPENSEARCH:
        opensearch_client = _load_opensearch_client()
        raw_client = opensearch_client(
            hosts=hosts,
            max_retries=max_retries,
            timeout=request_timeout,
            ca_certs=ca_certs,
            verify_certs=verify_certs,
        )
    else:
        raise ValueError(f"Unsupported search backend: {backend}")

    return SearchClientAdapter(raw_client, backend)


class _UnsupportedNamespace:
    def __init__(self, namespace: str):
        self.namespace = namespace

    def __getattr__(self, name):
        raise UnsupportedSearchBackendOperation(f"{self.namespace}.{name} is not supported by this adapter slice")


class _IndicesAdapter:
    def __init__(self, adapter: "SearchClientAdapter"):
        self._adapter = adapter

    def exists(self, **kwargs):
        return self._adapter._call(self._adapter.raw_client.indices.exists, **kwargs)

    def create(self, *, index, mappings=None, settings=None, **kwargs):
        if self._adapter.backend == SearchBackend.OPENSEARCH:
            body = {}
            if mappings is not None:
                body["mappings"] = self._adapter.opensearch_compatible_mappings(mappings)
            if settings is not None:
                body["settings"] = settings
            return self._adapter._call(self._adapter.raw_client.indices.create, index=index, body=body, **kwargs)
        return self._adapter._call(
            self._adapter.raw_client.indices.create,
            index=index,
            mappings=mappings,
            settings=settings,
            **kwargs,
        )

    def put_alias(self, **kwargs):
        return self._adapter._call(self._adapter.raw_client.indices.put_alias, **kwargs)

    def exists_alias(self, **kwargs):
        return self._adapter._call(self._adapter.raw_client.indices.exists_alias, **kwargs)

    def refresh(self, **kwargs):
        return self._adapter._call(self._adapter.raw_client.indices.refresh, **kwargs)

    def clear_cache(self, **kwargs):
        if self._adapter.backend == SearchBackend.OPENSEARCH:
            params = {}
            for key in (
                "allow_no_indices",
                "expand_wildcards",
                "fielddata",
                "fields",
                "ignore_unavailable",
                "query",
                "request",
            ):
                if key in kwargs:
                    params[key] = kwargs.pop(key)
            if params:
                kwargs["params"] = params
        return self._adapter._call(self._adapter.raw_client.indices.clear_cache, **kwargs)

    def get(self, **kwargs):
        return self._adapter._call(self._adapter.raw_client.indices.get, **kwargs)

    def __getattr__(self, name):
        if self._adapter.backend == SearchBackend.ELASTICSEARCH:
            return getattr(self._adapter.raw_client.indices, name)
        raise UnsupportedSearchBackendOperation(f"indices.{name} is not supported by this adapter slice")


class _TasksAdapter:
    def __init__(self, adapter: "SearchClientAdapter"):
        self._adapter = adapter

    def get(self, **kwargs):
        if self._adapter.backend == SearchBackend.ELASTICSEARCH:
            return self._adapter._call(self._adapter.raw_client.tasks.get, **kwargs)

        # opensearch-py 2.8 treats the tasks API timeout query parameter as a
        # transport timeout, so Assemblyline enforces finite waits at ESStore.
        kwargs.pop("timeout", None)
        params = self._adapter._extract_opensearch_params(
            kwargs,
            {
                "error_trace",
                "filter_path",
                "human",
                "pretty",
                "source",
                "wait_for_completion",
            },
        )
        params.pop("timeout", None)
        self._adapter._reject_unsupported_kwargs("tasks.get", kwargs, {"task_id", "headers"})
        return self._adapter._call(self._adapter.raw_client.tasks.get, params=params or None, **kwargs)

    def __getattr__(self, name):
        if self._adapter.backend == SearchBackend.ELASTICSEARCH:
            return getattr(self._adapter.raw_client.tasks, name)
        raise UnsupportedSearchBackendOperation(f"tasks.{name} is not supported by this adapter slice")


class SearchClientAdapter:
    def __init__(self, raw_client: Any, backend: str = SearchBackend.ELASTICSEARCH):
        self.raw_client = raw_client
        self.backend = SearchBackend(backend)
        self.indices = _IndicesAdapter(self)
        if self.backend == SearchBackend.ELASTICSEARCH:
            self.cat = raw_client.cat
            self.cluster = raw_client.cluster
            self.ilm = raw_client.ilm
            self.nodes = raw_client.nodes
            self.security = raw_client.security
            self.tasks = raw_client.tasks
        else:
            self.cat = _UnsupportedNamespace("cat")
            self.cluster = _UnsupportedNamespace("cluster")
            self.ilm = _UnsupportedNamespace("ilm")
            self.nodes = _UnsupportedNamespace("nodes")
            self.security = _UnsupportedNamespace("security")
            self.tasks = _TasksAdapter(self)

    def _call(self, func: Callable, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as err:
            if self.backend == SearchBackend.ELASTICSEARCH:
                raise
            raise self.normalize_exception(err) from err

    @staticmethod
    def get_exception_status(err: Exception) -> Optional[int]:
        if isinstance(err, SearchBackendException):
            return err.status_code

        status = getattr(err, "status_code", None)
        if status is None:
            meta = getattr(err, "meta", None)
            status = getattr(meta, "status", None)
        if status is None:
            info = getattr(err, "info", None)
            if isinstance(info, dict):
                status = info.get("status")
        if status is None and getattr(err, "args", None):
            try:
                status = int(err.args[0])
            except (TypeError, ValueError):
                pass
        try:
            return int(status) if status is not None else None
        except (TypeError, ValueError):
            return None

    @classmethod
    def normalize_exception(cls, err: Exception) -> SearchBackendException:
        if isinstance(err, SearchBackendException):
            return err

        message = getattr(err, "message", None) or str(err)
        return SearchBackendException(message, status_code=cls.get_exception_status(err), original=err)

    @staticmethod
    def _opensearch_param_value(value):
        if isinstance(value, bool):
            return "true" if value else "false"
        return value

    @classmethod
    def _extract_opensearch_params(cls, kwargs: dict, supported_params: set[str]) -> dict:
        params = {}
        explicit_params = kwargs.pop("params", None)
        if explicit_params:
            params.update({
                key: cls._opensearch_param_value(value)
                for key, value in explicit_params.items()
                if value is not None
            })

        for key in list(kwargs.keys()):
            if key not in supported_params:
                continue
            value = kwargs.pop(key)
            if value is not None:
                params[key] = cls._opensearch_param_value(value)

        return params

    @staticmethod
    def _extract_body_value(kwargs: dict, body: dict, key: str):
        value = kwargs.pop(key, None)
        if value is None:
            return
        if key in body:
            raise SearchBackendCompatibilityError(f"{key} cannot be supplied both directly and in body")
        body[key] = value

    @staticmethod
    def _reject_unsupported_kwargs(operation: str, kwargs: dict, allowed: set[str]):
        unsupported = sorted(set(kwargs) - allowed)
        if unsupported:
            raise SearchBackendCompatibilityError(
                f"{operation} does not support argument(s): {', '.join(unsupported)}"
            )

    @staticmethod
    def opensearch_compatible_mappings(mappings: dict) -> dict:
        compatible_mappings = deepcopy(mappings)

        def replace_unsupported_types(value):
            if isinstance(value, dict):
                if value.get("type") == "wildcard":
                    # OpenSearch 2.x has wildcard queries, but not Elasticsearch's wildcard field mapper.
                    # Keyword preserves Assemblyline metadata's exact/wildcard/regexp query behavior for
                    # term-sized values; over-limit values reject instead of being silently ignored.
                    value["type"] = "keyword"
                for child in value.values():
                    replace_unsupported_types(child)
            elif isinstance(value, list):
                for child in value:
                    replace_unsupported_types(child)

        replace_unsupported_types(compatible_mappings)
        return compatible_mappings

    @staticmethod
    def opensearch_compatible_sort(sort):
        compatible_sort = deepcopy(sort)
        for item in compatible_sort or []:
            if isinstance(item, dict) and "_shard_doc" in item:
                item["_doc"] = item.pop("_shard_doc")
        return compatible_sort

    def info(self):
        return self._call(self.raw_client.info)

    def ping(self):
        return self._call(self.raw_client.ping)

    def close(self):
        return self.raw_client.close()

    def exists(self, **kwargs):
        return self._call(self.raw_client.exists, **kwargs)

    def get(self, **kwargs):
        return self._call(self.raw_client.get, **kwargs)

    def index(self, *, document=None, **kwargs):
        if self.backend == SearchBackend.OPENSEARCH:
            return self._call(self.raw_client.index, body=document, **kwargs)
        return self._call(self.raw_client.index, document=document, **kwargs)

    def delete(self, **kwargs):
        return self._call(self.raw_client.delete, **kwargs)

    def update(self, **kwargs):
        if self.backend == SearchBackend.OPENSEARCH:
            script = kwargs.pop("script", None)
            body = kwargs.pop("body", {})
            if script is not None:
                body = {**body, "script": script}
            return self._call(self.raw_client.update, body=body, **kwargs)
        return self._call(self.raw_client.update, **kwargs)

    def mget(self, *, ids=None, **kwargs):
        if self.backend == SearchBackend.OPENSEARCH:
            return self._call(self.raw_client.mget, body={"ids": ids}, **kwargs)
        return self._call(self.raw_client.mget, ids=ids, **kwargs)

    def bulk(self, *, operations=None, **kwargs):
        if self.backend == SearchBackend.OPENSEARCH:
            return self._call(self.raw_client.bulk, body=operations, **kwargs)
        return self._call(self.raw_client.bulk, operations=operations, **kwargs)

    def search(self, **kwargs):
        if self.backend == SearchBackend.OPENSEARCH:
            body_keys = {
                "aggregations",
                "collapse",
                "from_",
                "pit",
                "query",
                "script_fields",
                "search_after",
                "seq_no_primary_term",
                "size",
                "sort",
                "_source",
                "timeout",
            }
            body = {}
            for key in list(kwargs.keys()):
                if key not in body_keys:
                    continue
                value = kwargs.pop(key)
                if value is not None:
                    body[key] = value
            if "from_" in body:
                body["from"] = body.pop("from_")
            if "sort" in body:
                body["sort"] = self.opensearch_compatible_sort(body["sort"])
            return self._call(self.raw_client.search, body=body, **kwargs)
        return self._call(self.raw_client.search, **kwargs)

    def delete_by_query(self, **kwargs):
        if self.backend == SearchBackend.ELASTICSEARCH:
            return self._call(self.raw_client.delete_by_query, **kwargs)

        body = kwargs.pop("body", {}) or {}
        params = self._extract_opensearch_params(
            kwargs,
            {
                "allow_no_indices",
                "analyze_wildcard",
                "analyzer",
                "conflicts",
                "default_operator",
                "df",
                "expand_wildcards",
                "from_",
                "ignore_unavailable",
                "lenient",
                "preference",
                "q",
                "refresh",
                "request_cache",
                "requests_per_second",
                "routing",
                "scroll",
                "scroll_size",
                "search_timeout",
                "search_type",
                "size",
                "slices",
                "sort",
                "stats",
                "terminate_after",
                "timeout",
                "version",
                "wait_for_active_shards",
                "wait_for_completion",
            },
        )
        if "from_" in params:
            params["from"] = params.pop("from_")
        self._extract_body_value(kwargs, body, "query")
        self._extract_body_value(kwargs, body, "max_docs")
        self._extract_body_value(kwargs, body, "slice")
        self._reject_unsupported_kwargs("delete_by_query", kwargs, {"index", "headers"})
        return self._call(self.raw_client.delete_by_query, body=body, params=params or None, **kwargs)

    def update_by_query(self, **kwargs):
        if self.backend == SearchBackend.ELASTICSEARCH:
            return self._call(self.raw_client.update_by_query, **kwargs)

        body = kwargs.pop("body", {}) or {}
        params = self._extract_opensearch_params(
            kwargs,
            {
                "allow_no_indices",
                "analyze_wildcard",
                "analyzer",
                "conflicts",
                "default_operator",
                "df",
                "expand_wildcards",
                "from_",
                "ignore_unavailable",
                "lenient",
                "pipeline",
                "preference",
                "q",
                "refresh",
                "request_cache",
                "requests_per_second",
                "routing",
                "scroll",
                "scroll_size",
                "search_timeout",
                "search_type",
                "size",
                "slices",
                "sort",
                "stats",
                "terminate_after",
                "timeout",
                "version",
                "wait_for_active_shards",
                "wait_for_completion",
            },
        )
        if "from_" in params:
            params["from"] = params.pop("from_")
        self._extract_body_value(kwargs, body, "query")
        self._extract_body_value(kwargs, body, "script")
        self._extract_body_value(kwargs, body, "max_docs")
        self._extract_body_value(kwargs, body, "slice")
        self._reject_unsupported_kwargs("update_by_query", kwargs, {"index", "headers"})
        return self._call(self.raw_client.update_by_query, body=body, params=params or None, **kwargs)

    def open_point_in_time(self, **kwargs):
        if self.backend == SearchBackend.ELASTICSEARCH:
            return self._call(self.raw_client.open_point_in_time, **kwargs)

        create_pit = getattr(self.raw_client, "create_pit", None)
        if create_pit is None:
            raise SearchBackendCompatibilityError(
                "OpenSearch client does not expose create_pit; PIT requires opensearch-py with PIT API support"
            )

        params = {}
        for key in ("keep_alive", "allow_partial_pit_creation", "expand_wildcards", "preference", "routing"):
            if key in kwargs:
                params[key] = kwargs.pop(key)

        response = self._call(create_pit, params=params, **kwargs)
        if isinstance(response, dict) and "id" not in response and "pit_id" in response:
            return {"id": response["pit_id"]}
        return response

    def close_point_in_time(self, **kwargs):
        if self.backend == SearchBackend.ELASTICSEARCH:
            return self._call(self.raw_client.close_point_in_time, **kwargs)

        delete_pit = getattr(self.raw_client, "delete_pit", None)
        if delete_pit is None:
            raise SearchBackendCompatibilityError(
                "OpenSearch client does not expose delete_pit; PIT requires opensearch-py with PIT API support"
            )

        pit_id = kwargs.pop("id")
        return self._call(delete_pit, body={"pit_id": [pit_id]}, **kwargs)

    def __getattr__(self, name):
        if self.backend == SearchBackend.ELASTICSEARCH:
            return getattr(self.raw_client, name)
        raise UnsupportedSearchBackendOperation(f"{name} is not supported by this adapter slice")
