from __future__ import annotations

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
                body["mappings"] = mappings
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

    def __getattr__(self, name):
        if self._adapter.backend == SearchBackend.ELASTICSEARCH:
            return getattr(self._adapter.raw_client.indices, name)
        raise UnsupportedSearchBackendOperation(f"indices.{name} is not supported by this adapter slice")


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
            self.tasks = _UnsupportedNamespace("tasks")

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
        return int(status) if status is not None else None

    @classmethod
    def normalize_exception(cls, err: Exception) -> SearchBackendException:
        if isinstance(err, SearchBackendException):
            return err

        message = getattr(err, "message", None) or str(err)
        return SearchBackendException(message, status_code=cls.get_exception_status(err), original=err)

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
            if "pit" in kwargs or "search_after" in kwargs:
                raise UnsupportedSearchBackendOperation("OpenSearch PIT search is not supported by this adapter slice")
            body_keys = {
                "aggregations",
                "collapse",
                "from_",
                "query",
                "script_fields",
                "seq_no_primary_term",
                "size",
                "sort",
                "_source",
                "timeout",
            }
            body = {key: kwargs.pop(key) for key in list(kwargs.keys()) if key in body_keys}
            if "from_" in body:
                body["from"] = body.pop("from_")
            return self._call(self.raw_client.search, body=body, **kwargs)
        return self._call(self.raw_client.search, **kwargs)

    def __getattr__(self, name):
        if self.backend == SearchBackend.ELASTICSEARCH:
            return getattr(self.raw_client, name)
        raise UnsupportedSearchBackendOperation(f"{name} is not supported by this adapter slice")
