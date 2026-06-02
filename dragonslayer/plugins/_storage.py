"""
Storage Abstraction
===================

Replaces the hard-coded Elasticsearch dependency that every Metroplex
plugin used for cross-plugin data sharing.  Three backends are provided:

* **ElasticsearchBackend** — wraps the ``elasticsearch`` client
* **LocalFileBackend**     — JSON files on disk (standalone / CI)
* **MemoryBackend**        — dict-based, useful for unit tests

Usage::

    from dragonslayer.plugins._storage import create_storage

    backend = create_storage("memory")         # or "local", "elasticsearch"
    backend.store("malware_functions", doc_id, {"name": "sub_401000", ...})
    hit = backend.query("malware_functions", {"match": {"name": "sub_401000"}})
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------


class StorageBackend(ABC):
    """Minimal key-value + search interface used by all plugins."""

    @abstractmethod
    def store(self, index: str, doc_id: str, document: dict[str, Any]) -> bool:
        """Persist *document* under *index*/*doc_id*.  Return success flag."""
        ...

    @abstractmethod
    def get(self, index: str, doc_id: str) -> dict[str, Any] | None:
        """Retrieve a single document, or ``None`` if not found."""
        ...

    @abstractmethod
    def query(self, index: str, query: dict[str, Any], size: int = 10) -> list[dict[str, Any]]:
        """
        Execute a search-like query and return up to *size* hits.

        The exact query DSL depends on the backend; callers should use
        simple ``{"match": {"field": "value"}}`` dicts that all backends
        can translate.
        """
        ...

    @abstractmethod
    def delete(self, index: str, doc_id: str) -> bool:
        """Delete a document.  Return ``True`` if it existed."""
        ...

    @abstractmethod
    def ensure_index(self, index: str, mapping: dict[str, Any] | None = None) -> None:
        """Create the index/collection if it doesn't exist."""
        ...

    # Convenience -----------------------------------------------------------

    def store_bulk(self, index: str, documents: list[dict[str, Any]], id_field: str = "id") -> int:
        """Store multiple docs.  Return count of successes."""
        ok = 0
        for doc in documents:
            doc_id = doc.get(id_field, hashlib.md5(json.dumps(doc, sort_keys=True).encode(), usedforsecurity=False).hexdigest())
            if self.store(index, str(doc_id), doc):
                ok += 1
        return ok


# ---------------------------------------------------------------------------
# In-memory backend (default / test)
# ---------------------------------------------------------------------------


class MemoryBackend(StorageBackend):
    """Thread-safe in-memory storage for tests and lightweight use."""

    def __init__(self) -> None:
        self._data: dict[str, dict[str, dict[str, Any]]] = {}  # index -> doc_id -> doc
        self._lock = threading.Lock()

    def store(self, index: str, doc_id: str, document: dict[str, Any]) -> bool:
        with self._lock:
            self._data.setdefault(index, {})[doc_id] = document
        return True

    def get(self, index: str, doc_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._data.get(index, {}).get(doc_id)

    def delete(self, index: str, doc_id: str) -> bool:
        with self._lock:
            bucket = self._data.get(index, {})
            if doc_id in bucket:
                del bucket[doc_id]
                return True
            return False

    def query(self, index: str, query: dict[str, Any], size: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            bucket = self._data.get(index, {})
            # Simple match filter
            match = query.get("match", {})
            hits: list[dict[str, Any]] = []
            for doc in bucket.values():
                ok = True
                for k, v in match.items():
                    if str(doc.get(k, "")) != str(v):
                        ok = False
                        break
                if ok:
                    hits.append(doc)
                    if len(hits) >= size:
                        break
            return hits

    def ensure_index(self, index: str, mapping: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._data.setdefault(index, {})

    def count(self, index: str) -> int:
        with self._lock:
            return len(self._data.get(index, {}))


# ---------------------------------------------------------------------------
# Local-file backend
# ---------------------------------------------------------------------------


class LocalFileBackend(StorageBackend):
    """
    JSON-file-per-index backend stored under *base_dir*.

    Layout::

        base_dir/
          malware_functions.json    ← {"doc_id": {doc}, ...}
          vectorshare_kb.json
    """

    def __init__(self, base_dir: str | Path = ".vmds_storage") -> None:
        self._base = Path(base_dir)
        self._base.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, dict[str, dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def _index_path(self, index: str) -> Path:
        safe_name = index.replace("/", "_").replace("\\", "_")
        return self._base / f"{safe_name}.json"

    def _load(self, index: str) -> dict[str, dict[str, Any]]:
        if index in self._cache:
            return self._cache[index]
        p = self._index_path(index)
        if p.exists():
            try:
                self._cache[index] = json.loads(p.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._cache[index] = {}
        else:
            self._cache[index] = {}
        return self._cache[index]

    def _flush(self, index: str) -> None:
        p = self._index_path(index)
        p.write_text(json.dumps(self._cache.get(index, {}), indent=2), encoding="utf-8")

    def store(self, index: str, doc_id: str, document: dict[str, Any]) -> bool:
        with self._lock:
            bucket = self._load(index)
            bucket[doc_id] = document
            self._flush(index)
        return True

    def store_bulk(self, index: str, documents: list[dict[str, Any]], id_field: str = "id") -> int:
        """Override to batch-flush: write the file only once after all inserts."""
        with self._lock:
            bucket = self._load(index)
            ok = 0
            for doc in documents:
                doc_id = doc.get(id_field, hashlib.md5(json.dumps(doc, sort_keys=True).encode(), usedforsecurity=False).hexdigest())
                bucket[str(doc_id)] = doc
                ok += 1
            self._flush(index)
        return ok

    def get(self, index: str, doc_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._load(index).get(doc_id)

    def delete(self, index: str, doc_id: str) -> bool:
        with self._lock:
            bucket = self._load(index)
            if doc_id in bucket:
                del bucket[doc_id]
                self._flush(index)
                return True
        return False

    def query(self, index: str, query: dict[str, Any], size: int = 10) -> list[dict[str, Any]]:
        with self._lock:
            bucket = self._load(index)
            match = query.get("match", {})
            hits: list[dict[str, Any]] = []
            for doc in bucket.values():
                ok = True
                for k, v in match.items():
                    if str(doc.get(k, "")) != str(v):
                        ok = False
                        break
                if ok:
                    hits.append(doc)
                    if len(hits) >= size:
                        break
        return hits

    def ensure_index(self, index: str, mapping: dict[str, Any] | None = None) -> None:
        with self._lock:
            self._load(index)  # creates file if needed


# ---------------------------------------------------------------------------
# Elasticsearch backend
# ---------------------------------------------------------------------------


class ElasticsearchBackend(StorageBackend):
    """Thin wrapper around ``elasticsearch.Elasticsearch``."""

    def __init__(self, hosts: str | list[str] = "http://localhost:9200") -> None:
        try:
            from elasticsearch import Elasticsearch
            self._es = Elasticsearch(hosts if isinstance(hosts, list) else [hosts])
        except ImportError:
            raise ImportError(
                "Install 'elasticsearch' to use ElasticsearchBackend: "
                "pip install elasticsearch"
            ) from None

    def store(self, index: str, doc_id: str, document: dict[str, Any]) -> bool:
        try:
            self._es.index(index=index, id=doc_id, body=document)
            return True
        except (ConnectionError, ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
            logger.warning("ES store failed: %s", exc)
            return False

    def get(self, index: str, doc_id: str) -> dict[str, Any] | None:
        try:
            res = self._es.get(index=index, id=doc_id)
            return res["_source"]
        except (ConnectionError, ValueError, TypeError, KeyError, RuntimeError, OSError):
            return None

    def delete(self, index: str, doc_id: str) -> bool:
        try:
            self._es.delete(index=index, id=doc_id)
            return True
        except (ConnectionError, ValueError, TypeError, KeyError, RuntimeError, OSError):
            return False

    def query(self, index: str, query: dict[str, Any], size: int = 10) -> list[dict[str, Any]]:
        try:
            body = {"size": size, "query": query}
            res = self._es.search(index=index, body=body)
            return [hit["_source"] for hit in res["hits"]["hits"]]
        except (ConnectionError, ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
            logger.warning("ES query failed: %s", exc)
            return []

    def ensure_index(self, index: str, mapping: dict[str, Any] | None = None) -> None:
        try:
            if not self._es.indices.exists(index=index):
                body = {"mappings": mapping} if mapping else {}
                self._es.indices.create(index=index, body=body)
        except (ConnectionError, ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
            logger.warning("ES ensure_index failed: %s", exc)

    def script_score_query(
        self,
        index: str,
        vector: list[float],
        field: str = "vector",
        size: int = 1,
    ) -> list[dict[str, Any]]:
        """Run a cosine-similarity script_score query (used by vector_share)."""
        body = {
            "size": size,
            "query": {
                "script_score": {
                    "query": {"match_all": {}},
                    "script": {
                        "source": f"cosineSimilarity(params.query_vector, '{field}') + 1.0",
                        "params": {"query_vector": vector},
                    },
                },
            },
        }
        try:
            res = self._es.search(index=index, body=body)
            return [
                {"_score": hit["_score"] - 1.0, **hit["_source"]}
                for hit in res["hits"]["hits"]
            ]
        except (ConnectionError, ValueError, TypeError, KeyError, RuntimeError, OSError) as exc:
            logger.warning("ES script_score query failed: %s", exc)
            return []


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_storage(backend: str = "memory", **kwargs: Any) -> StorageBackend:
    """
    Create a storage backend by name.

    Parameters
    ----------
    backend : str
        One of ``"memory"``, ``"local"``, ``"elasticsearch"``.
    **kwargs
        Forwarded to the backend constructor (e.g. ``base_dir``,
        ``hosts``).
    """
    backend = backend.lower()
    if backend == "memory":
        return MemoryBackend()
    if backend in ("local", "file", "localfile"):
        return LocalFileBackend(**kwargs)
    if backend in ("elasticsearch", "es"):
        hosts = kwargs.get("hosts", os.getenv("ES_HOST", "http://localhost:9200"))
        return ElasticsearchBackend(hosts=hosts)
    raise ValueError(f"Unknown storage backend: {backend!r}")
