"""
VectorShare — Function Vector Embedding & Symbol Recovery
==========================================================

Ported from ``repos/stage5/working/vector_share/vector_share.py``.

Generates 128-dimensional mnemonic 3-gram feature-hash vectors per
function, stores/queries them through the storage backend, and
optionally invokes an Ollama LLM to recover symbol names for unknown
(``sub_*`` / ``FUN_*``) functions.

Consumes function data from upstream plugins (angr, triton,
blackfyre, binexport) via ``PluginContext.shared_data``.

Optional dependencies: ``numpy``, ``requests`` (for Ollama).
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from typing import Any, cast

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

_HAS_NUMPY = False
try:
    import numpy as np
    _HAS_NUMPY = True
except ImportError:
    pass

_HAS_REQUESTS = False
try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    pass


# ── Helpers ───────────────────────────────────────────────────────────────


VECTOR_SIZE = 128


def _is_generic_name(name: str) -> bool:
    if not name:
        return True
    return name.startswith(("sub_", "FUN_", "fcn.", "func_"))


def _generate_vector(mnemonics: list[str]) -> np.ndarray:
    """Feature-hashing (hashing trick) on mnemonic 3-grams → L2-normalised vector."""
    vec = np.zeros(VECTOR_SIZE, dtype=np.float32)
    if len(mnemonics) < 3:
        return vec
    for i in range(len(mnemonics) - 2):
        ngram = "".join(mnemonics[i : i + 3])
        h = int(hashlib.md5(ngram.encode(), usedforsecurity=False).hexdigest(), 16)
        idx = h % VECTOR_SIZE
        vec[idx] += 1.0
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec /= norm
    return vec


def _is_thunk(mnemonics: list[str], block_count: int) -> bool:
    """Return True for trivial thunk/trampoline functions."""
    if len(mnemonics) < 4:
        return True
    return bool(block_count == 1 and mnemonics and mnemonics[-1].startswith("jmp"))


# ── Ollama integration ────────────────────────────────────────────────────


def _query_ollama(
    assembly_text: str,
    ollama_url: str,
    model: str,
    extra_context: str = "",
) -> str | None:
    """Ask an Ollama LLM to name a function from its assembly."""
    system_prompt = (
        "You are a reverse engineering assistant. "
        "Analyze the provided assembly code to understand its purpose. "
        "Generate a concise, descriptive function name in snake_case "
        "(e.g., encrypt_aes, parse_header, socket_connect). "
        "Do not use generic names like sub_XXXX or func_XXXX. "
        "Output ONLY the function name. No markdown, no explanations."
    )
    prompt_text = f"{system_prompt}\n\n"
    if extra_context:
        prompt_text += f"Context Info: {extra_context}\n\n"
    prompt_text += f"Assembly:\n{assembly_text}"

    payload = {"model": model, "prompt": prompt_text, "stream": False}
    try:
        resp = requests.post(ollama_url, json=payload, timeout=30)
        resp.raise_for_status()
        name = resp.json().get("response", "").strip()
        if " " in name or "\n" in name:
            name = name.split("\n")[0].strip().replace(" ", "_").lower()
        return name if name else None
    except (ConnectionError, ValueError, TypeError, RuntimeError, OSError, TimeoutError) as exc:
        logger.warning("Ollama query failed: %s", exc)
        return None


# ── Plugin ────────────────────────────────────────────────────────────────


@register_plugin
class VectorSharePlugin(Plugin):
    """Function vector embedding, DB look-up, and AI symbol recovery."""

    name = "vector_share"
    stage = Stage.ENRICHMENT
    description = "Mnemonic 3-gram vector hashing, cosine look-up, Ollama symbol recovery"

    @classmethod
    def available(cls) -> bool:
        return _HAS_NUMPY

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()
        try:
            result = self._process(context)
            return self._make_result(
                success=True,
                data=result,
                duration=time.monotonic() - t0,
            )
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError, IndexError) as exc:
            logger.exception("VectorShare failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    # ------------------------------------------------------------------ #

    def _process(self, ctx: PluginContext) -> dict[str, Any]:
        enable_ai = ctx.config.get("vector_share.enable_ai", False)
        ollama_url = ctx.config.get(
            "ollama.url",
            os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate"),
        )
        ollama_model = ctx.config.get(
            "ollama.model",
            os.getenv("OLLAMA_MODEL", "deepseek-coder-v2:latest"),
        )
        min_complexity = int(ctx.config.get("vector_share.min_complexity", 10))

        # Collect functions from upstream plugins
        functions = self._gather_functions(ctx)

        stats = {
            "functions_processed": 0,
            "symbols_recovered_db": 0,
            "symbols_recovered_ai": 0,
            "indexed": 0,
        }

        for func in functions:
            name = func.get("name", "")
            mnemonics: Any = func.get("mnemonics", [])

            # Flatten Counter-style mnemonics dicts to lists
            if isinstance(mnemonics, dict):
                mnemonics = list(mnemonics.keys())

            block_count = func.get("block_count", 0)
            stats["functions_processed"] += 1

            if _is_thunk(mnemonics, block_count):
                continue

            vec = _generate_vector(mnemonics)

            # Index occurrence for similarity tracking
            vec_id = hashlib.md5(vec.tobytes(), usedforsecurity=False).hexdigest()
            if ctx.storage:
                ctx.storage.store(
                    "vectorshare_occurrences",
                    hashlib.md5(f"{ctx.sample_hash}{vec_id}".encode(), usedforsecurity=False).hexdigest(),
                    {"source_binary": ctx.sample_hash, "function_id": vec_id},
                )

            # If function has a real name, index it in the KB
            if not _is_generic_name(name):
                if ctx.storage:
                    ctx.storage.store(
                        "vectorshare_kb",
                        vec_id,
                        {"name": name, "vector": vec.tolist()},
                    )
                    stats["indexed"] += 1
                continue

            # --- Symbol recovery for generic names ---

            # 1. DB cosine look-up (via storage backend)
            recovered = self._recover_from_db(vec, ctx)
            if recovered:
                func["recovered_name"] = recovered
                stats["symbols_recovered_db"] += 1
                continue

            # 2. AI inference (Ollama)
            if enable_ai and _HAS_REQUESTS and block_count > min_complexity:
                assembly_text = " ".join(mnemonics[:100])
                ai_name = _query_ollama(assembly_text, ollama_url, ollama_model)
                if ai_name:
                    func["recovered_name"] = ai_name
                    stats["symbols_recovered_ai"] += 1
                    # Store recovered name in KB for future look-ups
                    if ctx.storage:
                        ctx.storage.store(
                            "vectorshare_kb",
                            vec_id,
                            {"name": ai_name, "vector": vec.tolist()},
                        )

        return {
            "stats": stats,
            "functions_processed": stats["functions_processed"],
            "symbols_recovered": stats["symbols_recovered_db"] + stats["symbols_recovered_ai"],
        }

    # ------------------------------------------------------------------ #

    def _gather_functions(self, ctx: PluginContext) -> list[dict[str, Any]]:
        """Collect function lists from all upstream plugins."""
        funcs: list[dict[str, Any]] = []
        for source in ("angr", "triton", "blackfyre", "binexport"):
            src_data = ctx.shared_data.get(source, {})
            if isinstance(src_data, dict):
                for f in src_data.get("functions", []):
                    entry = dict(f)
                    entry.setdefault("source", source)
                    funcs.append(entry)
        return funcs

    def _recover_from_db(self, vec: np.ndarray, ctx: PluginContext) -> str | None:
        """
        Cosine similarity look-up in the vectorshare_kb index.

        If the storage backend supports ``script_score_query`` (ES), use
        that.  Otherwise, do a brute-force scan over the in-memory/local
        backend.
        """
        if ctx.storage is None:
            return None

        # ES-native cosine query
        if hasattr(ctx.storage, "script_score_query"):
            hits = ctx.storage.script_score_query(
                "vectorshare_kb", vec.tolist(), field="vector", size=1
            )
            if hits and hits[0].get("_score", 0) > 0.95:
                return cast("str | None", hits[0].get("name"))
            return None

        # Brute-force fallback for memory / local backends
        all_entries = ctx.storage.query("vectorshare_kb", {"match": {}}, size=500)
        best_score = 0.0
        best_name: str | None = None

        for entry in all_entries:
            stored_vec_list = entry.get("vector")
            if not stored_vec_list:
                continue
            stored_vec = np.array(stored_vec_list, dtype=np.float32)
            # Cosine similarity
            dot = float(np.dot(vec, stored_vec))
            norm_a = float(np.linalg.norm(vec))
            norm_b = float(np.linalg.norm(stored_vec))
            if norm_a > 0 and norm_b > 0:
                score = dot / (norm_a * norm_b)
                if score > 0.95 and score > best_score:
                    best_score = score
                    best_name = entry.get("name")

        return best_name
