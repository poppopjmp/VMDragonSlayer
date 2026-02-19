"""
Function-Level Similarity
==========================

Ported from ``repos/stage5/working/similarity/function_similarity.py``.

Compares functions across binaries using mnemonic-based feature
hashing, looking up known function names from the storage backend
(populated by blackfyre, angr, triton, vector_share plugins).

No heavy dependencies beyond the storage backend.
"""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any, Dict, List, Optional

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)


def _is_generic_name(name: str) -> bool:
    """Return ``True`` for auto-generated / stub names."""
    if not name:
        return True
    return name.startswith(("sub_", "FUN_", "fcn.", "func_"))


@register_plugin
class FunctionSimilarityPlugin(Plugin):
    """Cross-binary function matching via mnemonic hashing + storage look-up."""

    name = "function_similarity"
    stage = Stage.ENRICHMENT
    description = "Function-level cross-binary similarity matching"

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        try:
            result = self._analyze(context)
            return self._make_result(
                success=True,
                data=result,
                duration=time.monotonic() - t0,
            )
        except Exception as exc:
            logger.exception("Function similarity failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _analyze(self, ctx: PluginContext) -> Dict[str, Any]:
        """
        Look at functions collected by upstream plugins (angr, triton,
        blackfyre) in ``shared_data`` and search the storage for matching
        function hashes.
        """
        # Gather functions from shared_data
        all_functions: List[Dict[str, Any]] = []
        for source in ("angr", "triton", "blackfyre"):
            src_data = ctx.shared_data.get(source, {})
            if isinstance(src_data, dict):
                for func in src_data.get("functions", []):
                    func_copy = dict(func)
                    func_copy["source"] = source
                    all_functions.append(func_copy)

        if not all_functions:
            return {
                "matches": [],
                "functions_checked": 0,
                "summary": "No function data available from upstream plugins",
            }

        matches: List[Dict[str, Any]] = []
        functions_checked = 0
        symbols_recovered = 0

        for func in all_functions:
            func_hash = func.get("hash", "")
            func_name = func.get("name", "")
            func_addr = func.get("address", 0)
            source = func.get("source", "")

            if not func_hash:
                continue
            functions_checked += 1

            # Look up in storage
            if ctx.storage:
                stored = ctx.storage.get("blackfyre_functions", func_hash)
                if stored and stored.get("name") and not _is_generic_name(stored["name"]):
                    # Found a named function match
                    if _is_generic_name(func_name):
                        symbols_recovered += 1
                    matches.append({
                        "address": func_addr,
                        "original_name": func_name,
                        "matched_name": stored["name"],
                        "source_plugin": source,
                        "matched_sample": stored.get("sample", ""),
                        "hash": func_hash,
                    })

        return {
            "functions_checked": functions_checked,
            "matches_found": len(matches),
            "symbols_recovered": symbols_recovered,
            "matches": matches[:100],  # limit output size
        }
