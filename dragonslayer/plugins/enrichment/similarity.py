"""
Binary Similarity Analyser
============================

Ported from ``repos/stage5/working/similarity/similarity.py``.

Cross-format (PE / ELF / Mach-O) binary similarity scoring.
Computes weighted feature similarity (imports, sections, exports,
resources) plus ssdeep fuzzy hashing and optional Ollama-AI
summarisation.

Optional heavy dependencies: ``pefile``, ``pyelftools``, ``macholib``,
``ssdeep``, ``requests`` (for Ollama API).
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

# Optional imports ---------------------------------------------------------
_HAS_PEFILE = False
try:
    import pefile  # type: ignore[import-untyped]
    _HAS_PEFILE = True
except ImportError:
    pass

_HAS_ELFTOOLS = False
try:
    from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
    from elftools.elf.sections import SymbolTableSection  # type: ignore[import-untyped]
    _HAS_ELFTOOLS = True
except ImportError:
    pass

_HAS_MACHOLIB = False
try:
    from macholib.MachO import MachO  # type: ignore[import-untyped]
    _HAS_MACHOLIB = True
except ImportError:
    pass

_HAS_SSDEEP = False
try:
    import ssdeep  # type: ignore[import-untyped]
    _HAS_SSDEEP = True
except ImportError:
    pass


# ── Feature extraction ────────────────────────────────────────────────────


def _detect_format(data: bytes) -> str:
    if data[:2] == b"MZ":
        return "PE"
    if data[:4] == b"\x7fELF":
        return "ELF"
    import struct
    magic = struct.unpack(">I", data[:4])[0] if len(data) >= 4 else 0
    macho_magics = {0xFEEDFACE, 0xCEFAEDFE, 0xFEEDFACF, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA}
    if magic in macho_magics:
        return "MACHO"
    return "UNKNOWN"


def _extract_pe_features(file_path: str) -> Dict[str, Any]:
    """Extract PE features for similarity comparison."""
    features: Dict[str, Any] = {}
    pe: Optional[Any] = None
    try:
        pe = pefile.PE(file_path)
        # Imports
        imports: List[str] = []
        import_freq: Counter[str] = Counter()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace").lower()
                for imp in entry.imports:
                    name = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                    imports.append(f"{dll}:{name}")
                    import_freq[dll] += 1
        features["imports"] = sorted(set(imports))
        features["import_frequency"] = dict(import_freq)

        # Sections
        features["sections"] = sorted(
            sec.Name.decode("utf-8", errors="replace").rstrip("\x00")
            for sec in pe.sections
        )

        # Exports
        exports: List[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode("utf-8", errors="replace") if exp.name else f"ord_{exp.ordinal}"
                exports.append(name)
        features["exports"] = sorted(exports)

        # Resources (type strings)
        resources: List[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                resources.append(str(res_type.id))
        features["resources"] = resources

        # Imphash
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            features["imphash"] = pe.get_imphash()
    except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError) as exc:
        logger.warning("PE feature extraction failed: %s", exc)
    finally:
        if pe is not None:
            pe.close()
    return features


def _extract_elf_features(file_path: str) -> Dict[str, Any]:
    features: Dict[str, Any] = {}
    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)
            imports: List[str] = []
            exports: List[str] = []
            for sec in elf.iter_sections():
                if isinstance(sec, SymbolTableSection):
                    for sym in sec.iter_symbols():
                        if not sym.name:
                            continue
                        if sym["st_shndx"] == "SHN_UNDEF" and sym["st_value"] == 0:
                            imports.append(sym.name)
                        elif sym["st_info"]["bind"] == "STB_GLOBAL" and sym["st_shndx"] != "SHN_UNDEF":
                            exports.append(sym.name)
            features["imports"] = sorted(set(imports))
            features["exports"] = sorted(set(exports))
            features["import_frequency"] = {}  # ELF doesn't have DLL grouping
            features["sections"] = sorted(sec.name for sec in elf.iter_sections() if sec.name)
            features["resources"] = []
    except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError) as exc:
        logger.warning("ELF feature extraction failed: %s", exc)
    return features


def _extract_macho_features(file_path: str) -> Dict[str, Any]:
    features: Dict[str, Any] = {"imports": [], "exports": [], "sections": [], "resources": [], "import_frequency": {}}
    try:
        from macholib.mach_o import LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_SEGMENT, LC_SEGMENT_64
        macho = MachO(file_path)
        libraries: List[str] = []
        segments: List[str] = []
        for header in macho.headers:
            for cmd in header.commands:
                if cmd[0].cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
                    try:
                        libraries.append(cmd[2].decode("utf-8").rstrip("\x00"))
                    except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
                        pass
                elif cmd[0].cmd in (LC_SEGMENT, LC_SEGMENT_64):
                    try:
                        segments.append(cmd[1].segname.decode("utf-8").rstrip("\x00"))
                    except (ValueError, TypeError, UnicodeDecodeError, AttributeError):
                        pass
        features["imports"] = sorted(set(libraries))
        features["sections"] = sorted(set(segments))
    except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError) as exc:
        logger.warning("Mach-O feature extraction failed: %s", exc)
    return features


# ── Similarity math ───────────────────────────────────────────────────────


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


def _cosine(a: Counter, b: Counter) -> float:
    keys = set(a) | set(b)
    if not keys:
        return 1.0
    dot = sum(a.get(k, 0) * b.get(k, 0) for k in keys)
    mag_a = math.sqrt(sum(v * v for v in a.values()))
    mag_b = math.sqrt(sum(v * v for v in b.values()))
    if mag_a == 0 or mag_b == 0:
        return 0.0
    return dot / (mag_a * mag_b)


# Feature weights (matching the original plugin)
WEIGHTS = {
    "imports": 0.35,
    "import_frequency": 0.20,
    "sections": 0.15,
    "exports": 0.10,
    "resources": 0.10,
    "ssdeep": 0.10,
}


def compute_similarity(feat_a: Dict[str, Any], feat_b: Dict[str, Any], data_a: bytes = b"", data_b: bytes = b"",
                       ssdeep_a: str = "", ssdeep_b: str = "") -> Dict[str, Any]:
    """Compute weighted similarity between two feature dicts.

    *ssdeep_a* / *ssdeep_b* allow passing pre-computed hashes so that
    the raw bytes are not required for stored-sample comparisons.
    """
    scores: Dict[str, float] = {}
    scores["imports"] = _jaccard(set(feat_a.get("imports", [])), set(feat_b.get("imports", [])))
    scores["import_frequency"] = _cosine(
        Counter(feat_a.get("import_frequency", {})),
        Counter(feat_b.get("import_frequency", {})),
    )
    scores["sections"] = _jaccard(set(feat_a.get("sections", [])), set(feat_b.get("sections", [])))
    scores["exports"] = _jaccard(set(feat_a.get("exports", [])), set(feat_b.get("exports", [])))
    scores["resources"] = _jaccard(set(feat_a.get("resources", [])), set(feat_b.get("resources", [])))

    # ssdeep — prefer pre-computed hashes, fall back to raw bytes
    if _HAS_SSDEEP:
        try:
            h_a = ssdeep_a or (ssdeep.hash(data_a) if data_a else "")
            h_b = ssdeep_b or (ssdeep.hash(data_b) if data_b else "")
            if h_a and h_b:
                scores["ssdeep"] = ssdeep.compare(h_a, h_b) / 100.0
            else:
                scores["ssdeep"] = 0.0
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError):
            scores["ssdeep"] = 0.0
    else:
        scores["ssdeep"] = 0.0

    weighted = sum(scores[k] * WEIGHTS[k] for k in WEIGHTS)
    return {"scores": scores, "weighted_similarity": round(weighted, 6)}


# ── Plugin ────────────────────────────────────────────────────────────────


@register_plugin
class SimilarityPlugin(Plugin):
    """Cross-format binary similarity scoring."""

    name = "similarity"
    stage = Stage.ENRICHMENT
    description = "Weighted feature similarity (PE/ELF/Mach-O) with ssdeep"

    @classmethod
    def available(cls) -> bool:
        return _HAS_PEFILE or _HAS_ELFTOOLS or _HAS_MACHOLIB

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        try:
            features = self._extract(file_path, file_data)
            if not features:
                return self._make_result(
                    success=False,
                    error="Unsupported binary format or no features extracted",
                    duration=time.monotonic() - t0,
                )

            # Compute ssdeep hash
            ssdeep_hash = ""
            if _HAS_SSDEEP:
                try:
                    ssdeep_hash = ssdeep.hash(file_data)
                except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError):
                    pass

            result: Dict[str, Any] = {
                "format": _detect_format(file_data),
                "features": features,
                "ssdeep": ssdeep_hash,
                "imphash": features.get("imphash", ""),
            }

            # Compare against known samples in storage
            if context.storage:
                comparisons = self._compare_against_db(
                    features, file_data, context
                )
                result["comparisons"] = comparisons
                result["similar_count"] = len([c for c in comparisons if c["weighted_similarity"] > 0.5])

            # Store our features for future comparisons
            if context.storage and context.sample_hash:
                context.storage.store(
                    "similarity_features",
                    context.sample_hash,
                    {
                        "hash": context.sample_hash,
                        "features": features,
                        "ssdeep": ssdeep_hash,
                    },
                )

            return self._make_result(
                success=True,
                data=result,
                duration=time.monotonic() - t0,
            )
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError, IndexError) as exc:
            logger.exception("Similarity analysis failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _extract(self, file_path: str, file_data: bytes) -> Dict[str, Any]:
        fmt = _detect_format(file_data)
        if fmt == "PE" and _HAS_PEFILE:
            return _extract_pe_features(file_path)
        if fmt == "ELF" and _HAS_ELFTOOLS:
            return _extract_elf_features(file_path)
        if fmt == "MACHO" and _HAS_MACHOLIB:
            return _extract_macho_features(file_path)
        return {}

    def _compare_against_db(
        self,
        features: Dict[str, Any],
        file_data: bytes,
        ctx: PluginContext,
    ) -> List[Dict[str, Any]]:
        """Compare current sample against stored feature sets."""
        assert ctx.storage is not None
        hits = ctx.storage.query("similarity_features", {"match": {}}, size=50)

        # Pre-compute our ssdeep hash once
        our_ssdeep = ""
        if _HAS_SSDEEP and file_data:
            try:
                our_ssdeep = ssdeep.hash(file_data)
            except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError):
                pass

        comparisons = []
        for stored in hits:
            stored_hash = stored.get("hash", "")
            if stored_hash == ctx.sample_hash:
                continue  # skip self
            stored_feats = stored.get("features", {})
            stored_ssdeep = stored.get("ssdeep", "")
            sim = compute_similarity(
                features, stored_feats,
                ssdeep_a=our_ssdeep, ssdeep_b=stored_ssdeep,
            )
            sim["sample_hash"] = stored_hash
            comparisons.append(sim)
        # Sort by descending similarity
        comparisons.sort(key=lambda x: x["weighted_similarity"], reverse=True)
        return comparisons[:20]
