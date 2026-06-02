"""
VMProtect Version Fingerprinting
==================================

Classifies the VMProtect protector version (2.x, 3.0-3.4, 3.5+, 3.8+)
from observable dispatcher characteristics, pattern metadata, and
structural heuristics.

Version-discriminating signals
------------------------------

+-----------------------+----------+----------+-----------+----------+
| Signal                | vmp 2.x  | vmp 3.0  | vmp 3.5+  | vmp 3.8+ |
+=======================+==========+==========+===========+==========+
| dispatch_style        | jmp      | jmp      | push_ret  | push_ret |
+-----------------------+----------+----------+-----------+----------+
| decode_transforms     | ≤1       | 1–2      | 2–4       | 3–5      |
+-----------------------+----------+----------+-----------+----------+
| vip_delta sign        | +1       | +1       | −1        | −1       |
+-----------------------+----------+----------+-----------+----------+
| fetch_width           | 1        | 1        | 1         | 2 (word) |
+-----------------------+----------+----------+-----------+----------+
| entry stub pattern    | pushad   | push seq | ctx_save  | ctx_save |
+-----------------------+----------+----------+-----------+----------+
| rolling-key ops       | xor only | xor      | xor+rol   | xor+not+ |
|                       |          |          |           | rol+bswap|
+-----------------------+----------+----------+-----------+----------+

Usage::

    from dragonslayer.analysis.pattern_analysis.version_fingerprint import (
        VMProtectVersionFingerprinter,
        VersionFingerprint,
    )
    fp = VMProtectVersionFingerprinter()
    result = fp.fingerprint(dispatcher_match=match, matched_patterns=patterns)
    print(result.version, result.confidence)
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Version enum
# ---------------------------------------------------------------------------


class VMProtectVersion(str, Enum):
    """Known VMProtect major version families."""

    V2 = "2.x"
    V3_EARLY = "3.0-3.4"
    V3_MID = "3.5-3.7"
    V3_LATE = "3.8+"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class VersionFingerprint:
    """Result of VMProtect version fingerprinting.

    Attributes
    ----------
    version : VMProtectVersion
        Best-guess version family.
    version_string : str
        Human-readable version description.
    confidence : float
        Overall confidence (0.0-1.0).
    evidence : dict
        Per-signal evidence that contributed to the classification.
    alternative : VMProtectVersion | None
        Second-best version if scores are close.
    """

    version: VMProtectVersion = VMProtectVersion.UNKNOWN
    version_string: str = "unknown"
    confidence: float = 0.0
    evidence: dict[str, Any] = field(default_factory=dict)
    alternative: VMProtectVersion | None = None


# ---------------------------------------------------------------------------
# Version-discriminating rule sets
# ---------------------------------------------------------------------------

# Each rule is a (signal_name, test_function, version_scores) triple.
# version_scores maps version → weight delta when the test passes.

_DISPATCH_STYLE_SCORES = {
    "jmp": {VMProtectVersion.V2: 0.15, VMProtectVersion.V3_EARLY: 0.10},
    "push_ret": {VMProtectVersion.V3_MID: 0.15, VMProtectVersion.V3_LATE: 0.15},
    "computed_goto": {VMProtectVersion.V3_LATE: 0.20},
    "call": {VMProtectVersion.V3_MID: 0.05},
}

# Decode-transform chain length → version scores
_TRANSFORM_LENGTH_SCORES = [
    # (min_len, max_len, scores)
    (0, 0, {VMProtectVersion.V2: 0.15}),
    (1, 1, {VMProtectVersion.V2: 0.05, VMProtectVersion.V3_EARLY: 0.15}),
    (2, 2, {VMProtectVersion.V3_EARLY: 0.10, VMProtectVersion.V3_MID: 0.10}),
    (3, 4, {VMProtectVersion.V3_MID: 0.15, VMProtectVersion.V3_LATE: 0.10}),
    (5, 99, {VMProtectVersion.V3_LATE: 0.20}),
]

# Specific transform ops that indicate version
_TRANSFORM_OP_INDICATORS = {
    "bswap": {VMProtectVersion.V3_LATE: 0.15},
    "mul": {VMProtectVersion.V3_LATE: 0.10},
    "not": {VMProtectVersion.V3_MID: 0.08, VMProtectVersion.V3_LATE: 0.08},
    "rol": {VMProtectVersion.V3_MID: 0.10, VMProtectVersion.V3_LATE: 0.05},
    "ror": {VMProtectVersion.V3_MID: 0.10, VMProtectVersion.V3_LATE: 0.05},
}


# ---------------------------------------------------------------------------
# Fingerprinter class
# ---------------------------------------------------------------------------


class VMProtectVersionFingerprinter:
    """Determine the VMProtect version from dispatcher and pattern evidence."""

    def fingerprint(
        self,
        dispatcher_match: Any = None,
        matched_patterns: Sequence[Any] | None = None,
        binary_sections: Sequence[str] | None = None,
    ) -> VersionFingerprint:
        """Classify the VMProtect version.

        Parameters
        ----------
        dispatcher_match
            ``VMProtectDispatcherMatch`` or dict with dispatcher fields.
        matched_patterns
            Sequence of ``Pattern`` or ``Match`` objects from the recogniser.
            Used as additional evidence via ``metadata["vmprotect_version"]``.
        binary_sections
            Section names from the PE/ELF binary (e.g. ``[".vmp0", ".text"]``).

        Returns
        -------
        VersionFingerprint
        """
        scores: dict[VMProtectVersion, float] = dict.fromkeys(VMProtectVersion, 0.0)
        evidence: dict[str, Any] = {}

        # --- Signal 1: dispatch_style --------------------------------
        if dispatcher_match is not None:
            style = _g(dispatcher_match, "dispatch_style", "")
            if style and style in _DISPATCH_STYLE_SCORES:
                for ver, delta in _DISPATCH_STYLE_SCORES[style].items():
                    scores[ver] += delta
                evidence["dispatch_style"] = style

        # --- Signal 2: decode_transforms length ----------------------
        if dispatcher_match is not None:
            transforms = _g(dispatcher_match, "decode_transforms", [])
            n = len(transforms) if transforms else 0
            for lo, hi, s in _TRANSFORM_LENGTH_SCORES:
                if lo <= n <= hi:
                    for ver, delta in s.items():
                        scores[ver] += delta
                    break
            evidence["decode_transform_count"] = n

            # --- Signal 2b: specific transform ops -------------------
            ops_found: list[str] = []
            for t_str in (transforms or []):
                op = _extract_op(str(t_str))
                if op and op in _TRANSFORM_OP_INDICATORS:
                    for ver, delta in _TRANSFORM_OP_INDICATORS[op].items():
                        scores[ver] += delta
                    ops_found.append(op)
            if ops_found:
                evidence["transform_ops"] = ops_found

        # --- Signal 3: vip_delta sign --------------------------------
        if dispatcher_match is not None:
            delta = _g(dispatcher_match, "vip_delta", 0)
            if isinstance(delta, (int, float)):
                if delta < 0:
                    scores[VMProtectVersion.V3_MID] += 0.15
                    scores[VMProtectVersion.V3_LATE] += 0.15
                    evidence["vip_delta"] = delta
                elif delta > 0:
                    scores[VMProtectVersion.V2] += 0.10
                    scores[VMProtectVersion.V3_EARLY] += 0.10
                    evidence["vip_delta"] = delta

        # --- Signal 4: fetch_width -----------------------------------
        if dispatcher_match is not None:
            fw = _g(dispatcher_match, "fetch_width", 0)
            if fw == 2:
                scores[VMProtectVersion.V3_LATE] += 0.15
                evidence["fetch_width"] = 2
            elif fw == 1:
                scores[VMProtectVersion.V2] += 0.05
                scores[VMProtectVersion.V3_EARLY] += 0.05
                evidence["fetch_width"] = 1

        # --- Signal 5: pattern metadata votes ------------------------
        if matched_patterns:
            version_votes: dict[str, int] = {}
            for pat in matched_patterns:
                meta = _g(pat, "metadata", {})
                if not isinstance(meta, dict):
                    meta = {}
                # If metadata has no version, try nested .pattern.metadata
                if not meta.get("vmprotect_version"):
                    inner = _g(pat, "pattern", None)
                    if inner is not None:
                        inner_meta = _g(inner, "metadata", {})
                        if isinstance(inner_meta, dict) and inner_meta.get("vmprotect_version"):
                            meta = inner_meta
                vver = meta.get("vmprotect_version", "")
                if vver:
                    version_votes[vver] = version_votes.get(vver, 0) + 1

            for vstr, count in version_votes.items():
                mapped = _map_version_string(vstr)
                if mapped != VMProtectVersion.UNKNOWN:
                    scores[mapped] += min(count * 0.03, 0.15)
            if version_votes:
                evidence["pattern_version_votes"] = version_votes

        # --- Signal 6: section names --------------------------------
        if binary_sections:
            for sec in binary_sections:
                sec_lower = sec.lower()
                if sec_lower in (".vmp0", ".vmp1", ".vmp2", ".vmp3"):
                    # Generic VMProtect section — slight v3 lean
                    scores[VMProtectVersion.V3_EARLY] += 0.05
                    scores[VMProtectVersion.V3_MID] += 0.05
                    evidence["vmp_section"] = sec

        # --- Remove UNKNOWN from candidates --------------------------
        del scores[VMProtectVersion.UNKNOWN]

        # --- Pick winner --------------------------------------------
        if not scores or max(scores.values()) == 0:
            return VersionFingerprint()

        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        best_ver, best_score = ranked[0]
        alt_ver = ranked[1][0] if len(ranked) > 1 else None

        # Normalise confidence: best_score / theoretical_max (~1.0)
        # Theoretical max is ~0.8 for a clear v3.8+ with all signals
        confidence = min(best_score / 0.8, 1.0)

        return VersionFingerprint(
            version=best_ver,
            version_string=best_ver.value,
            confidence=round(confidence, 3),
            evidence=evidence,
            alternative=alt_ver if alt_ver and ranked[1][1] > 0 else None,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _g(obj: Any, attr: str, default: Any = None) -> Any:
    """Get attribute or dict key."""
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)


_OP_RE = re.compile(r"(xor|add|sub|not|neg|rol|ror|bswap|mul|inc|dec)", re.I)


def _extract_op(transform_str: str) -> str:
    m = _OP_RE.search(transform_str)
    return m.group(1).lower() if m else ""


def _map_version_string(s: str) -> VMProtectVersion:
    """Map a metadata version string to enum."""
    s = s.lower().strip()
    if "3.8" in s or "3.9" in s or "4." in s:
        return VMProtectVersion.V3_LATE
    if "3.5" in s or "3.6" in s or "3.7" in s:
        return VMProtectVersion.V3_MID
    if "3.0" in s or "3.1" in s or "3.2" in s or "3.3" in s or "3.4" in s:
        return VMProtectVersion.V3_EARLY
    if "3.x" in s:
        return VMProtectVersion.V3_EARLY  # conservative
    if "2." in s or "2.x" in s:
        return VMProtectVersion.V2
    return VMProtectVersion.UNKNOWN
