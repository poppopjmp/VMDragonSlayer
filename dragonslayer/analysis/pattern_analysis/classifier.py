"""
Pattern Classifier
==================

Classifies matched byte-patterns into VM handler categories by combining
rule-based heuristics with *optional* LLM refinement.  Works downstream
of :class:`PatternRecognizer` — takes a list of :class:`Match` objects and
produces :class:`ClassificationResult` records.

Usage::

    from dragonslayer.analysis.pattern_analysis.classifier import PatternClassifier

    classifier = PatternClassifier()
    results = classifier.classify_matches(matches)  # from PatternRecognizer
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set

from .database import HandlerType, Pattern

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Classification result
# ---------------------------------------------------------------------------

@dataclass
class ClassificationResult:
    """One classified pattern match."""

    pattern_id: str
    name: str
    handler_type: HandlerType
    sub_category: str = ""
    confidence: float = 0.0
    reasoning: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    llm_refined: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "handler_type": self.handler_type.value,
            "sub_category": self.sub_category,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "metadata": self.metadata,
            "llm_refined": self.llm_refined,
        }


@dataclass
class ClassificationReport:
    """Aggregate classification output."""

    results: List[ClassificationResult] = field(default_factory=list)
    category_counts: Dict[str, int] = field(default_factory=dict)
    dominant_type: Optional[HandlerType] = None
    complexity_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "results": [r.to_dict() for r in self.results],
            "category_counts": self.category_counts,
            "dominant_type": self.dominant_type.value if self.dominant_type else None,
            "complexity_score": self.complexity_score,
        }


# ---------------------------------------------------------------------------
# Heuristic rules
# ---------------------------------------------------------------------------

# Mapping from mnemonic keywords found inside pattern names / operations to
# their likely handler type.  Order matters — first match wins.
_OPERATION_RULES: List[tuple[re.Pattern, HandlerType, str]] = [
    # Arithmetic
    (re.compile(r"\b(add|sub|inc|dec|imul|idiv|mul|div|neg|adc|sbb)\b", re.I), HandlerType.ARITHMETIC, "arithmetic op"),
    # Bitwise / logic
    (re.compile(r"\b(xor|and|or|not|shl|shr|sar|sal|rol|ror|bt|bsf|bsr|bswap)\b", re.I), HandlerType.BITWISE, "bitwise op"),
    # Memory
    (re.compile(r"\b(mov|lea|lod|sto|load|store|read|write|mem)\b", re.I), HandlerType.MEMORY, "memory op"),
    # Control flow
    (re.compile(r"\b(jmp|jcc|jz|jnz|je|jne|ja|jb|jg|jl|call|ret|retn|branch|dispatch|loop|enter|leave)\b", re.I), HandlerType.CONTROL_FLOW, "control-flow op"),
    # Stack
    (re.compile(r"\b(push|pop|pusha|popa|pushf|popf|esp|rsp|stack)\b", re.I), HandlerType.STACK, "stack op"),
    # Comparison / flags
    (re.compile(r"\b(cmp|test|cmov|setz|setnz|setc|flag)\b", re.I), HandlerType.COMPARISON, "comparison / flag op"),
    # Conversion / data width
    (re.compile(r"\b(cbw|cwde|cdq|cqo|movsx|movzx|cvt|trunc|extend|widen|narrow)\b", re.I), HandlerType.CONVERSION, "conversion op"),
    # Crypto
    (re.compile(r"\b(aes|sha|crc|rc4|tea|xtea|serpent|encrypt|decrypt)\b", re.I), HandlerType.CRYPTO, "crypto op"),
]

# Byte-level heuristics for when we only have raw matched bytes.
_BYTE_RULES: List[tuple[bytes, HandlerType, str]] = [
    # Common x86 opcode prefixes
    (bytes([0x01]), HandlerType.ARITHMETIC, "ADD r/m"),
    (bytes([0x29]), HandlerType.ARITHMETIC, "SUB r/m"),
    (bytes([0x31]), HandlerType.BITWISE, "XOR r/m"),
    (bytes([0x21]), HandlerType.BITWISE, "AND r/m"),
    (bytes([0x09]), HandlerType.BITWISE, "OR r/m"),
    (bytes([0x89]), HandlerType.MEMORY, "MOV r/m"),
    (bytes([0x8B]), HandlerType.MEMORY, "MOV r,r/m"),
    (bytes([0xFF]), HandlerType.CONTROL_FLOW, "JMP/CALL indirect"),
    (bytes([0xE8]), HandlerType.CONTROL_FLOW, "CALL near"),
    (bytes([0xE9]), HandlerType.CONTROL_FLOW, "JMP near"),
    (bytes([0xC3]), HandlerType.CONTROL_FLOW, "RET"),
    (bytes([0x50]), HandlerType.STACK, "PUSH rAX"),
    (bytes([0x58]), HandlerType.STACK, "POP rAX"),
    (bytes([0x3B]), HandlerType.COMPARISON, "CMP r,r/m"),
    (bytes([0x85]), HandlerType.COMPARISON, "TEST r/m"),
]

# B56: Instruction-sequence signatures for handler body matching.
# Each entry: (mnemonic_sequence, handler_type, sub_category, base_confidence)
# Wildcards: \"*\" matches any single mnemonic, \"...\" matches 0+ mnemonics.
_INSTRUCTION_SEQ_SIGNATURES: List[tuple[List[str], HandlerType, str, float]] = [
    # VM enter: push context, set up VM frame
    (["push", "mov", "sub"], HandlerType.CONTROL_FLOW, "vm_enter", 0.8),
    (["push", "push", "push", "mov"], HandlerType.STACK, "context_save", 0.75),
    # VM exit: restore context, return
    (["pop", "pop", "pop", "ret"], HandlerType.CONTROL_FLOW, "vm_exit", 0.8),
    (["mov", "pop", "ret"], HandlerType.CONTROL_FLOW, "vm_exit", 0.75),
    # Arithmetic handlers
    (["mov", "add", "mov", "mov"], HandlerType.ARITHMETIC, "vm_add", 0.7),
    (["mov", "sub", "mov", "mov"], HandlerType.ARITHMETIC, "vm_sub", 0.7),
    (["mov", "imul", "mov"], HandlerType.ARITHMETIC, "vm_mul", 0.7),
    (["mov", "neg", "add"], HandlerType.ARITHMETIC, "vm_neg_add", 0.65),
    # Logic handlers
    (["mov", "xor", "mov", "mov"], HandlerType.BITWISE, "vm_xor", 0.7),
    (["mov", "and", "mov", "mov"], HandlerType.BITWISE, "vm_and", 0.7),
    (["mov", "or", "mov", "mov"], HandlerType.BITWISE, "vm_or", 0.7),
    (["mov", "shl", "or", "mov"], HandlerType.BITWISE, "vm_shl_or", 0.7),
    (["mov", "not", "mov"], HandlerType.BITWISE, "vm_not", 0.7),
    # Stack handlers
    (["mov", "sub", "mov"], HandlerType.STACK, "vm_push", 0.6),
    (["mov", "mov", "add"], HandlerType.STACK, "vm_pop", 0.6),
    # Key transform patterns
    (["xor", "rol", "xor"], HandlerType.CRYPTO, "key_transform_rol", 0.75),
    (["xor", "add", "xor"], HandlerType.CRYPTO, "key_transform_add", 0.75),
    (["xor", "bswap", "xor"], HandlerType.CRYPTO, "key_transform_bswap", 0.8),
    # Load/store
    (["movzx", "mov"], HandlerType.MEMORY, "vm_load_byte", 0.65),
    (["mov", "mov", "mov"], HandlerType.MEMORY, "vm_mov_chain", 0.5),
    # Compare / flags
    (["cmp", "*", "mov"], HandlerType.COMPARISON, "vm_cmp", 0.6),
    (["test", "*", "mov"], HandlerType.COMPARISON, "vm_test", 0.6),
]

# ═══════════════════════════════════════════════════════════════════════════════
# B61: Mutation-resilient matching helpers
# ═══════════════════════════════════════════════════════════════════════════════

# Known VMProtect junk mnemonics / patterns that should be stripped before
# sequence matching.  These are NOPs, identity moves, and dead computations
# that VMProtect inserts to obscure handler bodies.
_JUNK_MNEMONICS: Set[str] = {"nop", "fnop", "pause", "int3", "ud2"}

# Additional junk detection: identity instructions like "mov eax, eax" or
# "xchg eax, eax" or "lea eax, [eax+0]".  We detect these using a simple
# operand-equality check.
_IDENTITY_MNEMONICS: Set[str] = {"mov", "xchg", "lea"}


def _is_junk_instruction(mnemonic: str, operands: str = "") -> bool:
    """Return True if the instruction is likely junk / dead code.

    Recognised junk patterns:
    - Pure NOPs and equivalents (nop, fnop, pause)
    - Identity moves: ``mov rax, rax``, ``xchg rax, rax``
    - Zero-displacement LEA: ``lea rax, [rax]``
    """
    mnem = mnemonic.lower()
    if mnem in _JUNK_MNEMONICS:
        return True
    if mnem in _IDENTITY_MNEMONICS and operands:
        # Normalise and split
        parts = [p.strip().lower() for p in operands.split(",")]
        if len(parts) == 2:
            a, b = parts
            if a == b:
                return True
            # LEA with zero displacement: lea rax, [rax] or lea rax, [rax+0]
            if mnem == "lea":
                clean_b = b.strip("[]").replace("+0", "").replace("+ 0", "").strip()
                if a == clean_b:
                    return True
    return False


def strip_junk(mnemonics: List[str], operands_list: List[str] | None = None) -> List[str]:
    """Remove junk instructions from a mnemonic list.

    When *operands_list* is provided (parallel to *mnemonics*), identity
    instructions are also detected.  Returns the filtered mnemonic list.
    """
    if operands_list is None:
        operands_list = [""] * len(mnemonics)
    return [
        m for m, o in zip(mnemonics, operands_list)
        if not _is_junk_instruction(m, o)
    ]


# Register-class normalisation for register-agnostic matching.
_GP64 = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
         "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}
_GP32 = {r.replace("r", "e", 1) if r.startswith("r") and not r[1:].isdigit() else f"{r}d"
         for r in _GP64}
_GP32 |= {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
           "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"}


def normalize_operands(operands: str) -> str:
    """Replace concrete register names with class tokens.

    ``mov eax, [ecx+0x10]`` → ``mov GP32, [GP32+0x10]``

    This allows signatures to match regardless of which specific
    register VMProtect selects after register allocation.
    """
    result = operands
    # Sort longest first to avoid partial replacement
    for reg in sorted(_GP64, key=len, reverse=True):
        result = result.replace(reg, "GP64")
    for reg in sorted(_GP32, key=len, reverse=True):
        result = result.replace(reg, "GP32")
    return result


def _match_instruction_sequence_gap(
    mnemonics: List[str],
    pattern: List[str],
    max_gap: int = 2,
) -> bool:
    """Gap-tolerant sequence matching.

    Like :func:`_match_instruction_sequence` but allows up to *max_gap*
    non-matching instructions between each pair of consecutive pattern
    elements.  ``\"*\"`` still matches any single mnemonic.  This makes
    the matcher resilient to junk instructions that survive the strip
    pass (e.g. ``push; <junk>; mov`` matches ``[push, mov]`` with gap=1).
    """
    if not pattern:
        return True
    n = len(mnemonics)
    plen = len(pattern)
    if plen > n:
        return False

    def _matches(mnem: str, pat: str) -> bool:
        return pat == "*" or mnem == pat

    # B63: Memoize (mi, pi) → bool to prevent exponential backtracking
    _memo: Dict[tuple[int, int], bool] = {}

    def _search(mi: int, pi: int) -> bool:
        if pi == plen:
            return True
        key = (mi, pi)
        if key in _memo:
            return _memo[key]
        result = False
        for i in range(mi, n):
            if _matches(mnemonics[i], pattern[pi]):
                # Check gap constraint: gap = i - mi (skipped instructions)
                if pi > 0 and (i - mi) > max_gap:
                    break  # further positions only increase gap
                if _search(i + 1, pi + 1):
                    result = True
                    break
        _memo[key] = result
        return result

    # Try every starting position
    for start in range(n):
        if _matches(mnemonics[start], pattern[0]):
            if _search(start + 1, 1):
                return True
    return False


def _match_instruction_sequence(
    mnemonics: List[str],
    pattern: List[str],
) -> bool:
    """Check if *mnemonics* contains *pattern* as a subsequence.

    ``\"*\"`` matches any single mnemonic.  Plain strings match exactly.
    """
    if not pattern:
        return True
    if len(pattern) > len(mnemonics):
        return False
    # Sliding window match
    plen = len(pattern)
    for start in range(len(mnemonics) - plen + 1):
        matched = True
        for j, p in enumerate(pattern):
            if p == "*":
                continue
            if mnemonics[start + j] != p:
                matched = False
                break
        if matched:
            return True
    return False


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

class PatternClassifier:
    """
    Classifies matched patterns into VM handler categories.

    Two-pass approach:

    1. **Rule-based** — fast mnemonic / operation / byte heuristics.
    2. **LLM-refined** — optional; sends ambiguous results to the LLM for
       a more nuanced classification.  Requires the ``llm`` module.
    """

    def __init__(self, *, use_llm: bool = False) -> None:
        self._use_llm = use_llm

    # -- public API ---------------------------------------------------------

    def classify_matches(
        self,
        matches: Sequence[Any],
        *,
        min_confidence: float = 0.0,
    ) -> ClassificationReport:
        """
        Classify a list of :class:`Match` or match-dict objects.

        Parameters
        ----------
        matches
            Match objects (from PatternRecognizer) or dicts with keys
            ``pattern_id``, ``name``, ``operation``, ``handler_type``,
            ``matched_bytes``, ``confidence``.
        min_confidence
            Drop results below this confidence.

        Returns
        -------
        ClassificationReport
        """
        results: List[ClassificationResult] = []

        for m in matches:
            cr = self._classify_single(m)
            if cr.confidence >= min_confidence:
                results.append(cr)

        # Optional LLM refinement pass
        if self._use_llm:
            results = self._llm_refine(results)

        # Build report
        category_counts: Dict[str, int] = {}
        for r in results:
            key = r.handler_type.value
            category_counts[key] = category_counts.get(key, 0) + 1

        dominant = max(category_counts, key=category_counts.get, default=None) if category_counts else None
        dominant_type = HandlerType(dominant) if dominant else None

        complexity = self._compute_complexity(results, category_counts)

        return ClassificationReport(
            results=results,
            category_counts=category_counts,
            dominant_type=dominant_type,
            complexity_score=complexity,
        )

    def classify_handler_bytes(
        self,
        raw_bytes: bytes,
        *,
        handler_name: str = "",
        mnemonics: Optional[List[str]] = None,
        operands: Optional[List[str]] = None,
    ) -> ClassificationResult:
        """
        Classify a raw handler byte sequence directly (no Match object).

        Parameters
        ----------
        raw_bytes : bytes
            Raw handler bytes.
        handler_name : str
            Optional handler name for keyword matching.
        mnemonics : list of str or None
            B56: Optional mnemonic sequence for instruction-sequence matching.
        operands : list of str or None
            B63: Per-instruction operand strings (parallel to *mnemonics*).
            Used for identity-mov detection in junk stripping and
            register-class normalization for LLM refinement.
        """
        match_dict: Dict[str, Any] = {
            "pattern_id": f"raw_{handler_name or 'unknown'}",
            "name": handler_name or "raw_handler",
            "operation": "",
            "handler_type": "unknown",
            "matched_bytes": raw_bytes.hex().upper(),
            "confidence": 0.5,
        }
        if mnemonics is not None:
            match_dict["_mnemonics"] = mnemonics
        if operands is not None:
            match_dict["_operands"] = operands
            # B63: Store register-normalized operands for LLM / downstream
            match_dict["_normalized_operands"] = [
                normalize_operands(op) for op in operands
            ]
        return self._classify_single(match_dict)

    # -- internal -----------------------------------------------------------

    @staticmethod
    def _to_dict(match: Any) -> Dict[str, Any]:
        """Normalize a Match object or dict into a dict."""
        if isinstance(match, dict):
            return match
        # Match dataclass from recognizer
        d: Dict[str, Any] = {}
        if hasattr(match, "pattern"):
            p = match.pattern
            d["pattern_id"] = getattr(p, "pattern_id", "")
            d["name"] = getattr(p, "name", "")
            d["operation"] = getattr(p, "operation", "")
            d["handler_type"] = getattr(p, "handler_type", "unknown")
        d.setdefault("pattern_id", getattr(match, "pattern_id", ""))
        d.setdefault("name", getattr(match, "name", ""))
        d.setdefault("operation", getattr(match, "operation", ""))
        d.setdefault("handler_type", getattr(match, "handler_type", "unknown"))
        d["matched_bytes"] = getattr(match, "matched_bytes", "")
        d["confidence"] = getattr(match, "confidence", 0.0)
        # Preserve internal analysis fields (B56+ mnemonics, B61 operands)
        for internal_key in ("_mnemonics", "_operands"):
            if isinstance(match, dict) and internal_key in match:
                d[internal_key] = match[internal_key]
            elif hasattr(match, internal_key.lstrip("_")):
                d[internal_key] = getattr(match, internal_key.lstrip("_"))
        return d

    def _classify_single(self, match: Any) -> ClassificationResult:
        """Classify one match using heuristic rules."""
        d = self._to_dict(match)

        # Start with the declared handler_type if it's already meaningful
        declared = d.get("handler_type", "unknown")
        if isinstance(declared, str):
            try:
                ht = HandlerType(declared)
            except ValueError:
                ht = HandlerType.UNKNOWN
        else:
            ht = declared if isinstance(declared, HandlerType) else HandlerType.UNKNOWN

        reasoning_parts: List[str] = []

        # 1) If declared type is already specific, trust it
        if ht != HandlerType.UNKNOWN:
            reasoning_parts.append(f"declared as {ht.value}")
        else:
            # 2) Operation / name keyword matching
            text = f"{d.get('operation', '')} {d.get('name', '')}"
            for pattern, handler_type, label in _OPERATION_RULES:
                if pattern.search(text):
                    ht = handler_type
                    reasoning_parts.append(f"keyword match: {label}")
                    break

        # 3) B56: Instruction-sequence signature matching
        seq_sub_cat = ""
        if ht == HandlerType.UNKNOWN:
            mnems = d.get("_mnemonics", [])
            if mnems:
                # 3a) Strict sliding-window match (original B56)
                for sig_pattern, sig_type, sig_sub, sig_conf in _INSTRUCTION_SEQ_SIGNATURES:
                    if _match_instruction_sequence(mnems, sig_pattern):
                        ht = sig_type
                        seq_sub_cat = sig_sub
                        reasoning_parts.append(f"instruction-seq match: {sig_sub}")
                        break

                # 3b) B61: If strict failed, try junk-stripped strict match
                if ht == HandlerType.UNKNOWN:
                    operands_list = d.get("_operands", None)
                    stripped = strip_junk(mnems, operands_list)
                    if len(stripped) < len(mnems):  # stripping had effect
                        for sig_pattern, sig_type, sig_sub, sig_conf in _INSTRUCTION_SEQ_SIGNATURES:
                            if _match_instruction_sequence(stripped, sig_pattern):
                                ht = sig_type
                                seq_sub_cat = sig_sub
                                reasoning_parts.append(
                                    f"junk-stripped seq match: {sig_sub}"
                                )
                                break

                # 3c) B61: Gap-tolerant fuzzy match as final fallback
                if ht == HandlerType.UNKNOWN:
                    for sig_pattern, sig_type, sig_sub, sig_conf in _INSTRUCTION_SEQ_SIGNATURES:
                        if _match_instruction_sequence_gap(mnems, sig_pattern, max_gap=2):
                            ht = sig_type
                            seq_sub_cat = sig_sub
                            # Slightly lower confidence for fuzzy
                            reasoning_parts.append(
                                f"gap-tolerant seq match: {sig_sub}"
                            )
                            break

        # 4) If still unknown, try byte-level heuristics
        if ht == HandlerType.UNKNOWN:
            matched_hex = d.get("matched_bytes", "")
            try:
                raw = bytes.fromhex(matched_hex.replace(" ", ""))
            except (ValueError, AttributeError):
                raw = b""
            if raw:
                for prefix, handler_type, label in _BYTE_RULES:
                    if raw[:len(prefix)] == prefix:
                        ht = handler_type
                        reasoning_parts.append(f"byte heuristic: {label}")
                        break

        # 4) Compute confidence
        base_conf = d.get("confidence", 0.5)
        # Boost if multiple signals agree
        boost = 0.05 * len(reasoning_parts)
        confidence = min(base_conf + boost, 1.0)

        # Determine sub-category from operation field or instruction-seq match
        sub_cat = seq_sub_cat or d.get("operation", "") or ""

        return ClassificationResult(
            pattern_id=d.get("pattern_id", ""),
            name=d.get("name", ""),
            handler_type=ht,
            sub_category=sub_cat,
            confidence=confidence,
            reasoning="; ".join(reasoning_parts) if reasoning_parts else "no heuristic match",
        )

    def _llm_refine(
        self,
        results: List[ClassificationResult],
    ) -> List[ClassificationResult]:
        """Send ambiguous classifications to the LLM for refinement."""
        try:
            from ...llm import get_llm_analyzer
            llm = get_llm_analyzer()
            if not llm.available:
                return results
        except (ImportError, AttributeError, RuntimeError):
            return results

        refined: List[ClassificationResult] = []
        for cr in results:
            # Only refine uncertain ones
            if cr.handler_type == HandlerType.UNKNOWN or cr.confidence < 0.6:
                try:
                    import json
                    llm_result = llm.classify_handler(
                        handler_data=json.dumps(cr.to_dict(), indent=2),
                        context=f"sub_category={cr.sub_category}",
                    )
                    if "error" not in llm_result:
                        suggested = llm_result.get("category", "").lower()
                        try:
                            new_ht = HandlerType(suggested)
                        except ValueError:
                            new_ht = cr.handler_type
                        cr = ClassificationResult(
                            pattern_id=cr.pattern_id,
                            name=cr.name,
                            handler_type=new_ht,
                            sub_category=cr.sub_category,
                            confidence=min(cr.confidence + 0.15, 1.0),
                            reasoning=cr.reasoning + f"; LLM refined → {new_ht.value}",
                            metadata={"llm_response": llm_result},
                            llm_refined=True,
                        )
                except (ValueError, TypeError, KeyError, AttributeError, RuntimeError) as exc:
                    logger.debug("LLM refinement failed for %s: %s", cr.pattern_id, exc)
            refined.append(cr)

        return refined

    @staticmethod
    def _compute_complexity(
        results: List[ClassificationResult],
        counts: Dict[str, int],
    ) -> float:
        """
        Compute a 0.0–1.0 complexity score based on handler diversity.

        More distinct handler types AND higher total count ⇒ more complex VM.
        """
        if not results:
            return 0.0

        n_types = len(counts)
        n_total = len(results)

        # Diversity component: max 9 handler types (all minus UNKNOWN)
        diversity = min(n_types / 8.0, 1.0)
        # Volume component: logarithmic scaling
        import math
        volume = min(math.log2(1 + n_total) / 10.0, 1.0)
        # Average confidence penalty for low confidence
        avg_conf = sum(r.confidence for r in results) / n_total
        conf_factor = avg_conf

        return round(0.4 * diversity + 0.3 * volume + 0.3 * conf_factor, 4)
