"""
YARA-Based Pattern Matching Engine

Compiles PatternDatabase entries into YARA rules for high-performance
byte-level pattern matching.  Falls back to pure-Python regex when
``yara-python`` is not installed.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .database import Pattern, PatternDatabase

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional import – graceful degradation
# ---------------------------------------------------------------------------
try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    yara = None
    YARA_AVAILABLE = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sig_to_yara_hex(signature: str) -> str:
    """Convert a DB signature to a YARA hex-string body.

    Input  : ``"48 01 ?? 48 89 ??"``
    Output : ``"48 01 ?? 48 89 ??"``  (identical – already compatible)

    If the signature uses pipes or commas as separators they are stripped.
    """
    cleaned = signature.replace("|", " ").replace(",", " ")
    # Collapse whitespace
    tokens = cleaned.split()
    return " ".join(tokens)


def _safe_identifier(name: str) -> str:
    """Sanitise a pattern_id/name so it is a valid YARA identifier."""
    ident = re.sub(r"[^A-Za-z0-9_]", "_", name)
    # Must start with a letter or underscore
    if ident and ident[0].isdigit():
        ident = "_" + ident
    return ident


# ---------------------------------------------------------------------------
# YaraRule building
# ---------------------------------------------------------------------------

@dataclass
class _YaraRuleEntry:
    """Internal: one compiled YARA rule entry mapped back to a Pattern."""
    rule_name: str
    pattern_id: str
    confidence: float
    variant_index: int  # 0 = main sig, 1+ = variant


def _build_yara_source(patterns: list[Pattern]) -> tuple[str, list[_YaraRuleEntry]]:
    """Build a single YARA source string from *patterns*.

    Returns ``(source, entries)`` where *entries* map each rule name
    back to its originating ``Pattern`` and variant index.
    """
    entries: list[_YaraRuleEntry] = []
    rules: list[str] = []

    for pat in patterns:
        # Main signature
        main_ident = _safe_identifier(pat.pattern_id)
        hex_body = _sig_to_yara_hex(pat.signature)
        rules.append(
            f'rule {main_ident} {{\n'
            f'  strings:\n'
            f'    $sig = {{ {hex_body} }}\n'
            f'  condition:\n'
            f'    $sig\n'
            f'}}\n'
        )
        entries.append(_YaraRuleEntry(
            rule_name=main_ident,
            pattern_id=pat.pattern_id,
            confidence=pat.confidence,
            variant_index=0,
        ))

        # Variants
        for vi, variant_sig in enumerate(pat.variants, start=1):
            var_ident = f"{main_ident}_v{vi}"
            var_hex = _sig_to_yara_hex(variant_sig)
            rules.append(
                f'rule {var_ident} {{\n'
                f'  strings:\n'
                f'    $sig = {{ {var_hex} }}\n'
                f'  condition:\n'
                f'    $sig\n'
                f'}}\n'
            )
            entries.append(_YaraRuleEntry(
                rule_name=var_ident,
                pattern_id=pat.pattern_id,
                confidence=pat.confidence * 0.95,
                variant_index=vi,
            ))

    source = "\n".join(rules)
    return source, entries


# ---------------------------------------------------------------------------
# Public engine class
# ---------------------------------------------------------------------------

@dataclass
class YaraMatch:
    """A single YARA match result."""
    pattern_id: str
    rule_name: str
    offset: int
    length: int
    confidence: float
    variant_index: int
    matched_bytes: bytes
    meta: dict[str, Any] = field(default_factory=dict)


class YaraEngine:
    """Compile DB patterns into YARA rules and scan binary data.

    Usage::

        engine = YaraEngine()
        engine.compile_from_database(db)
        matches = engine.scan(raw_bytes)
    """

    def __init__(self) -> None:
        self._compiled: Any | None = None  # yara.Rules
        self._entries: list[_YaraRuleEntry] = []
        self._entry_lookup: dict[str, _YaraRuleEntry] = {}

    # ------------------------------------------------------------------
    @property
    def is_available(self) -> bool:  # noqa: D401
        """``True`` when ``yara-python`` is installed."""
        return YARA_AVAILABLE

    @property
    def is_compiled(self) -> bool:  # noqa: D401
        """``True`` when rules have been compiled and are ready for scanning."""
        return self._compiled is not None

    # ------------------------------------------------------------------
    def compile_from_database(
        self,
        database: PatternDatabase,
        *,
        architecture: str | None = None,
        handler_type: str | None = None,
        min_confidence: float = 0.0,
    ) -> int:
        """Compile patterns from *database* into YARA rules.

        Returns the number of YARA rules compiled.

        Raises ``RuntimeError`` if ``yara-python`` is not installed.
        """
        if not YARA_AVAILABLE:
            raise RuntimeError(
                "yara-python is not installed.  "
                "Install it with:  pip install yara-python"
            )

        patterns = database.search(
            architecture=architecture,
            handler_type=handler_type,
            min_confidence=min_confidence,
        )

        if not patterns:
            logger.warning("No patterns matched the search criteria – nothing to compile")
            self._compiled = None
            self._entries = []
            self._entry_lookup = {}
            return 0

        source, entries = _build_yara_source(patterns)
        self._compiled = yara.compile(source=source)
        self._entries = entries
        self._entry_lookup = {e.rule_name: e for e in entries}

        logger.info("Compiled %d YARA rules from %d patterns", len(entries), len(patterns))
        return len(entries)

    def compile_from_source(self, source: str) -> int:
        """Compile raw YARA source (for external ``.yar`` files).

        Returns the number of rules (not directly known – returns 1 as a
        sentinel since ``yara.Rules`` doesn't expose a count).
        """
        if not YARA_AVAILABLE:
            raise RuntimeError("yara-python is not installed")
        self._compiled = yara.compile(source=source)
        self._entries = []
        self._entry_lookup = {}
        return 1

    # ------------------------------------------------------------------
    def scan(
        self,
        data: bytes,
        *,
        min_confidence: float = 0.0,
    ) -> list[YaraMatch]:
        """Scan *data* against compiled YARA rules.

        Returns a list of :class:`YaraMatch` ordered by offset.
        """
        if self._compiled is None:
            raise RuntimeError("No YARA rules compiled – call compile_from_database first")

        raw_matches = self._compiled.match(data=data)

        results: list[YaraMatch] = []
        for m in raw_matches:
            entry = self._entry_lookup.get(m.rule)
            confidence = entry.confidence if entry else 0.9
            variant_index = entry.variant_index if entry else 0
            pattern_id = entry.pattern_id if entry else m.rule

            if confidence < min_confidence:
                continue

            for offset, _identifier, matched_data in m.strings:
                results.append(YaraMatch(
                    pattern_id=pattern_id,
                    rule_name=m.rule,
                    offset=offset,
                    length=len(matched_data),
                    confidence=confidence,
                    variant_index=variant_index,
                    matched_bytes=matched_data,
                ))

        results.sort(key=lambda r: r.offset)
        return results

    # ------------------------------------------------------------------
    def scan_hex(
        self,
        hex_string: str,
        *,
        min_confidence: float = 0.0,
    ) -> list[YaraMatch]:
        """Convenience: scan a hex-encoded byte string."""
        cleaned = hex_string.replace(" ", "").replace("|", "").replace(",", "")
        data = bytes.fromhex(cleaned)
        return self.scan(data, min_confidence=min_confidence)
