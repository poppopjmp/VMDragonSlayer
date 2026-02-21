"""
Pattern Recognizer Module

Performs pattern matching against instruction sequences to identify
VM handlers and obfuscation patterns.

When ``yara-python`` is available the :class:`PatternRecognizer` delegates
to :class:`~.yara_engine.YaraEngine` for high-performance byte-level
matching.  Otherwise it falls back to a pure-Python regex engine
transparently.
"""

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any

from .database import Pattern, PatternDatabase
from .yara_engine import YaraEngine, YaraMatch, YARA_AVAILABLE

logger = logging.getLogger(__name__)


@dataclass
class Match:
    """
    Represents a pattern match result.
    
    """
    pattern: Pattern
    start_offset: int
    end_offset: int
    confidence: float
    matched_bytes: str
    context: Dict[str, Any] = None
    
    def __post_init__(self) -> None:
        if self.context is None:
            self.context = {}


class PatternRecognizer:
    """
    Recognizes VM handler patterns in instruction sequences.

    When ``yara-python`` is installed, patterns are compiled to YARA rules
    for ~10-100× faster scanning.  The pure-Python regex path is kept as a
    seamless fallback.
    """
    
    def __init__(self, database: PatternDatabase, *, use_yara: bool = True):
        """
        Initialize pattern recognizer.

        Parameters
        ----------
        database : PatternDatabase
            Pattern database to match against.
        use_yara : bool
            If *True* (default) and ``yara-python`` is installed, compile the
            patterns to YARA rules once and use them for all subsequent scans.
        """
        self.database = database
        self._compiled_patterns: Dict[str, re.Pattern] = {}

        # YARA engine (preferred)
        self._yara: Optional[YaraEngine] = None
        if use_yara and YARA_AVAILABLE:
            try:
                engine = YaraEngine()
                n = engine.compile_from_database(database)
                if n:
                    self._yara = engine
                    logger.info("YARA engine active – %d rules compiled", n)
            except (ValueError, TypeError, AttributeError, RuntimeError, OSError):
                logger.warning("YARA compilation failed – falling back to regex", exc_info=True)
    
    def recognize(self, 
                  instruction_bytes: str,
                  min_confidence: float = 0.7,
                  architecture: Optional[str] = None,
                  handler_type: Optional[str] = None) -> List[Match]:
        """
        Recognize patterns in instruction byte sequence.

        Uses YARA when available, otherwise falls back to regex matching.

        .. versionchanged:: B70
           Applies :meth:`normalize_semantics` before matching to strip
           junk NOP opcodes inserted by obfuscators.
        """
        # Convert enum to string if needed
        if architecture and hasattr(architecture, 'value'):
            architecture = architecture.value
        if handler_type and hasattr(handler_type, 'value'):
            handler_type = handler_type.value

        # B70: normalise semantics (strip NOP junk) before matching
        normalised = self.normalize_semantics(instruction_bytes)
        
        # ---- YARA fast path ----
        if self._yara is not None:
            return self._recognize_yara(
                normalised,
                min_confidence=min_confidence,
                architecture=architecture,
                handler_type=handler_type,
            )
        
        # ---- Regex fallback ----
        return self._recognize_regex(
            normalised,
            min_confidence=min_confidence,
            architecture=architecture,
            handler_type=handler_type,
        )
    
    def recognize_single(self,
                        instruction_bytes: str,
                        min_confidence: float = 0.7,
                        architecture: Optional[str] = None,
                        handler_type: Optional[str] = None) -> Optional[Match]:
        """
        Recognize the best matching pattern.

        Convenience wrapper around :meth:`recognize` that returns only the
        highest-confidence match (or ``None`` if nothing exceeds the
        threshold).

        Args:
            instruction_bytes: Hex-encoded byte string to match against.
            min_confidence: Minimum confidence threshold (0.0–1.0).
            architecture: Optional architecture filter (e.g. ``"x86_64"``).
            handler_type: Optional handler-type filter (e.g. ``"vadd"``).

        Returns:
            The best :class:`Match`, or ``None`` if no pattern matched.
        """
        matches = self.recognize(
            instruction_bytes,
            min_confidence=min_confidence,
            architecture=architecture,
            handler_type=handler_type
        )
        return matches[0] if matches else None
    
    # ------------------------------------------------------------------
    # YARA fast path
    # ------------------------------------------------------------------

    def _recognize_yara(
        self,
        instruction_bytes: str,
        *,
        min_confidence: float = 0.7,
        architecture: Optional[str] = None,
        handler_type: Optional[str] = None,
    ) -> List[Match]:
        """Use the YARA engine for matching and translate results to Match."""
        assert self._yara is not None

        yara_hits = self._yara.scan_hex(instruction_bytes, min_confidence=min_confidence)

        # Build a set of acceptable pattern IDs when filtering by arch/type
        allowed_ids: Optional[set] = None
        if architecture or handler_type:
            allowed = self.database.search(
                architecture=architecture,
                handler_type=handler_type,
                min_confidence=0.0,
            )
            allowed_ids = {p.pattern_id for p in allowed}

        matches: list[Match] = []
        for yh in yara_hits:
            if allowed_ids is not None and yh.pattern_id not in allowed_ids:
                continue

            pattern = self.database.get_pattern(yh.pattern_id)
            if pattern is None:
                continue

            matched_hex = yh.matched_bytes.hex().upper()
            matches.append(Match(
                pattern=pattern,
                start_offset=yh.offset,
                end_offset=yh.offset + yh.length,
                confidence=yh.confidence,
                matched_bytes=self._format_bytes(matched_hex),
                context={
                    "variant_index": yh.variant_index,
                    "match_type": "yara",
                    "rule_name": yh.rule_name,
                },
            ))

        matches.sort(key=lambda m: m.confidence, reverse=True)
        logger.info("YARA found %d matches (min_confidence=%.2f)", len(matches), min_confidence)
        return matches

    # ------------------------------------------------------------------
    # Regex fallback
    # ------------------------------------------------------------------

    def _recognize_regex(
        self,
        instruction_bytes: str,
        *,
        min_confidence: float = 0.7,
        architecture: Optional[str] = None,
        handler_type: Optional[str] = None,
    ) -> List[Match]:
        """Pure-Python regex matching (original algorithm)."""
        patterns = self.database.search(
            architecture=architecture,
            handler_type=handler_type,
            min_confidence=min_confidence * 0.8,
        )

        if not patterns:
            logger.debug("No patterns found matching search criteria")
            return []

        normalized_bytes = self._normalize_bytes(instruction_bytes)

        matches: list[Match] = []
        for pattern in patterns:
            pattern_matches = self._match_pattern(pattern, normalized_bytes)
            for match in pattern_matches:
                if match.confidence >= min_confidence:
                    matches.append(match)

        matches.sort(key=lambda m: m.confidence, reverse=True)
        logger.info("Regex found %d matches (min_confidence=%.2f)", len(matches), min_confidence)
        return matches
    
    def _match_pattern(self, pattern: Pattern, normalized_bytes: str) -> List[Match]:
        """
        Match a single pattern against byte sequence.

        Tries the main signature first, then each variant.  Returns all
        successful matches (callers filter by confidence later).

        Args:
            pattern: The :class:`Pattern` to attempt.
            normalized_bytes: Uppercase hex string with separators stripped.

        Returns:
            List of :class:`Match` instances (may be empty).
        """
        matches = []
        
        # Try main signature
        match = self._try_match(pattern, pattern.signature, normalized_bytes, 0)
        if match:
            matches.append(match)
        
        # Try variants
        for i, variant in enumerate(pattern.variants):
            match = self._try_match(pattern, variant, normalized_bytes, i + 1)
            if match:
                matches.append(match)
        
        return matches
    
    def _try_match(self, 
                   pattern: Pattern, 
                   signature: str, 
                   normalized_bytes: str,
                   variant_index: int) -> Optional[Match]:
        """
        Try matching a specific signature.

        Normalises the signature, then delegates to :meth:`_exact_match`
        or :meth:`_regex_match` depending on wildcard presence.

        Args:
            pattern: Source :class:`Pattern`.
            signature: Raw hex signature string (may contain ``??`` wildcards).
            normalized_bytes: Target byte string, already normalised.
            variant_index: 0 for the main signature, 1+ for variants.

        Returns:
            A :class:`Match` on success, ``None`` otherwise.
        """
        # Normalize signature
        sig_normalized = self._normalize_bytes(signature)
        
        # Convert to regex pattern if wildcards present
        if pattern.wildcards or '?' in sig_normalized:
            regex_pattern = self._signature_to_regex(sig_normalized)
            return self._regex_match(pattern, regex_pattern, normalized_bytes, variant_index)
        else:
            # Exact match
            return self._exact_match(pattern, sig_normalized, normalized_bytes, variant_index)
    
    def _exact_match(self,
                     pattern: Pattern,
                     signature: str,
                     normalized_bytes: str,
                     variant_index: int) -> Optional[Match]:
        """
        Perform exact byte matching.

        Searches for *signature* as a literal sub-string of
        *normalized_bytes* (no wildcard expansion).  Variant matches
        receive a 5 % confidence penalty.

        Args:
            pattern: Source :class:`Pattern` (supplies base confidence).
            signature: Normalised signature (uppercase hex, no separators).
            normalized_bytes: Target byte string.
            variant_index: 0 for primary signature, 1+ for variants.

        Returns:
            A :class:`Match` on hit, ``None`` if the signature is absent.
        """
        # Find all occurrences
        index = normalized_bytes.find(signature)
        if index == -1:
            return None

        confidence = pattern.confidence
        
        if variant_index > 0:
            confidence *= 0.95 
        
        matched_bytes = normalized_bytes[index:index + len(signature)]
        
        return Match(
            pattern=pattern,
            start_offset=index // 2,  # Convert to byte offset
            end_offset=(index + len(signature)) // 2,
            confidence=confidence,
            matched_bytes=self._format_bytes(matched_bytes),
            context={'variant_index': variant_index, 'match_type': 'exact'}
        )
    
    def _regex_match(self,
                     pattern: Pattern,
                     regex_pattern: str,
                     normalized_bytes: str,
                     variant_index: int) -> Optional[Match]:
        """
        Perform regex-based matching with wildcards.

        Compiles and caches the *regex_pattern*, then searches
        *normalized_bytes*.  Confidence is adjusted for the wildcard-to-exact
        byte ratio (higher exactness → higher confidence) and variant index.

        Args:
            pattern: Source :class:`Pattern`.
            regex_pattern: Compiled-ready regex string (``??`` → ``'.{2}'``).
            normalized_bytes: Target byte string.
            variant_index: 0 for primary signature, 1+ for variants.

        Returns:
            A :class:`Match` on hit, ``None`` on miss.
        """
        # Compile and cache regex
        if regex_pattern not in self._compiled_patterns:
            self._compiled_patterns[regex_pattern] = re.compile(regex_pattern)
        
        compiled = self._compiled_patterns[regex_pattern]
        match = compiled.search(normalized_bytes)
        
        if not match:
            return None
        
        matched_str = match.group(0)
        wildcard_count = regex_pattern.count('.{2}') 
        total_bytes = len(matched_str) // 2
        exact_bytes = total_bytes - wildcard_count
        
        # Base confidence from pattern
        confidence = pattern.confidence
        
        # Adjust for wildcard ratio (more exact bytes = higher confidence)
        if total_bytes > 0:
            exactness_ratio = exact_bytes / total_bytes
            confidence *= (0.7 + 0.3 * exactness_ratio)  
        else:
            exactness_ratio = 0.0
        # Apply variant penalty
        if variant_index > 0:
            confidence *= 0.95
        
        return Match(
            pattern=pattern,
            start_offset=match.start() // 2,
            end_offset=match.end() // 2,
            confidence=confidence,
            matched_bytes=self._format_bytes(matched_str),
            context={
                'variant_index': variant_index,
                'match_type': 'wildcard',
                'wildcard_count': wildcard_count,
                'exactness_ratio': exactness_ratio
            }
        )
    
    def _signature_to_regex(self, signature: str) -> str:
        """
        Convert signature with wildcards to regex pattern.

        Splits *signature* on ``??`` tokens, ``re.escape``-s each literal
        segment, and rejoins with ``'.{2}'`` (match any two hex chars).

        Args:
            signature: Normalised hex signature containing ``??`` wildcards.

        Returns:
            A regex pattern string suitable for :func:`re.search`.
        """
        # Split on wildcard tokens, escape literal parts, rejoin
        parts = signature.split('??')
        escaped_parts = [re.escape(p) for p in parts]
        regex = '.{2}'.join(escaped_parts)
        return regex
    
    def _normalize_bytes(self, byte_string: str) -> str:
        """
        Normalize byte string by removing spaces, pipes, and converting to uppercase.

        Strips common separators (space, pipe, comma, newline, tab) and
        returns the result in uppercase so comparisons are case-insensitive.

        Args:
            byte_string: Raw hex string with arbitrary separators.

        Returns:
            Uppercase hex string with all separators removed.
        """
        # Remove common separators
        normalized = byte_string.replace(' ', '').replace('|', '').replace(',', '')
        normalized = normalized.replace('\n', '').replace('\t', '')
        return normalized.upper()
    
    def _format_bytes(self, byte_string: str) -> str:
        """
        Format byte string with spaces for readability.

        Inserts a space every two hex characters (i.e. every byte).

        Args:
            byte_string: Continuous hex string (e.g. ``"4D5A90"``).

        Returns:
            Space-separated hex string (e.g. ``"4D 5A 90"``).
        """
        return ' '.join(byte_string[i:i+2] for i in range(0, len(byte_string), 2))
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get recognizer statistics.

        Returns:
            Dict with ``total_patterns``, ``compiled_patterns``,
            ``database_stats``, ``yara_available``, and ``yara_active``.
        """
        return {
            'total_patterns': len(self.database),
            'compiled_patterns': len(self._compiled_patterns),
            'database_stats': self.database.get_statistics(),
            'yara_available': YARA_AVAILABLE,
            'yara_active': self._yara is not None,
        }

    # -- B69: Semantic normalisation for mutation-resilient matching ----------

    # Semantically equivalent instruction rewrites (mnemonic-level).
    # Used by ``normalize_semantics`` to canonicalise instructions before
    # byte-level matching, improving resilience to trivial obfuscation.
    _SEMANTIC_EQUIV: Dict[str, str] = {
        # Arithmetic / logic equivalences
        "test": "and",        # TEST and AND set the same flags; normalise to AND
        "sal": "shl",         # SAL is identical to SHL
        # Conditional branch aliases (Intel synonyms)
        "jnb": "jae",         # Jump Not Below ≡ Jump Above or Equal
        "jnbe": "ja",         # Jump Not Below or Equal ≡ Jump Above
        "jna": "jbe",         # Jump Not Above ≡ Jump Below or Equal
        "jnae": "jb",         # Jump Not Above or Equal ≡ Jump Below
        "jz": "je",           # Jump Zero ≡ Jump Equal
        "jnz": "jne",         # Jump Not Zero ≡ Jump Not Equal
        "jc": "jb",           # Jump Carry ≡ Jump Below
        "jnc": "jae",         # Jump Not Carry ≡ Jump Above or Equal
        "jp": "jpe",          # Jump Parity ≡ Jump Parity Even
        "jnp": "jpo",         # Jump Not Parity ≡ Jump Parity Odd
        # Conditional move aliases
        "cmovz": "cmove",     # CMOVZero ≡ CMOVEqual
        "cmovnz": "cmovne",   # CMOVNotZero ≡ CMOVNotEqual
        "cmovc": "cmovb",     # CMOVCarry ≡ CMOVBelow
        "cmovnc": "cmovae",   # CMOVNotCarry ≡ CMOVAboveEqual
        "cmovna": "cmovbe",   # CMOVNotAbove ≡ CMOVBelowEqual
        # Set-byte aliases
        "setz": "sete",       # SETZero ≡ SETEqual
        "setnz": "setne",     # SETNotZero ≡ SETNotEqual
        "setc": "setb",       # SETCarry ≡ SETBelow
        "setnc": "setae",     # SETNotCarry ≡ SETAboveEqual
        # Misc
        "repe": "rep",        # REP/REPE prefix equivalence for string ops
        "repz": "rep",
    }

    # Junk / NOP-equivalent single-byte opcodes (can be stripped).
    _NOP_OPCODES: frozenset[str] = frozenset({
        "90",  # NOP
        "6690", "0f1f00", "0f1f4000", "0f1f440000",  # long NOPs
        "8d4000", "8d642400",  # lea same, [same+0]
    })

    # B71/B73: Extended opcode-byte equivalences — maps obfuscator-favoured
    # byte sequences to their canonical forms.  Used for byte-level pattern
    # normalisation AFTER hex-string NOP stripping.
    _OPCODE_EQUIV: Dict[str, str] = {
        # SUB reg, 0  →  NOP (no effect)
        "83E800": "90",      # sub eax, 0
        "83E900": "90",      # sub ecx, 0
        "83EA00": "90",      # sub edx, 0
        "83EB00": "90",      # sub ebx, 0
        # ADD reg, 0  →  NOP
        "83C000": "90",      # add eax, 0
        "83C100": "90",      # add ecx, 0
        "83C200": "90",      # add edx, 0
        "83C300": "90",      # add ebx, 0
        # XOR reg, 0  → NOP
        "83F000": "90",      # xor eax, 0
        "83F100": "90",      # xor ecx, 0
        # OR reg, 0   → NOP
        "83C800": "90",      # or eax, 0
        "83C900": "90",      # or ecx, 0
        # MOV reg, reg (same) → NOP
        "89C0": "90",        # mov eax, eax
        "89C9": "90",        # mov ecx, ecx
        "89D2": "90",        # mov edx, edx
        "89DB": "90",        # mov ebx, ebx
        # LEA reg, [reg+0] → NOP (already partially in _NOP_OPCODES)
        "8D4000": "90",      # lea eax, [eax+0]
        "8D4900": "90",      # lea ecx, [ecx+0]
    }

    @classmethod
    def normalize_semantics(cls, hex_bytes: str) -> str:
        """Normalise a hex instruction stream by stripping junk NOPs.

        This is a lightweight pre-pass applied *before* byte-pattern
        matching.  It removes single-instruction NOP sequences that
        compilers and obfuscators insert without changing semantics.

        If *hex_bytes* contains mnemonic text (space-separated
        "mnemonic op1, op2" tokens), mnemonic-level equivalences from
        :attr:`_SEMANTIC_EQUIV` are applied as well.

        Returns the normalised hex string (uppercase, no spaces).
        """
        normalised = hex_bytes.replace(" ", "").upper()
        for nop in sorted(cls._NOP_OPCODES, key=len, reverse=True):
            normalised = normalised.replace(nop.upper(), "")

        # B73: Apply byte-level opcode equivalences (e.g. sub reg,0 → NOP)
        for old_bytes, new_bytes in sorted(
            cls._OPCODE_EQUIV.items(), key=lambda x: len(x[0]), reverse=True
        ):
            normalised = normalised.replace(old_bytes.upper(), new_bytes.upper())

        # B74: Second NOP stripping pass — opcode equivalences may have
        # produced new "90" (NOP) sequences that need removal.
        for nop in sorted(cls._NOP_OPCODES, key=len, reverse=True):
            normalised = normalised.replace(nop.upper(), "")

        # B71: Apply mnemonic-level semantic equivalences when the input
        # contains textual mnemonics (heuristic: presence of alpha runs
        # longer than 2 that aren't pure hex).
        if any(c.isalpha() and c not in "ABCDEFabcdef" for c in hex_bytes):
            tokens = hex_bytes.split()
            rewritten = []
            for tok in tokens:
                mn = tok.lower().rstrip(",")
                canonical = cls._SEMANTIC_EQUIV.get(mn)
                if canonical:
                    tok = canonical + tok[len(mn):]
                rewritten.append(tok)
            normalised = "".join(rewritten).replace(" ", "").upper()
            # Still strip NOPs from the text form
            for nop in sorted(cls._NOP_OPCODES, key=len, reverse=True):
                normalised = normalised.replace(nop.upper(), "")

        return normalised

    # ── B81: version fingerprinting ──────────────────────────────────

    # Protector prologue signatures — byte patterns that distinguish
    # VMProtect and Themida/Code Virtualizer at version granularity.
    _VERSION_SIGS: List[Dict[str, Any]] = [
        # VMProtect 3.0.x: pushad + large immediate load
        {"protector": "VMProtect", "version": "3.0.x", "confidence": 0.85,
         "pattern": r"60.{0,8}B8[0-9A-Fa-f]{8}"},
        # VMProtect 3.1.x: push reg + xor key + jmp dispatcher
        {"protector": "VMProtect", "version": "3.1.x", "confidence": 0.85,
         "pattern": r"5[0-7]81[F0-F7][0-9A-Fa-f]{8}(?:E9|EB)"},
        # VMProtect 3.5.x+: push reg + lea-based context switch
        {"protector": "VMProtect", "version": "3.5.x", "confidence": 0.80,
         "pattern": r"5[0-7]48(?:8D|89)[0-9A-Fa-f]{2,8}"},
        # VMProtect 3.8.x: extended handler table (64-bit specific)
        {"protector": "VMProtect", "version": "3.8.x", "confidence": 0.75,
         "pattern": r"4[89]8B[0-9A-Fa-f]{2}48[0-9A-Fa-f]{2,8}FF"},
        # Themida / Code Virtualizer 2.x
        {"protector": "Themida", "version": "2.x", "confidence": 0.80,
         "pattern": r"9C60E8000000005[DE]"},
        # Themida / Code Virtualizer 3.x
        {"protector": "Themida", "version": "3.x", "confidence": 0.80,
         "pattern": r"E8[0-9A-Fa-f]{8}(?:83|81)C4"},
    ]

    # B82: Map from YARA rule names → (protector, version, base_confidence)
    _YARA_VERSION_MAP: Dict[str, Tuple[str, str, float]] = {
        # --- VMProtect ---
        "VMP_30_Handler_Prologue": ("VMProtect", "3.0.x", 0.85),
        "VMP_31_Handler_Prologue": ("VMProtect", "3.1.x", 0.85),
        "VMP_35_Handler_Prologue": ("VMProtect", "3.5.x", 0.80),
        "VMP_38_Extended_Dispatch": ("VMProtect", "3.8.x", 0.75),
        "VMP_Dispatcher_Loop": ("VMProtect", "unknown", 0.60),
        "VMP_30_Stack_Machine": ("VMProtect", "3.0.x", 0.70),
        "VMP_31_Mutation_Engine": ("VMProtect", "3.1.x", 0.70),
        "VMP_35_Handler_Table": ("VMProtect", "3.5.x", 0.75),
        "VMP_38_Complex_Dispatch": ("VMProtect", "3.8.x", 0.70),
        # --- Themida / Code Virtualizer ---
        "Themida_2x_Entry": ("Themida", "2.x", 0.80),
        "Themida_3x_Entry": ("Themida", "3.x", 0.80),
        "CodeVirtualizer_Handler": ("Themida", "unknown", 0.65),
        "Themida_2x_VM_Init": ("Themida", "2.x", 0.75),
        "Themida_3x_Dolphin": ("Themida", "3.x", 0.75),
        "Themida_3x_Tiger": ("Themida", "3.x", 0.70),
        "CodeVirtualizer_2x_Dispatch": ("Themida", "2.x", 0.70),
        "CodeVirtualizer_3x_Dispatch": ("Themida", "3.x", 0.70),
    }

    # Confidence boost when both regex and YARA agree on the same version
    _DUAL_ENGINE_BOOST = 0.10

    def version_fingerprint(
        self,
        instruction_bytes: str,
    ) -> Dict[str, Any]:
        """Identify the protector and version from prologue bytes.

        Uses regex signatures, and — when the YARA engine is active —
        cross-validates with YARA rule matches.  Confidence is boosted
        when both engines agree on the same protector + version.

        Returns
        -------
        dict
            ``{"protector": str, "version": str, "confidence": float,
               "engines": list[str]}``
            or ``{"protector": "unknown", "version": "unknown",
                  "confidence": 0.0, "engines": []}``
        """
        best: Dict[str, Any] = {
            "protector": "unknown",
            "version": "unknown",
            "confidence": 0.0,
            "engines": [],
        }

        regex_hit: Optional[Dict[str, Any]] = None
        yara_hit: Optional[Tuple[str, str, float]] = None

        # 1. Regex-based detection
        normalised = instruction_bytes.replace(" ", "")
        for sig in self._VERSION_SIGS:
            try:
                if re.search(sig["pattern"], normalised, re.IGNORECASE):
                    if sig["confidence"] > (regex_hit or {}).get("confidence", 0.0):
                        regex_hit = {
                            "protector": sig["protector"],
                            "version": sig["version"],
                            "confidence": sig["confidence"],
                        }
            except re.error:
                continue

        # 2. YARA-based detection (when engine is available)
        if self._yara is not None:
            try:
                raw = bytes.fromhex(normalised)
                yara_matches = self._yara.scan(raw)
                best_yara_conf = 0.0
                for ym in yara_matches:
                    rule_name = ym.rule if hasattr(ym, "rule") else str(ym)
                    mapping = self._YARA_VERSION_MAP.get(rule_name)
                    if mapping and mapping[2] > best_yara_conf:
                        yara_hit = mapping
                        best_yara_conf = mapping[2]
            except (ValueError, TypeError, AttributeError, RuntimeError, OSError):
                pass  # hex decode / YARA scan failure

        # 3. Merge results — boost confidence when both agree
        engines: List[str] = []
        if regex_hit:
            best = {**regex_hit, "engines": ["regex"]}
            engines.append("regex")

        if yara_hit:
            yp, yv, yc = yara_hit
            if regex_hit and regex_hit["protector"] == yp:
                engines.append("yara")
                # Both agree on protector
                if regex_hit["version"] == yv or yv == "unknown":
                    # Same version — boost
                    best["confidence"] = min(
                        1.0, best["confidence"] + self._DUAL_ENGINE_BOOST
                    )
                    best["engines"] = engines
                else:
                    # Different version — keep higher confidence
                    if yc > best["confidence"]:
                        best = {"protector": yp, "version": yv,
                                "confidence": yc, "engines": engines}
                    else:
                        best["engines"] = engines
            elif not regex_hit:
                best = {"protector": yp, "version": yv,
                        "confidence": yc, "engines": ["yara"]}

        return best


class SequenceRecognizer:
    """
    Recognizes patterns across instruction sequences (multi-instruction patterns).
    
    """
    
    def __init__(self, database: PatternDatabase):

        self.database = database
        self.recognizer = PatternRecognizer(database)
    
    def recognize_sequence(self,
                          instructions: List[str],
                          window_size: int = 5,
                          min_confidence: float = 0.7,
                          architecture: Optional[str] = None) -> List[Match]:
        """
        Recognize patterns across a sequence of instructions.

        Slides a window of *window_size* over the instruction hex strings,
        concatenates each window, and runs single-pattern recognition.
        De-duplicates overlapping results.

        Args:
            instructions: List of hex-encoded instruction byte strings.
            window_size: Number of consecutive instructions per window.
            min_confidence: Minimum match confidence threshold.
            architecture: Optional architecture filter.

        Returns:
            De-duplicated list of :class:`Match` objects, sorted by
            descending confidence.
        """
        all_matches = []
        
        # Sliding window over instructions
        for i in range(len(instructions) - window_size + 1):
            window = instructions[i:i + window_size]
            combined_bytes = ' '.join(window)
            
            # Recognize in this window
            matches = self.recognizer.recognize(
                combined_bytes,
                min_confidence=min_confidence,
                architecture=architecture
            )
            
            # Adjust offsets to account for window position
            # The match offsets are byte-level from the combined hex string;
            # store the window index separately so callers know the context.
            for match in matches:
                match.context['window_start'] = i
                match.context['window_size'] = window_size
            
            all_matches.extend(matches)
        
        # Remove duplicate matches (same pattern, overlapping ranges)
        unique_matches = self._deduplicate_matches(all_matches)
        
        return unique_matches
    
    def _deduplicate_matches(self, matches: List[Match]) -> List[Match]:
        """
        Remove duplicate/overlapping matches, keeping highest confidence.

        Sorts by descending confidence, then greedily keeps non-overlapping
        matches using byte-offset ranges.

        Args:
            matches: Unsorted list of candidate matches.

        Returns:
            Filtered list with overlapping lower-confidence matches removed.
        """
        if not matches:
            return []
        
        # Sort by confidence (highest first)
        matches.sort(key=lambda m: m.confidence, reverse=True)
        
        unique = []
        used_ranges = []
        
        for match in matches:
            match_range = (match.start_offset, match.end_offset)
            
            # Check if this range overlaps with any used range
            overlaps = False
            for used_range in used_ranges:
                if self._ranges_overlap(match_range, used_range):
                    overlaps = True
                    break
            
            if not overlaps:
                unique.append(match)
                used_ranges.append(match_range)
        
        return unique
    
    def _ranges_overlap(self, range1: Tuple[int, int], range2: Tuple[int, int]) -> bool:
        """
        Check if two ranges overlap.

        Uses the standard non-overlapping test: two half-open intervals
        ``[a, b)`` and ``[c, d)`` overlap unless ``b <= c`` or ``d <= a``.

        Args:
            range1: ``(start, end)`` byte-offset pair.
            range2: ``(start, end)`` byte-offset pair.

        Returns:
            ``True`` if the ranges share at least one byte.
        """
        return not (range1[1] <= range2[0] or range2[1] <= range1[0])
