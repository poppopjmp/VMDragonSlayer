"""
Context-Aware Pattern Matcher  (Batch 36)
==========================================

Wraps the byte-level :class:`PatternRecognizer` with context-aware
disambiguation so that the 75-pattern VMProtect handler database produces
meaningful, ranked results even when several patterns share the same
byte signature.

The :class:`PatternMatcher` adds:

* **Collision detection** — pre-computes groups of patterns with identical
  normalised signatures.
* **Context scoring** — promotes / demotes candidates using:
    - surrounding (prefix/suffix) instruction mnemonics,
    - register-usage heuristics (pushall → vm_entry_exit, etc.),
    - handler position relative to the dispatcher,
    - operation semantic coherence.
* **Ranked output** — returns :class:`RankedMatch` objects with a
  ``reason`` string explaining the ranking decision.
* **Batch matching** — ``match_handler_sequence()`` processes a list
  of handler snippets in one call.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .database import Pattern, PatternDatabase
from .recognizer import Match, PatternRecognizer

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class MatchContext:
    """Surrounding context supplied to the matcher for disambiguation.

    All fields are optional — the matcher uses whatever is available.
    """
    preceding_mnemonics: list[str] = field(default_factory=list)
    following_mnemonics: list[str] = field(default_factory=list)
    registers_read: list[str] = field(default_factory=list)
    registers_written: list[str] = field(default_factory=list)
    handler_index: int | None = None
    dispatcher_address: int | None = None
    handler_address: int | None = None


@dataclass
class RankedMatch:
    """A pattern match with context-aware scoring and ranking rationale."""
    pattern: Pattern
    base_confidence: float
    context_score: float
    final_score: float
    start_offset: int
    end_offset: int
    matched_bytes: str
    reason: str
    alternatives: list[RankedMatch] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern.pattern_id,
            "operation": self.pattern.operation,
            "handler_type": self.pattern.handler_type,
            "base_confidence": round(self.base_confidence, 4),
            "context_score": round(self.context_score, 4),
            "final_score": round(self.final_score, 4),
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
            "matched_bytes": self.matched_bytes,
            "reason": self.reason,
            "alternatives_count": len(self.alternatives),
        }


# ---------------------------------------------------------------------------
# Context scoring heuristics
# ---------------------------------------------------------------------------

# Mnemonic sets used for context classification
_ARITH_MNEMONICS: set[str] = {
    "add", "sub", "imul", "mul", "idiv", "div", "neg", "inc", "dec",
    "adc", "sbb",
}
_LOGIC_MNEMONICS: set[str] = {
    "and", "or", "xor", "not", "shl", "shr", "sar", "rol", "ror",
    "bt", "bts", "btr", "btc",
}
_MEMORY_MNEMONICS: set[str] = {
    "mov", "movzx", "movsx", "movsxd", "lea", "movabs",
}
_STACK_MNEMONICS: set[str] = {"push", "pop", "pushf", "popf", "pusha", "popa"}
_BRANCH_MNEMONICS: set[str] = {
    "jmp", "je", "jne", "jz", "jnz", "jb", "ja", "jl", "jg",
    "jbe", "jae", "jle", "jge", "call", "ret", "cmove", "cmovne",
}
_CRYPTO_MNEMONICS: set[str] = {
    "cpuid", "rdtsc", "bswap", "ror", "rol",
}
_ENTRY_EXIT_MNEMONICS: set[str] = {"pushf", "popf", "ret"}

# Register sets for context classification
_GP_REGS_64: set[str] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}
_CONTEXT_REGS: set[str] = {"rsi", "rdi"}  # typically VM context/bytecode pointers


def _mnemonic_category_score(
    mnemonics: list[str],
    handler_type: str,
) -> float:
    """Score how well *mnemonics* match *handler_type*."""
    if not mnemonics:
        return 0.0

    mset = {m.lower() for m in mnemonics}
    overlap_map: dict[str, set[str]] = {
        "arithmetic": _ARITH_MNEMONICS,
        "bitwise": _LOGIC_MNEMONICS,
        "memory": _MEMORY_MNEMONICS,
        "stack": _STACK_MNEMONICS,
        "control_flow": _BRANCH_MNEMONICS,
        "crypto": _CRYPTO_MNEMONICS,
        "conversion": _MEMORY_MNEMONICS,  # movzx/movsx-heavy
        "comparison": {"cmp", "test"},
    }

    target_set = overlap_map.get(handler_type, set())
    if not target_set:
        return 0.0

    overlap = len(mset & target_set)
    return overlap / max(len(mset), 1)


def _register_pattern_score(
    reads: list[str],
    writes: list[str],
    handler_type: str,
) -> float:
    """Score based on register-usage patterns."""
    rset = {r.lower() for r in reads}
    wset = {w.lower() for w in writes}
    all_regs = rset | wset
    score = 0.0

    if handler_type == "stack":
        # Stack ops should touch rsp/rbp
        if {"rsp", "rbp"} & all_regs:
            score += 0.4

    elif handler_type == "control_flow":
        # Branches often modify rip/rsi (VPC)
        if {"rsi", "rip"} & wset:
            score += 0.3

    elif handler_type == "memory":
        # Memory ops should have both reads and writes
        if rset and wset:
            score += 0.2

    elif handler_type == "arithmetic":
        # Arithmetic typically uses rax/rcx as accumulators
        if {"rax", "rcx"} & all_regs:
            score += 0.2

    # Crypto handlers often touch many registers
    elif handler_type == "crypto" and len(all_regs & _GP_REGS_64) >= 3:
        score += 0.3

    return min(score, 1.0)


def _position_score(
    handler_index: int | None,
    handler_type: str,
) -> float:
    """Score based on handler position (e.g., vm_enter is typically first)."""
    if handler_index is None:
        return 0.0

    # vm_entry patterns are likely at the start of a handler sequence
    if handler_type in ("control_flow",) and handler_index == 0:
        return 0.15

    return 0.0


def _compute_context_score(
    pattern: Pattern,
    ctx: MatchContext,
) -> tuple[float, str]:
    """Compute the aggregate context score and reason string."""
    scores: list[tuple[float, str]] = []

    # 1. Surrounding mnemonic coherence
    all_mnemonics = ctx.preceding_mnemonics + ctx.following_mnemonics
    mnem_score = _mnemonic_category_score(all_mnemonics, pattern.handler_type)
    if mnem_score > 0:
        scores.append((mnem_score * 0.4, f"mnemonic_coherence={mnem_score:.2f}"))

    # 2. Register usage
    reg_score = _register_pattern_score(
        ctx.registers_read, ctx.registers_written, pattern.handler_type,
    )
    if reg_score > 0:
        scores.append((reg_score * 0.3, f"register_pattern={reg_score:.2f}"))

    # 3. Position in handler sequence
    pos_score = _position_score(ctx.handler_index, pattern.handler_type)
    if pos_score > 0:
        scores.append((pos_score, f"position_bonus={pos_score:.2f}"))

    # 4. Preceding-instruction specificity (e.g., push-heavy prefix → stack)
    if ctx.preceding_mnemonics:
        pre_set = {m.lower() for m in ctx.preceding_mnemonics}
        if pre_set & _STACK_MNEMONICS and pattern.handler_type == "stack":
            scores.append((0.1, "stack_prefix"))
        elif pre_set & _ARITH_MNEMONICS and pattern.handler_type == "arithmetic":
            scores.append((0.1, "arith_prefix"))

    total = sum(s for s, _ in scores)
    reason_parts = [r for _, r in scores]
    reason = "; ".join(reason_parts) if reason_parts else "no_context"

    return min(total, 1.0), reason


# ---------------------------------------------------------------------------
# Collision detection
# ---------------------------------------------------------------------------

def _normalize_signature(sig: str) -> str:
    """Normalise a signature for collision detection (strip spaces, uppercase)."""
    return sig.replace(" ", "").replace("|", "").upper()


def find_signature_collisions(db: PatternDatabase) -> dict[str, list[str]]:
    """Return groups of pattern IDs that share identical normalised signatures.

    Only groups with 2+ patterns are returned.
    """
    sig_map: dict[str, list[str]] = {}
    for pat in db.get_all_patterns():
        nsig = _normalize_signature(pat.signature)
        sig_map.setdefault(nsig, []).append(pat.pattern_id)
        # Also check variants
        for variant in pat.variants:
            nv = _normalize_signature(variant)
            sig_map.setdefault(nv, []).append(pat.pattern_id)

    return {sig: ids for sig, ids in sig_map.items() if len(set(ids)) >= 2}


# ---------------------------------------------------------------------------
# PatternMatcher — context-aware wrapper
# ---------------------------------------------------------------------------

class PatternMatcher:
    """Context-aware pattern matcher that wraps :class:`PatternRecognizer`.

    Usage::

        db = PatternDatabase(Path("data/patterns/vmprotect_handlers.json"))
        matcher = PatternMatcher(db)
        results = matcher.match(
            "48 8B 45 00 48 03 45 08",
            context=MatchContext(preceding_mnemonics=["push", "mov"]),
        )
        for r in results:
            print(r.pattern.operation, r.final_score, r.reason)
    """

    def __init__(
        self,
        database: PatternDatabase,
        *,
        use_yara: bool = True,
        context_weight: float = 0.3,
    ) -> None:
        self.database = database
        self._recognizer = PatternRecognizer(database, use_yara=use_yara)
        self.context_weight = max(0.0, min(context_weight, 1.0))
        self._collisions = find_signature_collisions(database)

    # -- Public API ---------------------------------------------------------

    def match(
        self,
        instruction_bytes: str,
        *,
        context: MatchContext | None = None,
        min_confidence: float = 0.5,
        architecture: str | None = None,
        handler_type: str | None = None,
        top_k: int = 5,
    ) -> list[RankedMatch]:
        """Match *instruction_bytes* and return ranked results.

        When *context* is provided, candidates are re-scored using
        contextual heuristics.  Colliding patterns are disambiguated
        and only the best candidate per collision group is kept.
        """
        raw_matches = self._recognizer.recognize(
            instruction_bytes,
            min_confidence=min_confidence * 0.6,  # widen for re-ranking
            architecture=architecture,
            handler_type=handler_type,
        )

        if not raw_matches:
            return []

        ctx = context or MatchContext()
        ranked = self._rank_matches(raw_matches, ctx)

        # Disambiguate collisions: keep only the best per signature group
        ranked = self._disambiguate(ranked)

        # Apply final confidence threshold
        ranked = [r for r in ranked if r.final_score >= min_confidence]
        ranked.sort(key=lambda r: r.final_score, reverse=True)

        return ranked[:top_k]

    def match_handler_sequence(
        self,
        handler_bytes_list: list[str],
        *,
        contexts: list[MatchContext] | None = None,
        min_confidence: float = 0.5,
        architecture: str | None = None,
    ) -> list[list[RankedMatch]]:
        """Match a sequence of handler byte-strings in batch.

        Returns one list of :class:`RankedMatch` per handler.  If
        *contexts* is provided it must have the same length as
        *handler_bytes_list*.
        """
        results: list[list[RankedMatch]] = []
        for i, hbytes in enumerate(handler_bytes_list):
            ctx = contexts[i] if contexts and i < len(contexts) else None
            if ctx is None:
                ctx = MatchContext(handler_index=i)
            elif ctx.handler_index is None:
                ctx.handler_index = i
            results.append(self.match(
                hbytes,
                context=ctx,
                min_confidence=min_confidence,
                architecture=architecture,
            ))
        return results

    @property
    def collision_groups(self) -> dict[str, list[str]]:
        """Return the pre-computed signature collision groups."""
        return dict(self._collisions)

    def get_statistics(self) -> dict[str, Any]:
        """Matcher statistics."""
        inner = self._recognizer.get_statistics()
        inner["collision_groups"] = len(self._collisions)
        inner["colliding_patterns"] = sum(
            len(set(ids)) for ids in self._collisions.values()
        )
        inner["context_weight"] = self.context_weight
        return inner

    # -- Internal -----------------------------------------------------------

    def _rank_matches(
        self, raw_matches: list[Match], ctx: MatchContext,
    ) -> list[RankedMatch]:
        """Re-score raw matches with context and produce RankedMatch list."""
        ranked: list[RankedMatch] = []
        for m in raw_matches:
            ctx_score, reason = _compute_context_score(m.pattern, ctx)
            # Blend base confidence and context score
            w = self.context_weight
            final = (1 - w) * m.confidence + w * ctx_score
            ranked.append(RankedMatch(
                pattern=m.pattern,
                base_confidence=m.confidence,
                context_score=ctx_score,
                final_score=final,
                start_offset=m.start_offset,
                end_offset=m.end_offset,
                matched_bytes=m.matched_bytes,
                reason=reason,
            ))
        return ranked

    def _disambiguate(self, ranked: list[RankedMatch]) -> list[RankedMatch]:
        """Remove lower-ranked duplicates from collision groups.

        When two RankedMatches come from patterns that share a signature,
        keep only the one with the higher final_score; attach the loser
        as an ``alternative``.
        """
        # Build pattern_id → collision-group-key lookup
        pid_to_group: dict[str, str] = {}
        for sig, ids in self._collisions.items():
            for pid in ids:
                pid_to_group[pid] = sig

        # Group ranked matches by collision key (or unique-per-match)
        groups: dict[str, list[RankedMatch]] = {}
        ungrouped: list[RankedMatch] = []
        for rm in ranked:
            gkey = pid_to_group.get(rm.pattern.pattern_id)
            if gkey is not None:
                groups.setdefault(gkey, []).append(rm)
            else:
                ungrouped.append(rm)

        result: list[RankedMatch] = list(ungrouped)
        for _gkey, members in groups.items():
            members.sort(key=lambda r: r.final_score, reverse=True)
            winner = members[0]
            winner.alternatives = members[1:]
            result.append(winner)

        return result
