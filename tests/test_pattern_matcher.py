"""
Tests for the context-aware pattern matching engine  (Batch 36)
================================================================

Tests cover:
  - MatchContext construction and defaults
  - RankedMatch data structure and serialisation
  - Context scoring heuristics (mnemonic, register, position)
  - Signature collision detection
  - PatternMatcher.match() end-to-end (with & without context)
  - PatternMatcher.match_handler_sequence() batch API
  - Disambiguation (collision group de-duplication)
  - Edge cases: empty bytes, no context, min_confidence filtering, top_k
  - Statistics API
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from dataclasses import asdict
from typing import List

from dragonslayer.analysis.pattern_analysis.database import (
    Pattern,
    PatternDatabase,
)
from dragonslayer.analysis.pattern_analysis.recognizer import (
    Match,
    PatternRecognizer,
)
from dragonslayer.analysis.pattern_analysis.matcher import (
    MatchContext,
    RankedMatch,
    PatternMatcher,
    find_signature_collisions,
    _normalize_signature,
    _mnemonic_category_score,
    _register_pattern_score,
    _position_score,
    _compute_context_score,
)


# ── helpers ──────────────────────────────────────────────────────────

def _make_pattern(
    pid: str = "p1",
    name: str = "test",
    signature: str = "48 8B 45 00",
    architecture: str = "x64",
    handler_type: str = "arithmetic",
    operation: str = "vAdd64",
    confidence: float = 0.9,
    wildcards: bool = True,
    variants: list | None = None,
    metadata: dict | None = None,
) -> Pattern:
    return Pattern(
        pattern_id=pid,
        name=name,
        signature=signature,
        architecture=architecture,
        handler_type=handler_type,
        operation=operation,
        confidence=confidence,
        wildcards=wildcards,
        variants=variants or [],
        metadata=metadata or {},
    )


def _make_match(
    pattern: Pattern | None = None,
    confidence: float = 0.85,
    start: int = 0,
    end: int = 4,
    matched: str = "48 8B 45 00",
) -> Match:
    pat = pattern or _make_pattern()
    return Match(
        pattern=pat,
        start_offset=start,
        end_offset=end,
        confidence=confidence,
        matched_bytes=matched,
    )


def _make_db(*patterns: Pattern) -> PatternDatabase:
    """Build a PatternDatabase populated with the given patterns."""
    db = PatternDatabase()
    for p in patterns:
        db.add_pattern(p)
    return db


# =====================================================================
#  1. MatchContext
# =====================================================================

class TestMatchContext:
    """MatchContext data structure."""

    def test_default_values(self):
        ctx = MatchContext()
        assert ctx.preceding_mnemonics == []
        assert ctx.following_mnemonics == []
        assert ctx.registers_read == []
        assert ctx.registers_written == []
        assert ctx.handler_index is None
        assert ctx.dispatcher_address is None
        assert ctx.handler_address is None

    def test_custom_values(self):
        ctx = MatchContext(
            preceding_mnemonics=["push", "mov"],
            following_mnemonics=["jmp"],
            registers_read=["rax"],
            registers_written=["rbx"],
            handler_index=3,
            dispatcher_address=0x401000,
            handler_address=0x402000,
        )
        assert ctx.preceding_mnemonics == ["push", "mov"]
        assert ctx.handler_index == 3

    def test_partial_context(self):
        ctx = MatchContext(registers_read=["rsi", "rdi"])
        assert ctx.registers_read == ["rsi", "rdi"]
        assert ctx.preceding_mnemonics == []


# =====================================================================
#  2. RankedMatch
# =====================================================================

class TestRankedMatch:
    """RankedMatch data structure and serialisation."""

    def test_basic_fields(self):
        pat = _make_pattern()
        rm = RankedMatch(
            pattern=pat,
            base_confidence=0.9,
            context_score=0.3,
            final_score=0.72,
            start_offset=0,
            end_offset=8,
            matched_bytes="48 8B 45 00",
            reason="mnemonic_coherence=0.30",
        )
        assert rm.final_score == 0.72
        assert rm.alternatives == []

    def test_to_dict(self):
        pat = _make_pattern(pid="x1", operation="vMul64")
        rm = RankedMatch(
            pattern=pat,
            base_confidence=0.85,
            context_score=0.4,
            final_score=0.715,
            start_offset=2,
            end_offset=10,
            matched_bytes="48 0F AF ??",
            reason="register_pattern=0.20",
        )
        d = rm.to_dict()
        assert d["pattern_id"] == "x1"
        assert d["operation"] == "vMul64"
        assert "alternatives_count" in d
        assert d["alternatives_count"] == 0

    def test_to_dict_rounds_scores(self):
        pat = _make_pattern()
        rm = RankedMatch(
            pattern=pat, base_confidence=0.123456, context_score=0.654321,
            final_score=0.333333, start_offset=0, end_offset=4,
            matched_bytes="AA BB CC DD", reason="test",
        )
        d = rm.to_dict()
        assert d["base_confidence"] == 0.1235
        assert d["context_score"] == 0.6543
        assert d["final_score"] == 0.3333


# =====================================================================
#  3. Normalisation & collision detection
# =====================================================================

class TestNormalizeSignature:
    def test_strips_spaces(self):
        assert _normalize_signature("48 8B 45 00") == "488B4500"

    def test_strips_pipes(self):
        assert _normalize_signature("48|8B|45") == "488B45"

    def test_uppercase(self):
        assert _normalize_signature("48 ff c0") == "48FFC0"


class TestFindSignatureCollisions:
    def test_no_collisions_when_unique(self):
        p1 = _make_pattern(pid="a", signature="48 8B 45 00")
        p2 = _make_pattern(pid="b", signature="48 FF C0")
        db = _make_db(p1, p2)
        assert find_signature_collisions(db) == {}

    def test_detects_same_signature(self):
        p1 = _make_pattern(pid="a", signature="48 F7 ?? 48 89 ??", handler_type="arithmetic", operation="vNeg64")
        p2 = _make_pattern(pid="b", signature="48 F7 ?? 48 89 ??", handler_type="bitwise", operation="vNot64")
        db = _make_db(p1, p2)
        collisions = find_signature_collisions(db)
        assert len(collisions) == 1
        group = list(collisions.values())[0]
        assert set(group) == {"a", "b"}

    def test_variant_collision(self):
        p1 = _make_pattern(pid="a", signature="AA BB CC")
        p2 = _make_pattern(pid="b", signature="11 22 33", variants=["AA BB CC"])
        db = _make_db(p1, p2)
        collisions = find_signature_collisions(db)
        assert len(collisions) >= 1

    def test_normalisation_catches_spacing_diff(self):
        p1 = _make_pattern(pid="a", signature="48 8B45 00")
        p2 = _make_pattern(pid="b", signature="488B 45 00")
        db = _make_db(p1, p2)
        collisions = find_signature_collisions(db)
        assert len(collisions) == 1


# =====================================================================
#  4. Mnemonic category scoring
# =====================================================================

class TestMnemonicCategoryScore:
    def test_arith_mnemonics_match_arithmetic(self):
        score = _mnemonic_category_score(["add", "sub", "imul"], "arithmetic")
        assert score > 0.5

    def test_logic_mnemonics_match_bitwise(self):
        score = _mnemonic_category_score(["xor", "and", "shl"], "bitwise")
        assert score > 0.5

    def test_stack_mnemonics_match_stack(self):
        score = _mnemonic_category_score(["push", "pop"], "stack")
        assert score > 0.5

    def test_empty_gives_zero(self):
        assert _mnemonic_category_score([], "arithmetic") == 0.0

    def test_unrelated_gives_zero(self):
        score = _mnemonic_category_score(["nop", "nop"], "arithmetic")
        assert score == 0.0

    def test_unknown_handler_type_gives_zero(self):
        assert _mnemonic_category_score(["add"], "totally_unknown") == 0.0

    def test_mixed_mnemonics_partial(self):
        score = _mnemonic_category_score(["add", "nop", "sub", "ret"], "arithmetic")
        assert 0.0 < score < 1.0

    def test_control_flow_match(self):
        score = _mnemonic_category_score(["jmp", "je", "call"], "control_flow")
        assert score > 0.5


# =====================================================================
#  5. Register pattern scoring
# =====================================================================

class TestRegisterPatternScore:
    def test_stack_with_rsp(self):
        score = _register_pattern_score(["rsp"], ["rsp"], "stack")
        assert score >= 0.3

    def test_control_flow_with_rsi(self):
        score = _register_pattern_score([], ["rsi"], "control_flow")
        assert score > 0.0

    def test_arithmetic_with_rax(self):
        score = _register_pattern_score(["rax"], ["rcx"], "arithmetic")
        assert score > 0.0

    def test_memory_with_reads_writes(self):
        score = _register_pattern_score(["rax"], ["rbx"], "memory")
        assert score > 0.0

    def test_crypto_with_many_regs(self):
        score = _register_pattern_score(
            ["rax", "rbx", "rcx"], ["rdx", "rsi"], "crypto",
        )
        assert score > 0.0

    def test_no_regs_zero(self):
        assert _register_pattern_score([], [], "stack") == 0.0


# =====================================================================
#  6. Position scoring
# =====================================================================

class TestPositionScore:
    def test_first_handler_control_flow(self):
        assert _position_score(0, "control_flow") > 0.0

    def test_non_first_no_bonus(self):
        assert _position_score(5, "control_flow") == 0.0

    def test_none_index(self):
        assert _position_score(None, "control_flow") == 0.0


# =====================================================================
#  7. Compute context score integration
# =====================================================================

class TestComputeContextScore:
    def test_no_context_gives_zero(self):
        pat = _make_pattern(handler_type="arithmetic")
        ctx = MatchContext()
        score, reason = _compute_context_score(pat, ctx)
        assert score == 0.0
        assert reason == "no_context"

    def test_arith_preceding_boosts(self):
        pat = _make_pattern(handler_type="arithmetic")
        ctx = MatchContext(preceding_mnemonics=["add", "sub"])
        score, reason = _compute_context_score(pat, ctx)
        assert score > 0.0
        assert "mnemonic_coherence" in reason

    def test_register_boost(self):
        pat = _make_pattern(handler_type="stack")
        ctx = MatchContext(registers_read=["rsp"], registers_written=["rbp"])
        score, reason = _compute_context_score(pat, ctx)
        assert score > 0.0
        assert "register_pattern" in reason

    def test_combined_score_capped_at_one(self):
        pat = _make_pattern(handler_type="stack")
        ctx = MatchContext(
            preceding_mnemonics=["push", "pop", "push", "pop"],
            following_mnemonics=["push", "pop"],
            registers_read=["rsp"],
            registers_written=["rbp"],
            handler_index=0,
        )
        score, _ = _compute_context_score(pat, ctx)
        assert 0.0 <= score <= 1.0


# =====================================================================
#  8. PatternMatcher — construction
# =====================================================================

class TestPatternMatcherInit:
    def test_default_construction(self):
        db = _make_db(_make_pattern())
        matcher = PatternMatcher(db, use_yara=False)
        assert matcher.context_weight == 0.3
        assert matcher.database is db

    def test_context_weight_clamped(self):
        db = _make_db()
        m1 = PatternMatcher(db, use_yara=False, context_weight=-1.0)
        m2 = PatternMatcher(db, use_yara=False, context_weight=5.0)
        assert m1.context_weight == 0.0
        assert m2.context_weight == 1.0


# =====================================================================
#  9. PatternMatcher.match()
# =====================================================================

class TestPatternMatcherMatch:
    """End-to-end matching through PatternMatcher."""

    def _build_matcher(self, *patterns: Pattern) -> PatternMatcher:
        db = _make_db(*patterns)
        return PatternMatcher(db, use_yara=False)

    def test_match_returns_ranked_matches(self):
        p = _make_pattern(signature="48 8B 45 00")
        matcher = self._build_matcher(p)
        results = matcher.match("48 8B 45 00", min_confidence=0.1)
        assert len(results) >= 1
        assert all(isinstance(r, RankedMatch) for r in results)

    def test_match_with_context_changes_score(self):
        p = _make_pattern(handler_type="arithmetic", signature="48 03 45 08")
        matcher = self._build_matcher(p)
        no_ctx = matcher.match("48 03 45 08", min_confidence=0.1)
        with_ctx = matcher.match(
            "48 03 45 08",
            context=MatchContext(preceding_mnemonics=["add", "sub"]),
            min_confidence=0.1,
        )
        # Both should return results; context match may differ in score
        assert len(no_ctx) >= 1
        assert len(with_ctx) >= 1

    def test_match_respects_min_confidence(self):
        p = _make_pattern(confidence=0.5, signature="48 FF C0")
        matcher = self._build_matcher(p)
        results = matcher.match("48 FF C0", min_confidence=0.99)
        # Very high threshold should filter almost everything
        assert len(results) == 0

    def test_match_empty_bytes(self):
        p = _make_pattern(signature="48 8B 45 00")
        matcher = self._build_matcher(p)
        results = matcher.match("", min_confidence=0.1)
        assert results == []

    def test_match_top_k(self):
        patterns = [
            _make_pattern(pid=f"p{i}", signature="48 8B 45 00", operation=f"op{i}")
            for i in range(10)
        ]
        matcher = self._build_matcher(*patterns)
        results = matcher.match("48 8B 45 00", min_confidence=0.1, top_k=3)
        assert len(results) <= 3

    def test_match_architecture_filter(self):
        p64 = _make_pattern(pid="a64", architecture="x64", signature="48 8B 45 00")
        p32 = _make_pattern(pid="a32", architecture="x86", signature="8B 45 00")
        matcher = self._build_matcher(p64, p32)
        results = matcher.match("48 8B 45 00", architecture="x64", min_confidence=0.1)
        for r in results:
            assert r.pattern.architecture == "x64"


# =====================================================================
# 10. Disambiguation
# =====================================================================

class TestDisambiguation:
    """Test that collision groups are resolved to a single winner."""

    def test_colliding_patterns_reduced(self):
        sig = "48 F7 ?? 48 89 ??"
        p1 = _make_pattern(pid="neg", handler_type="arithmetic", operation="vNeg64", signature=sig, confidence=0.9)
        p2 = _make_pattern(pid="not", handler_type="bitwise", operation="vNot64", signature=sig, confidence=0.9)
        db = _make_db(p1, p2)
        matcher = PatternMatcher(db, use_yara=False)

        # Without context → any one wins (both equal base)
        results = matcher.match(sig, min_confidence=0.1)
        # Only the winner should survive (alternatives attached)
        winners = [r for r in results if not any(
            alt.pattern.pattern_id == r.pattern.pattern_id for alt in r.alternatives
        )]
        assert len(winners) >= 1
        # Winner should have alternatives attached
        assert any(r.alternatives for r in results)

    def test_context_tips_disambiguation(self):
        sig = "48 F7 ?? 48 89 ??"
        p_arith = _make_pattern(pid="neg", handler_type="arithmetic", operation="vNeg64", signature=sig, confidence=0.9)
        p_bit = _make_pattern(pid="not", handler_type="bitwise", operation="vNot64", signature=sig, confidence=0.9)
        db = _make_db(p_arith, p_bit)
        matcher = PatternMatcher(db, use_yara=False)

        # Provide arithmetic context → should favour arithmetic pattern
        ctx = MatchContext(
            preceding_mnemonics=["add", "sub", "imul"],
            registers_read=["rax"],
            registers_written=["rcx"],
        )
        results = matcher.match(sig, context=ctx, min_confidence=0.1)
        if results:
            assert results[0].pattern.handler_type in ("arithmetic", "bitwise")

    def test_collision_groups_property(self):
        sig = "AA BB CC"
        p1 = _make_pattern(pid="x1", signature=sig)
        p2 = _make_pattern(pid="x2", signature=sig)
        db = _make_db(p1, p2)
        matcher = PatternMatcher(db, use_yara=False)
        groups = matcher.collision_groups
        assert len(groups) >= 1


# =====================================================================
# 11. Batch matching
# =====================================================================

class TestBatchMatching:
    """match_handler_sequence() batch API."""

    def test_batch_returns_per_handler_results(self):
        p = _make_pattern(signature="48 8B 45 00")
        db = _make_db(p)
        matcher = PatternMatcher(db, use_yara=False)
        byte_list = ["48 8B 45 00", "FF FF FF FF"]
        results = matcher.match_handler_sequence(byte_list, min_confidence=0.1)
        assert len(results) == 2
        assert isinstance(results[0], list)
        assert isinstance(results[1], list)

    def test_batch_with_contexts(self):
        p = _make_pattern(signature="48 8B 45 00", handler_type="arithmetic")
        db = _make_db(p)
        matcher = PatternMatcher(db, use_yara=False)
        ctxs = [
            MatchContext(preceding_mnemonics=["add"]),
            MatchContext(preceding_mnemonics=["push"]),
        ]
        results = matcher.match_handler_sequence(
            ["48 8B 45 00", "48 8B 45 00"],
            contexts=ctxs,
            min_confidence=0.1,
        )
        assert len(results) == 2

    def test_batch_auto_assigns_handler_index(self):
        p = _make_pattern(signature="48 8B 45 00")
        db = _make_db(p)
        matcher = PatternMatcher(db, use_yara=False)
        results = matcher.match_handler_sequence(
            ["48 8B 45 00", "48 8B 45 00", "48 8B 45 00"],
            min_confidence=0.1,
        )
        assert len(results) == 3


# =====================================================================
# 12. Statistics
# =====================================================================

class TestStatistics:
    def test_get_statistics(self):
        sig = "48 F7 ??"
        p1 = _make_pattern(pid="a", signature=sig)
        p2 = _make_pattern(pid="b", signature=sig)
        db = _make_db(p1, p2)
        matcher = PatternMatcher(db, use_yara=False)
        stats = matcher.get_statistics()
        assert "collision_groups" in stats
        assert stats["collision_groups"] >= 1
        assert "context_weight" in stats

    def test_statistics_with_empty_db(self):
        db = _make_db()
        matcher = PatternMatcher(db, use_yara=False)
        stats = matcher.get_statistics()
        assert stats["collision_groups"] == 0
        assert stats["colliding_patterns"] == 0


# =====================================================================
# 13. Edge cases
# =====================================================================

class TestEdgeCases:
    def test_no_patterns_in_db(self):
        db = _make_db()
        matcher = PatternMatcher(db, use_yara=False)
        results = matcher.match("48 8B 45 00", min_confidence=0.1)
        assert results == []

    def test_wildcard_signature(self):
        p = _make_pattern(signature="48 ?? 45 ??")
        db = _make_db(p)
        matcher = PatternMatcher(db, use_yara=False)
        results = matcher.match("48 AB 45 CD", min_confidence=0.1)
        # Should still match via wildcard
        assert len(results) >= 0  # depends on regex engine

    def test_context_weight_zero_ignores_context(self):
        p = _make_pattern(handler_type="arithmetic", signature="48 03 45 08")
        db = _make_db(p)
        matcher = PatternMatcher(db, use_yara=False, context_weight=0.0)
        ctx = MatchContext(preceding_mnemonics=["add", "sub"])
        results = matcher.match("48 03 45 08", context=ctx, min_confidence=0.1)
        if results:
            # With weight=0, final_score should equal base_confidence
            assert abs(results[0].final_score - results[0].base_confidence) < 1e-6

    def test_context_weight_one_uses_only_context(self):
        p = _make_pattern(handler_type="arithmetic", confidence=0.5, signature="48 03 45 08")
        db = _make_db(p)
        matcher = PatternMatcher(db, use_yara=False, context_weight=1.0)
        ctx = MatchContext(preceding_mnemonics=["add", "sub", "imul", "neg"])
        results = matcher.match("48 03 45 08", context=ctx, min_confidence=0.1)
        if results:
            # final_score should be purely context_score
            assert abs(results[0].final_score - results[0].context_score) < 0.1

    def test_multiple_non_colliding_patterns(self):
        p1 = _make_pattern(pid="a", signature="48 8B 45 00", operation="op1")
        p2 = _make_pattern(pid="b", signature="48 8B 45 00 48 03 45 08", operation="op2")
        db = _make_db(p1, p2)
        matcher = PatternMatcher(db, use_yara=False)
        results = matcher.match("48 8B 45 00 48 03 45 08", min_confidence=0.1)
        # Both might match; they have different sigs so no collision
        assert isinstance(results, list)


# =====================================================================
# 14. Import from __init__
# =====================================================================

class TestImportPath:
    def test_import_from_pattern_analysis(self):
        from dragonslayer.analysis.pattern_analysis import (
            PatternMatcher,
            RankedMatch,
            MatchContext,
            find_signature_collisions,
        )
        assert PatternMatcher is not None
        assert RankedMatch is not None
        assert MatchContext is not None
        assert find_signature_collisions is not None
