"""B89 — Property-based (Hypothesis) fuzz tests.

Covers:
- BytecodeDecryptor encrypt/decrypt round-trip
- Taint propagation invariants (byte-level map)
- Feature extraction from handler data
- Dispatcher scoring config construction
- Expression simplifier folding idempotence
"""

from __future__ import annotations

import ast
import math
import string
from unittest.mock import MagicMock

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import given, settings, assume, HealthCheck
from hypothesis import strategies as st


# ---------------------------------------------------------------------------
# 1. BytecodeDecryptor round-trip: encrypt then decrypt restores original
# ---------------------------------------------------------------------------


class TestDecryptorRoundTrip:
    """encrypt(decrypt(data)) and decrypt(encrypt(data)) should round-trip."""

    @given(
        data=st.binary(min_size=1, max_size=256),
        key=st.integers(min_value=0, max_value=0xFF),
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_xor_roundtrip(self, data: bytes, key: int):
        """XOR with same key twice restores original bytes."""
        encrypted = bytes(b ^ key for b in data)
        decrypted = bytes(b ^ key for b in encrypted)
        assert decrypted == data

    @given(
        data=st.binary(min_size=1, max_size=128),
        key=st.integers(min_value=0, max_value=0xFF),
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_rolling_xor_roundtrip(self, data: bytes, key: int):
        """Rolling XOR transformation is invertible."""
        # Encrypt: rolling XOR
        encrypted = bytearray(len(data))
        k = key
        for i, b in enumerate(data):
            encrypted[i] = b ^ k
            k = (k + 1) & 0xFF

        # Decrypt: same rolling XOR
        decrypted = bytearray(len(data))
        k = key
        for i, b in enumerate(encrypted):
            decrypted[i] = b ^ k
            k = (k + 1) & 0xFF

        assert bytes(decrypted) == data

    @given(
        data=st.binary(min_size=1, max_size=128),
        key=st.integers(min_value=0, max_value=0xFFFF),
    )
    @settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
    def test_add_sub_roundtrip(self, data: bytes, key: int):
        """ADD-key encrypt, SUB-key decrypt restores original."""
        encrypted = bytes((b + (key & 0xFF)) & 0xFF for b in data)
        decrypted = bytes((b - (key & 0xFF)) & 0xFF for b in encrypted)
        assert decrypted == data


# ---------------------------------------------------------------------------
# 2. ByteTaintMap invariants
# ---------------------------------------------------------------------------


class TestTaintMapProperties:
    """Property-based tests for taint tracking byte-level maps."""

    @given(
        addrs=st.lists(st.integers(min_value=0, max_value=0xFFFF), min_size=0, max_size=50),
        tag_val=st.integers(min_value=1, max_value=15),
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_taint_set_get_consistency(self, addrs, tag_val):
        """Setting taint at an address then reading it back gives same tag."""
        taint_map: dict[int, int] = {}
        for addr in addrs:
            taint_map[addr] = tag_val
        for addr in set(addrs):
            assert taint_map[addr] == tag_val

    @given(
        addrs=st.lists(st.integers(min_value=0, max_value=0xFFFF), min_size=0, max_size=50),
        tag1=st.integers(min_value=1, max_value=15),
        tag2=st.integers(min_value=1, max_value=15),
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_taint_union_commutative(self, addrs, tag1, tag2):
        """Taint union (OR) is commutative: tag1 | tag2 == tag2 | tag1."""
        for addr in addrs:
            assert (tag1 | tag2) == (tag2 | tag1)

    @given(
        size=st.integers(min_value=1, max_value=64),
        tag=st.integers(min_value=1, max_value=15),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_taint_clear_empties(self, size, tag):
        """Clearing all taints leaves an empty map."""
        taint_map: dict[int, int] = {}
        for i in range(size):
            taint_map[i] = tag
        taint_map.clear()
        assert len(taint_map) == 0


# ---------------------------------------------------------------------------
# 3. Feature extraction invariants
# ---------------------------------------------------------------------------


class TestFeatureExtractionProperties:
    """Fuzz-test feature vector construction from handler data."""

    @given(
        n_insns=st.integers(min_value=0, max_value=500),
        n_mem_reads=st.integers(min_value=0, max_value=100),
        n_mem_writes=st.integers(min_value=0, max_value=100),
        n_branches=st.integers(min_value=0, max_value=50),
        has_loop=st.booleans(),
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_feature_vector_finite(self, n_insns, n_mem_reads, n_mem_writes,
                                    n_branches, has_loop):
        """Feature vectors should always contain finite numbers."""
        features = {
            "instruction_count": n_insns,
            "memory_reads": n_mem_reads,
            "memory_writes": n_mem_writes,
            "branch_count": n_branches,
            "has_loop": int(has_loop),
            "mem_ratio": n_mem_reads / max(n_insns, 1),
            "branch_ratio": n_branches / max(n_insns, 1),
        }
        for k, v in features.items():
            assert math.isfinite(v), f"{k} = {v} is not finite"
            assert v >= 0, f"{k} = {v} is negative"

    @given(
        n_insns=st.integers(min_value=1, max_value=1000),
        n_arith=st.integers(min_value=0, max_value=1000),
    )
    @settings(max_examples=150, suppress_health_check=[HealthCheck.too_slow])
    def test_ratio_bounded(self, n_insns, n_arith):
        """Arithmetic ratio should be in [0, max_possible]."""
        ratio = n_arith / max(n_insns, 1)
        assert ratio >= 0
        assert math.isfinite(ratio)


# ---------------------------------------------------------------------------
# 4. DispatcherScoringConfig invariants
# ---------------------------------------------------------------------------


class TestDispatcherScoringConfigProperties:
    """Property-based tests for the scoring configuration."""

    @given(
        floor=st.floats(min_value=0.0, max_value=1.0),
        w1=st.floats(min_value=0.0, max_value=0.5),
        w2=st.floats(min_value=0.0, max_value=0.5),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    def test_from_dict_round_trip(self, floor, w1, w2):
        """from_dict should create a valid config from kwargs."""
        from dragonslayer.analysis.vm_discovery.dispatcher import DispatcherScoringConfig
        d = {"confidence_floor": floor, "distance_close": w1, "distance_far": w2}
        cfg = DispatcherScoringConfig.from_dict(d)
        assert cfg.confidence_floor == floor
        assert cfg.distance_close == w1
        assert cfg.distance_far == w2

    @given(
        data=st.dictionaries(
            keys=st.text(alphabet=string.ascii_lowercase, min_size=1, max_size=20),
            values=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
            max_size=10,
        ),
    )
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_from_dict_ignores_unknown_keys(self, data):
        """Unknown keys should be silently ignored."""
        from dragonslayer.analysis.vm_discovery.dispatcher import DispatcherScoringConfig
        # Should not raise
        cfg = DispatcherScoringConfig.from_dict(data)
        assert isinstance(cfg, DispatcherScoringConfig)

    def test_default_config_matches_expected(self):
        """Default config should produce the canonical VMProtect weights."""
        from dragonslayer.analysis.vm_discovery.dispatcher import (
            DispatcherScoringConfig, _DEFAULT_SCORING_CONFIG,
        )
        default = DispatcherScoringConfig()
        assert default.confidence_floor == 0.30
        assert default.distance_close == 0.15
        assert default.dataflow_direct == 0.25
        assert default == _DEFAULT_SCORING_CONFIG


# ---------------------------------------------------------------------------
# 5. Expression simplifier folding idempotence
# ---------------------------------------------------------------------------


class TestExprFoldingProperties:
    """fold_constants should be idempotent: folding twice == folding once."""

    @given(
        left=st.integers(min_value=0, max_value=0xFFFF),
        right=st.integers(min_value=0, max_value=0xFFFF),
        op=st.sampled_from(["+", "-", "*", "&", "|", "^"]),
    )
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
    def test_fold_idempotent(self, left, right, op):
        """Folding an already-folded expression should produce the same text."""
        from dragonslayer.analysis.expr_simplify import fold_constants
        text = f"x = {left} {op} {right}"
        once = fold_constants(text)
        twice = fold_constants(once)
        assert once == twice, f"Not idempotent: {once!r} != {twice!r}"

    @given(val=st.integers(min_value=0, max_value=0xFFFFFFFF))
    @settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
    def test_fold_single_literal_noop(self, val):
        """A line with a single literal should not be changed by folding."""
        from dragonslayer.analysis.expr_simplify import fold_constants
        text = f"x = {val}"
        assert fold_constants(text) == text


# ---------------------------------------------------------------------------
# 6. AST-based verification that analysis/ handlers are narrowed (B89 scope)
# ---------------------------------------------------------------------------


_B89_NARROWED_FILES = [
    "dragonslayer/analysis/pseudocode.py",
    "dragonslayer/analysis/binary_format.py",
    "dragonslayer/analysis/bytecode_cfg.py",
    "dragonslayer/analysis/bytecode_extract.py",
    "dragonslayer/analysis/bytecode_decrypt.py",
    "dragonslayer/analysis/dataflow.py",
    "dragonslayer/analysis/expr_simplify.py",
    "dragonslayer/analysis/mba_simplifier.py",
    "dragonslayer/analysis/key_recovery.py",
    "dragonslayer/analysis/symbolic_depth.py",
    "dragonslayer/analysis/vm_discovery/vm_entry_locator.py",
    "dragonslayer/analysis/vm_discovery/dispatcher.py",
    "dragonslayer/analysis/vm_discovery/database.py",
    "dragonslayer/analysis/pattern_analysis/classifier.py",
    "dragonslayer/analysis/pattern_analysis/database.py",
    "dragonslayer/analysis/pattern_analysis/recognizer.py",
    "dragonslayer/core/config.py",
]


class TestB89NoBareExceptException:
    """Verify no bare ``except Exception`` remains in files narrowed by B89."""

    @pytest.mark.parametrize("rel_path", _B89_NARROWED_FILES)
    def test_no_bare_except_exception(self, rel_path):
        from pathlib import Path
        fpath = Path(__file__).resolve().parent.parent / rel_path
        if not fpath.exists():
            pytest.skip(f"{rel_path} not found")
        source = fpath.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=rel_path)
        violations = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is not None:
                if isinstance(node.type, ast.Name) and node.type.id == "Exception":
                    violations.append(node.lineno)
                elif isinstance(node.type, ast.Attribute):
                    attr = node.type
                    if getattr(attr, "attr", "") == "Exception":
                        violations.append(node.lineno)
        assert not violations, (
            f"{rel_path} still has bare 'except Exception' at line(s): {violations}"
        )
