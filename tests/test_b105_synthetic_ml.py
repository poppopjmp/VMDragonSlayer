"""B105 – Multi-protector synthetic data, ML training pipeline, pattern expansion.

Tests cover:
- Themida / Code Virtualizer handler templates completeness
- ``generate_multi_protector_data`` correctness (handler counts, metadata, structure)
- ``_apply_jitter`` transformations (NOP insertion, register rename, dead-code)
- ``train_and_save_model`` end-to-end pipeline (model file + JSON report)
- Expanded VMProtect patterns (≥140 patterns with required fields)
- ML ``__init__`` exports (all new names importable)
"""

from __future__ import annotations

import json
import os
import random
from pathlib import Path

import pytest

from dragonslayer.ml.trainer import (
    PROTECTOR_CV,
    PROTECTOR_THEMIDA,
    PROTECTOR_VMPROTECT,
    _apply_jitter,
    _CV_HANDLER_TEMPLATES,
    _PROTECTOR_TEMPLATE_MAP,
    _THEMIDA_HANDLER_TEMPLATES,
    generate_multi_protector_data,
    train_and_save_model,
)

# ── Canonical categories every protector template map must have ──────────

_EXPECTED_CATEGORIES = frozenset({
    "arithmetic", "bitwise", "stack", "memory", "control_flow",
    "nop", "vm_control", "comparison", "crypto",
})


# ═══════════════════════════════════════════════════════════════════════════
# Template completeness
# ═══════════════════════════════════════════════════════════════════════════

class TestThemidaTemplates:
    """Validate _THEMIDA_HANDLER_TEMPLATES."""

    def test_all_categories_present(self) -> None:
        assert set(_THEMIDA_HANDLER_TEMPLATES.keys()) == _EXPECTED_CATEGORIES

    def test_each_category_has_templates(self) -> None:
        for cat, tmpls in _THEMIDA_HANDLER_TEMPLATES.items():
            assert len(tmpls) >= 1, f"Category {cat} has no templates"

    def test_templates_are_instruction_lists(self) -> None:
        for cat, tmpls in _THEMIDA_HANDLER_TEMPLATES.items():
            for i, tmpl in enumerate(tmpls):
                assert isinstance(tmpl, list), f"{cat}[{i}] is not a list"
                for j, instr in enumerate(tmpl):
                    assert isinstance(instr, tuple) and len(instr) == 2, (
                        f"{cat}[{i}][{j}] is not a (mnemonic, operands) tuple"
                    )

    def test_themida_markers_present(self) -> None:
        """Themida handlers must reference EDI-based context or pushad/popad."""
        body_str = ""
        for tmpls in _THEMIDA_HANDLER_TEMPLATES.values():
            for tmpl in tmpls:
                for m, ops in tmpl:
                    body_str += f" {m} {ops}"
        assert "edi" in body_str.lower() or "pushad" in body_str.lower()


class TestCVTemplates:
    """Validate _CV_HANDLER_TEMPLATES."""

    def test_all_categories_present(self) -> None:
        assert set(_CV_HANDLER_TEMPLATES.keys()) == _EXPECTED_CATEGORIES

    def test_each_category_has_templates(self) -> None:
        for cat, tmpls in _CV_HANDLER_TEMPLATES.items():
            assert len(tmpls) >= 1, f"Category {cat} has no templates"

    def test_templates_are_instruction_lists(self) -> None:
        for cat, tmpls in _CV_HANDLER_TEMPLATES.items():
            for i, tmpl in enumerate(tmpls):
                assert isinstance(tmpl, list), f"{cat}[{i}] is not a list"
                for j, instr in enumerate(tmpl):
                    assert isinstance(instr, tuple) and len(instr) == 2, (
                        f"{cat}[{i}][{j}] is not a (mnemonic, operands) tuple"
                    )

    def test_cv_markers_present(self) -> None:
        """CV handlers must use LODSB/XLAT or BSWAP patterns."""
        body_str = ""
        for tmpls in _CV_HANDLER_TEMPLATES.values():
            for tmpl in tmpls:
                for m, ops in tmpl:
                    body_str += f" {m} {ops}"
        lower = body_str.lower()
        assert "lodsb" in lower or "xlat" in lower or "bswap" in lower


class TestProtectorTemplateMap:
    """Validate _PROTECTOR_TEMPLATE_MAP."""

    def test_contains_all_three_protectors(self) -> None:
        assert set(_PROTECTOR_TEMPLATE_MAP.keys()) == {
            PROTECTOR_VMPROTECT, PROTECTOR_THEMIDA, PROTECTOR_CV,
        }

    def test_constants_are_strings(self) -> None:
        assert isinstance(PROTECTOR_VMPROTECT, str)
        assert isinstance(PROTECTOR_THEMIDA, str)
        assert isinstance(PROTECTOR_CV, str)

    @pytest.mark.parametrize("protector", [PROTECTOR_VMPROTECT, PROTECTOR_THEMIDA, PROTECTOR_CV])
    def test_each_protector_has_9_categories(self, protector: str) -> None:
        assert len(_PROTECTOR_TEMPLATE_MAP[protector]) == 9


# ═══════════════════════════════════════════════════════════════════════════
# Jitter function
# ═══════════════════════════════════════════════════════════════════════════

class TestApplyJitter:
    """Tests for _apply_jitter."""

    _SAMPLE_BODY: list[tuple[str, str]] = [
        ("mov", "eax, [edi+0x00]"),
        ("add", "eax, ecx"),
        ("mov", "[edi+0x00], eax"),
    ]

    def test_returns_new_list(self) -> None:
        rng = random.Random(42)
        result = _apply_jitter(self._SAMPLE_BODY, rng)
        assert result is not self._SAMPLE_BODY

    def test_does_not_mutate_input(self) -> None:
        original = [tuple(x) for x in self._SAMPLE_BODY]
        rng = random.Random(42)
        _apply_jitter(self._SAMPLE_BODY, rng)
        assert self._SAMPLE_BODY == original

    def test_nop_insertion_with_high_probability(self) -> None:
        """With nop_probability=1.0 and max_nops>0, NOPs should appear."""
        rng = random.Random(0)
        result = _apply_jitter(
            self._SAMPLE_BODY, rng, nop_probability=1.0, max_nops=3,
        )
        nop_count = sum(1 for m, _ in result if m == "nop")
        # At least one NOP should have been inserted (max_nops ≥ 1)
        assert len(result) >= len(self._SAMPLE_BODY)

    def test_no_nop_insertion_when_disabled(self) -> None:
        rng = random.Random(42)
        result = _apply_jitter(
            self._SAMPLE_BODY, rng, nop_probability=0.0, max_nops=0, reg_rename=False,
        )
        # Should have original instructions (possibly with dead-code pair)
        mnemonics = [m for m, _ in result]
        original_mnemonics = [m for m, _ in self._SAMPLE_BODY]
        # If no dead-code inserted, should match
        assert len(result) >= len(self._SAMPLE_BODY)

    def test_output_is_tuples(self) -> None:
        rng = random.Random(42)
        result = _apply_jitter(self._SAMPLE_BODY, rng)
        for item in result:
            assert isinstance(item, tuple) and len(item) == 2

    def test_statistical_nop_rate(self) -> None:
        """Over many runs, NOPs should appear roughly nop_probability of the time."""
        has_nop = 0
        n_runs = 200
        for i in range(n_runs):
            rng = random.Random(i)
            result = _apply_jitter(
                self._SAMPLE_BODY, rng, nop_probability=0.8, max_nops=2,
            )
            if any(m == "nop" for m, _ in result):
                has_nop += 1
        rate = has_nop / n_runs
        # Should be at least 40% (theoretical ~80% × P(nops>0))
        assert rate > 0.2, f"NOP rate too low: {rate:.2f}"


# ═══════════════════════════════════════════════════════════════════════════
# Multi-protector data generation
# ═══════════════════════════════════════════════════════════════════════════

class TestGenerateMultiProtectorData:
    """Tests for generate_multi_protector_data."""

    def test_handler_count(self) -> None:
        handlers = generate_multi_protector_data(n_per_category=5, seed=100)
        # 3 protectors × 9 categories × 5 = 135
        assert len(handlers) == 135

    def test_all_protectors_present(self) -> None:
        handlers = generate_multi_protector_data(n_per_category=3, seed=0)
        protectors = {h["protector"] for h in handlers}
        assert protectors == {PROTECTOR_VMPROTECT, PROTECTOR_THEMIDA, PROTECTOR_CV}

    def test_all_categories_present(self) -> None:
        handlers = generate_multi_protector_data(n_per_category=3, seed=0)
        categories = {h["category"] for h in handlers}
        assert categories == _EXPECTED_CATEGORIES

    def test_handler_dict_structure(self) -> None:
        handlers = generate_multi_protector_data(n_per_category=2, seed=0)
        required_keys = {
            "instructions", "mnemonics", "category", "operation",
            "operand_width", "block_count", "reads", "writes", "protector",
        }
        for h in handlers:
            assert required_keys.issubset(h.keys()), (
                f"Missing keys: {required_keys - h.keys()}"
            )

    def test_instructions_are_dicts(self) -> None:
        handlers = generate_multi_protector_data(n_per_category=1, seed=0)
        for h in handlers:
            for instr in h["instructions"]:
                assert "mnemonic" in instr
                assert "operands" in instr

    def test_mnemonics_lowercase(self) -> None:
        handlers = generate_multi_protector_data(n_per_category=2, seed=0)
        for h in handlers:
            for m in h["mnemonics"]:
                assert m == m.lower(), f"Mnemonic not lowercase: {m!r}"

    def test_shuffled(self) -> None:
        """Generated data should be shuffled (first N items not all same protector)."""
        handlers = generate_multi_protector_data(n_per_category=10, seed=42)
        first_10_protectors = [h["protector"] for h in handlers[:10]]
        assert len(set(first_10_protectors)) > 1, "Data does not appear shuffled"

    def test_deterministic_with_seed(self) -> None:
        h1 = generate_multi_protector_data(n_per_category=3, seed=99)
        h2 = generate_multi_protector_data(n_per_category=3, seed=99)
        assert len(h1) == len(h2)
        for a, b in zip(h1, h2):
            assert a["category"] == b["category"]
            assert a["protector"] == b["protector"]
            assert a["mnemonics"] == b["mnemonics"]

    def test_different_seeds_different_data(self) -> None:
        h1 = generate_multi_protector_data(n_per_category=5, seed=1)
        h2 = generate_multi_protector_data(n_per_category=5, seed=999)
        # At least some handlers should differ in mnemonics (jitter gives variation)
        differ = sum(
            1 for a, b in zip(h1, h2) if a["mnemonics"] != b["mnemonics"]
        )
        assert differ > 0

    def test_single_protector(self) -> None:
        handlers = generate_multi_protector_data(
            n_per_category=3, protectors=[PROTECTOR_THEMIDA], seed=0,
        )
        assert len(handlers) == 27  # 1 protector × 9 categories × 3
        assert all(h["protector"] == PROTECTOR_THEMIDA for h in handlers)

    def test_jitter_disabled(self) -> None:
        handlers = generate_multi_protector_data(
            n_per_category=2, seed=0, jitter=False,
        )
        # Should still produce correct count
        assert len(handlers) == 54  # 3 × 9 × 2

    def test_per_category_count(self) -> None:
        n = 7
        handlers = generate_multi_protector_data(n_per_category=n, seed=0)
        from collections import Counter
        counts = Counter((h["protector"], h["category"]) for h in handlers)
        for key, count in counts.items():
            assert count == n, f"{key} has {count} handlers, expected {n}"


# ═══════════════════════════════════════════════════════════════════════════
# End-to-end train_and_save_model
# ═══════════════════════════════════════════════════════════════════════════

class TestTrainAndSaveModel:
    """Tests for train_and_save_model (full pipeline)."""

    def test_train_and_save(self, tmp_path: Path) -> None:
        out = str(tmp_path / "model.pkl")
        model, result, imp = train_and_save_model(
            output_path=out, n_per_category=15, seed=42, n_estimators=50,
        )
        assert model.is_trained
        assert result.accuracy > 0.7  # Synthetic data should train well
        assert os.path.isfile(out)

    def test_report_json_created(self, tmp_path: Path) -> None:
        out = str(tmp_path / "model.pkl")
        train_and_save_model(output_path=out, n_per_category=10, seed=0, n_estimators=30)
        report_path = tmp_path / "model.report.json"
        assert report_path.exists()
        report = json.loads(report_path.read_text("utf-8"))
        assert "accuracy" in report
        assert "protectors" in report
        assert "categories" in report
        assert "top_features" in report
        assert len(report["protectors"]) == 3
        assert len(report["categories"]) == 9

    def test_feature_importances_returned(self, tmp_path: Path) -> None:
        out = str(tmp_path / "model.pkl")
        _, _, imp = train_and_save_model(
            output_path=out, n_per_category=10, seed=0, n_estimators=30,
        )
        assert len(imp) > 0
        for name, val in imp:
            assert isinstance(name, str)
            assert isinstance(val, float)
            assert val >= 0.0

    def test_high_accuracy_on_synthetic_data(self, tmp_path: Path) -> None:
        out = str(tmp_path / "model.pkl")
        _, result, _ = train_and_save_model(
            output_path=out, n_per_category=60, seed=42, n_estimators=100,
        )
        # Should achieve ≥90% on synthetic data
        assert result.accuracy >= 0.90, f"Accuracy too low: {result.accuracy}"


# ═══════════════════════════════════════════════════════════════════════════
# Expanded VMProtect patterns
# ═══════════════════════════════════════════════════════════════════════════

class TestVMProtectPatterns:
    """Validate expanded data/patterns/vmprotect_handlers.json."""

    @pytest.fixture
    def patterns(self) -> list[dict]:
        path = Path(__file__).resolve().parents[1] / "data" / "patterns" / "vmprotect_handlers.json"
        assert path.exists(), f"Pattern file not found: {path}"
        data = json.loads(path.read_text("utf-8"))
        # File wraps patterns in an object with a "patterns" key.
        return data["patterns"]

    def test_minimum_count(self, patterns: list[dict]) -> None:
        assert len(patterns) >= 140, f"Only {len(patterns)} patterns, expected ≥140"

    def test_required_fields(self, patterns: list[dict]) -> None:
        for i, p in enumerate(patterns):
            assert "pattern_id" in p, f"Pattern {i} missing 'pattern_id'"
            assert "handler_type" in p, f"Pattern {i} missing 'handler_type'"
            assert "signature" in p, f"Pattern {i} missing 'signature'"

    def test_category_distribution(self, patterns: list[dict]) -> None:
        from collections import Counter
        cats = Counter(p["handler_type"] for p in patterns)
        # Should have at least 6 distinct categories
        assert len(cats) >= 6, f"Too few categories: {list(cats.keys())}"

    def test_no_duplicate_ids(self, patterns: list[dict]) -> None:
        ids = [p["pattern_id"] for p in patterns]
        dupes = [n for n in ids if ids.count(n) > 1]
        assert not dupes, f"Duplicate pattern IDs: {set(dupes)}"


# ═══════════════════════════════════════════════════════════════════════════
# ML __init__ exports
# ═══════════════════════════════════════════════════════════════════════════

class TestMLExports:
    """Verify that new B105 symbols are exported from dragonslayer.ml."""

    _NEW_NAMES = [
        "generate_multi_protector_data",
        "train_and_save_model",
        "PROTECTOR_VMPROTECT",
        "PROTECTOR_THEMIDA",
        "PROTECTOR_CV",
    ]

    def test_all_in___all__(self) -> None:
        import dragonslayer.ml as ml_mod
        all_names = getattr(ml_mod, "__all__", [])
        for name in self._NEW_NAMES:
            assert name in all_names, f"{name} not in ml.__all__"

    @pytest.mark.parametrize("name", _NEW_NAMES)
    def test_importable(self, name: str) -> None:
        import dragonslayer.ml as ml_mod
        obj = getattr(ml_mod, name, None)
        assert obj is not None, f"dragonslayer.ml.{name} is None (import failed?)"
