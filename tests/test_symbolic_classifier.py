"""
Tests for Symbolic-Summary Classification + Ensemble Wiring (Batch 39)
=======================================================================

Tests cover:
  1. SymbolicClassifierModel with various symbolic summaries
  2. Expression pattern matching (arithmetic, bitwise, shifts, memory)
  3. Stack/memory write detection
  4. Error/empty summary handling
  5. Ensemble integration (WeightedEnsemble with VMHandlerModel + SymbolicClassifierModel)
  6. Ensemble majority voting
  7. Import path verification
"""

from __future__ import annotations

import pytest
from typing import Any, Dict, List

from dragonslayer.ml.model import (
    PredictionResult,
    VMHandlerModel,
    SymbolicClassifierModel,
)
from dragonslayer.ml.ensemble import (
    EnsembleClassifier,
    WeightedEnsemble,
)


# ── Helpers ──────────────────────────────────────────────────────────

def _make_summary(
    *,
    simplified_registers: Dict[str, str] | None = None,
    input_symbols: Dict[str, str] | None = None,
    memory_writes: List[Dict[str, Any]] | None = None,
    error: str | None = None,
) -> Dict[str, Any]:
    """Build a mock symbolic execution summary dict."""
    s: Dict[str, Any] = {}
    if simplified_registers is not None:
        s["simplified_registers"] = simplified_registers
    if input_symbols is not None:
        s["input_symbols"] = input_symbols
    if memory_writes is not None:
        s["memory_writes"] = memory_writes
    if error is not None:
        s["error"] = error
    return s


# =====================================================================
#  1. SymbolicClassifierModel — arithmetic patterns
# =====================================================================

class TestSymbolicArithmetic:
    def test_add_two_registers(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "init_rax + init_rbx"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "arithmetic"
        assert result.confidence > 0.8

    def test_sub_registers(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "init_rcx - init_rdx"},
            input_symbols={"rax": "init_rax", "rcx": "init_rcx"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "arithmetic"

    def test_mul_registers(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "init_rax * init_rbx"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "arithmetic"

    def test_div_expression(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "UDiv(init_rax, init_rbx)"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "arithmetic"

    def test_neg_expression(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "-init_rax"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "arithmetic"


# =====================================================================
#  2. Bitwise patterns
# =====================================================================

class TestSymbolicBitwise:
    def test_and(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "init_rax & init_rbx"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "bitwise"

    def test_or(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "init_rdi | init_rsi"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "bitwise"

    def test_xor_operator(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "init_rax ^ init_rbx"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "bitwise"

    def test_xor_function(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "Xor(init_rax, init_rbx)"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "bitwise"

    def test_not(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "~init_rax"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "bitwise"

    def test_shift_left(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "init_rax << 5"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "bitwise"

    def test_lshr(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "LShR(init_rax, init_rcx)"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "bitwise"


# =====================================================================
#  3. Crypto / rotation patterns
# =====================================================================

class TestSymbolicCrypto:
    def test_rotate_left(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "RotateLeft(init_rax, 13)"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "crypto"

    def test_rotate_right(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "RotateRight(init_rax, 7)"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "crypto"


# =====================================================================
#  4. Memory / Stack patterns
# =====================================================================

class TestSymbolicMemory:
    def test_memory_load(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "mem_0x401000"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "memory"

    def test_stack_write_only(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={},
            input_symbols={},
            memory_writes=[{"address": "init_rsp - 8", "value": "init_rax"}],
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "stack"

    def test_non_stack_memory_write(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={},
            input_symbols={},
            memory_writes=[{"address": "init_rbx + 0x10", "value": "init_rax"}],
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "memory"


# =====================================================================
#  5. Error / empty handling
# =====================================================================

class TestSymbolicEdgeCases:
    def test_no_summary(self):
        model = SymbolicClassifierModel()
        result = model.predict({})
        assert result.label == "unknown"
        assert result.confidence == 0.0

    def test_error_summary(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(error="timeout")
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "unknown"

    def test_empty_registers_no_mem(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={},
            input_symbols={},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.label == "nop"  # no effects → nop

    def test_identity_register_ignored(self):
        """Registers whose output == input should not generate matches."""
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "init_rax", "rbx": "init_rbx"},
            input_symbols={"rax": "init_rax", "rbx": "init_rbx"},
        )
        result = model.predict({"symbolic_summary": summary})
        # No interesting expressions, no mem writes → nop
        assert result.label == "nop"

    def test_summary_as_object_with_to_dict(self):
        """Accept objects with to_dict() method."""
        model = SymbolicClassifierModel()

        class FakeSummary:
            def to_dict(self):
                return {
                    "simplified_registers": {"rax": "init_rax + init_rbx"},
                    "input_symbols": {"rax": "init_rax"},
                }

        result = model.predict({"symbolic_summary": FakeSummary()})
        assert result.label == "arithmetic"


# =====================================================================
#  6. Ensemble integration
# =====================================================================

class TestEnsembleIntegration:
    """WeightedEnsemble with heuristic + symbolic models."""

    def _build_ensemble(self) -> WeightedEnsemble:
        heuristic = VMHandlerModel()
        symbolic = SymbolicClassifierModel()
        return WeightedEnsemble(
            models=[heuristic, symbolic],
            weights=[0.4, 0.6],
        )

    def test_ensemble_predicts(self):
        ensemble = self._build_ensemble()
        features = {
            "values": [0.5, 0.3, 0.0, 0.8, 0.2, 0.0, 0.0, 0.0, 0.0, 0.1, 0.0, 0.0, 0.0],
            "names": [
                "arith_ratio", "logic_ratio", "mem_ratio", "stack_ratio",
                "branch_ratio", "vip_delta", "nop_ratio", "junk_ratio",
                "reg_diversity", "insn_count", "avg_operands", "push_ratio", "pop_ratio",
            ],
            "symbolic_summary": _make_summary(
                simplified_registers={"rax": "init_rax + init_rbx"},
                input_symbols={"rax": "init_rax"},
            ),
        }
        result = ensemble.predict(features)
        assert result.label != ""
        assert result.confidence > 0.0

    def test_ensemble_without_symbolic(self):
        """Ensemble still works when symbolic returns unknown."""
        ensemble = self._build_ensemble()
        features = {
            "values": [0.5, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 5.0, 0.0, 0.0, 0.0],
            "names": [
                "arith_ratio", "logic_ratio", "mem_ratio", "stack_ratio",
                "branch_ratio", "vip_delta", "nop_ratio", "junk_ratio",
                "reg_diversity", "insn_count", "avg_operands", "push_ratio", "pop_ratio",
            ],
            # No symbolic_summary → SymbolicClassifierModel returns unknown
        }
        result = ensemble.predict(features)
        assert result.label != ""

    def test_ensemble_majority_vote(self):
        """EnsembleClassifier simple majority."""
        symbolic = SymbolicClassifierModel()
        heuristic = VMHandlerModel()
        ensemble = EnsembleClassifier(models=[heuristic, symbolic])
        features = {
            "values": [0.8, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 10.0, 0.0, 0.0, 0.0],
            "names": [
                "arith_ratio", "logic_ratio", "mem_ratio", "stack_ratio",
                "branch_ratio", "vip_delta", "nop_ratio", "junk_ratio",
                "reg_diversity", "insn_count", "avg_operands", "push_ratio", "pop_ratio",
            ],
            "symbolic_summary": _make_summary(
                simplified_registers={"rax": "init_rax + init_rbx"},
                input_symbols={"rax": "init_rax"},
            ),
        }
        result = ensemble.predict(features)
        assert result.label in ("arithmetic", "unknown", "bitwise", "stack")


# =====================================================================
#  7. PredictionResult metadata
# =====================================================================

class TestPredictionMetadata:
    def test_symbolic_method_in_metadata(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "init_rax + init_rbx"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.metadata.get("method") == "symbolic"

    def test_no_match_metadata(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "42"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert result.metadata.get("method") == "symbolic"

    def test_probabilities_populated(self):
        model = SymbolicClassifierModel()
        summary = _make_summary(
            simplified_registers={"rax": "init_rax & init_rbx"},
            input_symbols={"rax": "init_rax"},
        )
        result = model.predict({"symbolic_summary": summary})
        assert "bitwise" in result.probabilities


# =====================================================================
#  8. Import paths
# =====================================================================

class TestImportPaths:
    def test_import_from_ml(self):
        from dragonslayer.ml import SymbolicClassifierModel
        assert SymbolicClassifierModel is not None

    def test_import_from_ml_model(self):
        from dragonslayer.ml.model import SymbolicClassifierModel
        assert SymbolicClassifierModel is not None
