"""B85 tests — AnalysisMetrics integration, ML stub removal, AF flag.

Covers:
  - Orchestrator ships ``metrics`` dict in AnalysisResult
  - SymbolicExecutor has ``metrics`` property
  - Executor populates phase timings when metrics attached
  - BaseModel.save()/load() concrete defaults
  - EnsembleClassifier raises ValueError (not NotImplementedError)
  - FeatureExtractor raises ValueError (not NotImplementedError)
  - AF flag concrete path (add, sub)
  - AF flag z3 path
  - pushf → popf roundtrip preserving CF/PF/AF/ZF/SF/OF
  - Negative: unknown condition code returns False
"""

from __future__ import annotations

import json
import os
import pickle
import tempfile
import textwrap

import pytest

# ---------------------------------------------------------------------------
# AF flag — concrete path
# ---------------------------------------------------------------------------

from dragonslayer.analysis.symbolic_execution.state import SymbolicState


class TestAuxiliaryFlagConcrete:
    """AF computation via update_flags_arith (concrete ints)."""

    @staticmethod
    def _make() -> SymbolicState:
        return SymbolicState(arch="x86_64", bit_width=64, initial_pc=0)

    def test_af_set_add(self):
        """0x0F + 0x01 = 0x10 → carry out of nibble, AF = True."""
        st = self._make()
        st.update_flags_arith(0x10, 0x0F, 0x01, is_sub=False)
        assert st.flags["AF"] is True

    def test_af_clear_add(self):
        """0x01 + 0x01 = 0x02 → no nibble carry, AF = False."""
        st = self._make()
        st.update_flags_arith(0x02, 0x01, 0x01, is_sub=False)
        assert st.flags["AF"] is False

    def test_af_set_sub(self):
        """0x10 - 0x01 → borrow into nibble (0x0 < 0x1), AF = True."""
        st = self._make()
        st.update_flags_arith(0x0F, 0x10, 0x01, is_sub=True)
        assert st.flags["AF"] is True

    def test_af_clear_sub(self):
        """0x08 - 0x01 → no borrow (0x8 >= 0x1), AF = False."""
        st = self._make()
        st.update_flags_arith(0x07, 0x08, 0x01, is_sub=True)
        assert st.flags["AF"] is False

    def test_af_boundary_0xf_add(self):
        """0x0F + 0x0F → low nibbles sum 0x1E > 0xF, AF = True."""
        st = self._make()
        st.update_flags_arith(0x1E, 0x0F, 0x0F, is_sub=False)
        assert st.flags["AF"] is True

    def test_af_logic_clears(self):
        """Logical ops (AND/OR/XOR) clear AF."""
        st = self._make()
        st.flags["AF"] = True
        st.update_flags_logic(0xFF)
        assert st.flags["AF"] == False  # noqa: E712  — may be z3 BoolRef


# ---------------------------------------------------------------------------
# AF flag — z3 path
# ---------------------------------------------------------------------------

z3 = pytest.importorskip("z3")


class TestAuxiliaryFlagZ3:
    """AF via z3 symbolic path."""

    @staticmethod
    def _make(bw: int = 64) -> SymbolicState:
        return SymbolicState(arch="x86_64", bit_width=bw, initial_pc=0)

    def test_af_z3_add(self):
        """Concrete value through z3: 0x0F + 0x01 → AF set."""
        st = self._make()
        a = z3.BitVecVal(0x0F, 64)
        b = z3.BitVecVal(0x01, 64)
        res = z3.BitVecVal(0x10, 64)
        st.update_flags_arith(res, a, b, is_sub=False)
        af = st.flags["AF"]
        assert z3.is_true(z3.simplify(af))

    def test_af_z3_sub(self):
        """Concrete value through z3: 0x10 - 0x01 → AF set."""
        st = self._make()
        a = z3.BitVecVal(0x10, 64)
        b = z3.BitVecVal(0x01, 64)
        res = z3.BitVecVal(0x0F, 64)
        st.update_flags_arith(res, a, b, is_sub=True)
        af = st.flags["AF"]
        assert z3.is_true(z3.simplify(af))

    def test_af_z3_clear(self):
        """0x01 + 0x01 = 0x02 through z3 → AF not set."""
        st = self._make()
        a = z3.BitVecVal(0x01, 64)
        b = z3.BitVecVal(0x01, 64)
        res = z3.BitVecVal(0x02, 64)
        st.update_flags_arith(res, a, b, is_sub=False)
        af = st.flags["AF"]
        assert z3.is_false(z3.simplify(af))


# ---------------------------------------------------------------------------
# pushf → popf roundtrip  (now with 6 flags: CF, PF, AF, ZF, SF, OF)
# ---------------------------------------------------------------------------

from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction


class TestPushfPopfRoundtrip:
    """pushf serialises all 6 flags; popf restores them."""

    @staticmethod
    def _make():
        exe = SymbolicExecutor(arch="x86_64")
        st = SymbolicState(arch="x86_64", bit_width=64, initial_pc=0)
        # Give a valid stack pointer
        st.set_register("rsp", 0x7FFF_0100)
        return exe, st

    @staticmethod
    def _dummy_insn():
        return LiftedInstruction(
            address=0, mnemonic="pushf", operands=[], size=1,
            category="system", raw_bytes=b"\x9c",
        )

    def test_roundtrip_all_set(self):
        exe, st = self._make()
        st.flags["CF"] = True
        st.flags["PF"] = True
        st.flags["AF"] = True
        st.flags["ZF"] = True
        st.flags["SF"] = True
        st.flags["OF"] = True
        insn = self._dummy_insn()
        exe._exec_pushf(st, [], insn, "pushf")
        # Clear all flags
        for f in ("CF", "PF", "AF", "ZF", "SF", "OF"):
            st.flags[f] = False
        popf_insn = LiftedInstruction(
            address=1, mnemonic="popf", operands=[], size=1,
            category="system", raw_bytes=b"\x9d",
        )
        exe._exec_popf(st, [], popf_insn, "popf")
        for f in ("CF", "PF", "AF", "ZF", "SF", "OF"):
            assert st.flags[f] is True, f"Expected {f} True after roundtrip"

    def test_roundtrip_all_clear(self):
        exe, st = self._make()
        for f in ("CF", "PF", "AF", "ZF", "SF", "OF"):
            st.flags[f] = False
        insn = self._dummy_insn()
        exe._exec_pushf(st, [], insn, "pushf")
        # Set all flags
        for f in ("CF", "PF", "AF", "ZF", "SF", "OF"):
            st.flags[f] = True
        popf_insn = LiftedInstruction(
            address=1, mnemonic="popf", operands=[], size=1,
            category="system", raw_bytes=b"\x9d",
        )
        exe._exec_popf(st, [], popf_insn, "popf")
        for f in ("CF", "PF", "AF", "ZF", "SF", "OF"):
            assert st.flags[f] is False, f"Expected {f} False after roundtrip"

    def test_roundtrip_mixed(self):
        exe, st = self._make()
        st.flags["CF"] = True
        st.flags["PF"] = False
        st.flags["AF"] = True
        st.flags["ZF"] = False
        st.flags["SF"] = True
        st.flags["OF"] = False
        insn = self._dummy_insn()
        exe._exec_pushf(st, [], insn, "pushf")
        for f in ("CF", "PF", "AF", "ZF", "SF", "OF"):
            st.flags[f] = not st.flags[f]  # invert
        popf_insn = LiftedInstruction(
            address=1, mnemonic="popf", operands=[], size=1,
            category="system", raw_bytes=b"\x9d",
        )
        exe._exec_popf(st, [], popf_insn, "popf")
        assert st.flags["CF"] is True
        assert st.flags["PF"] is False
        assert st.flags["AF"] is True
        assert st.flags["ZF"] is False
        assert st.flags["SF"] is True
        assert st.flags["OF"] is False


# ---------------------------------------------------------------------------
# Unknown condition code returns False
# ---------------------------------------------------------------------------


class TestUnknownConditionCode:
    def test_unknown_returns_false(self):
        exe = SymbolicExecutor(arch="x86_64")
        st = SymbolicState(arch="x86_64", bit_width=64, initial_pc=0)
        result = exe._evaluate_condition(st, "bogus_cc")
        assert result is False


# ---------------------------------------------------------------------------
# AnalysisMetrics integration into Orchestrator
# ---------------------------------------------------------------------------

from dragonslayer.core.orchestrator import Orchestrator, AnalysisResult
from dragonslayer.utils.metrics import AnalysisMetrics


class TestOrchestratorMetrics:
    """Orchestrator attaches AnalysisMetrics and includes them in results."""

    def test_orchestrator_has_metrics(self):
        orch = Orchestrator()
        assert isinstance(orch.metrics, AnalysisMetrics)

    def test_result_has_metrics_field(self):
        r = AnalysisResult(success=True, metrics={"phases": []})
        d = r.to_dict()
        assert "metrics" in d
        assert d["metrics"]["phases"] == []

    def test_dispatch_populates_metrics(self):
        """analyze_binary should include metrics dict in result."""
        orch = Orchestrator()
        # Minimal binary — enough for pattern engine to run briefly
        result = orch.analyze_binary(b"\xcc" * 16)
        assert "metrics" in result.to_dict()
        assert isinstance(result.metrics, dict)


# ---------------------------------------------------------------------------
# SymbolicExecutor metrics property
# ---------------------------------------------------------------------------


class TestExecutorMetricsProperty:
    def test_default_none(self):
        exe = SymbolicExecutor(arch="x86_64")
        assert exe.metrics is None

    def test_set_metrics(self):
        exe = SymbolicExecutor(arch="x86_64")
        m = AnalysisMetrics()
        exe.metrics = m
        assert exe.metrics is m

    def test_analyze_populates_phases(self):
        exe = SymbolicExecutor(arch="x86_64")
        m = AnalysisMetrics()
        exe.metrics = m
        code = b"\x55\x48\x89\xe5\xb8\x01\x00\x00\x00\x5d\xc3"
        exe.analyze(code, entry_point=0)
        d = m.to_dict()
        phase_names = [p["name"] for p in d["phases"]]
        assert "lift" in phase_names


# ---------------------------------------------------------------------------
# ML stub elimination
# ---------------------------------------------------------------------------

from dragonslayer.ml.model import BaseModel
from dragonslayer.ml.ensemble import EnsembleClassifier
from dragonslayer.ml.pipeline import FeatureExtractor


class TestBaseModelSaveLoad:
    """BaseModel now has concrete save/load defaults."""

    def test_save_raises_without_artifact(self):
        m = BaseModel()
        with pytest.raises(RuntimeError, match="no artifact"):
            m.save("/tmp/model.pkl")

    def test_save_load_roundtrip(self):
        m = BaseModel()
        m._artifact = {"test": 42}
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "model.pkl")
            m.save(path)
            m2 = BaseModel()
            m2.load(path)
            assert m2._artifact["test"] == 42

    def test_load_missing_file(self):
        m = BaseModel()
        with pytest.raises(FileNotFoundError):
            m.load("/nonexistent/path/model.pkl")


class TestEnsembleValueError:
    """EnsembleClassifier.predict() now raises ValueError, not NotImplementedError."""

    def test_empty_ensemble_raises_value_error(self):
        ens = EnsembleClassifier()
        with pytest.raises(ValueError, match="no component models"):
            ens.predict({"x": 1})


class TestFeatureExtractorValueError:
    """FeatureExtractor.extract() raises ValueError when no spec is given."""

    def test_no_spec_raises_value_error(self):
        fe = FeatureExtractor()
        with pytest.raises(ValueError, match="requires a feature_spec"):
            fe.extract({"some": "data"})
