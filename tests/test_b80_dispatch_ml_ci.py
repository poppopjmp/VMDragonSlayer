"""B80 — dispatch table, ML cmp/test features, _VOLATILE_REGS, CI security.

Tests cover:
  - Executor: _DISPATCH_MAP exists with full mnemonic coverage, all handler
    methods are callable, compact _apply_instruction, CMOVcc fix, ``import re``
    hoisted to module level.
  - ML/pipeline: ``has_cmp_insn`` and ``has_test_insn`` in feature names and
    extracted values.
  - ML/model: comparison heuristic rules include new features.
  - Taint/tracker: ``_VOLATILE_REGS`` at module level.
  - CI: ``bandit`` and ``pip-audit`` security steps, ``py.typed`` marker.
"""

from __future__ import annotations

import ast
import importlib
import inspect
import textwrap
from pathlib import Path
from typing import Any, Dict, List

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_REPO = Path(__file__).resolve().parent.parent
_EXECUTOR_PY = _REPO / "dragonslayer" / "analysis" / "symbolic_execution" / "executor.py"
_CI_YML = _REPO / ".github" / "workflows" / "ci.yml"
_PIPELINE_PY = _REPO / "dragonslayer" / "ml" / "pipeline.py"
_MODEL_PY = _REPO / "dragonslayer" / "ml" / "model.py"
_TRACKER_PY = _REPO / "dragonslayer" / "analysis" / "taint_tracking" / "tracker.py"


# ===================================================================
# Executor dispatch table
# ===================================================================
class TestDispatchTable:
    """Verify the dispatch-table architecture in the executor."""

    def test_dispatch_map_exists(self) -> None:
        from dragonslayer.analysis.symbolic_execution import executor as mod
        cls = mod.SymbolicExecutor
        assert hasattr(cls, "_DISPATCH_MAP"), "_DISPATCH_MAP missing"
        assert isinstance(cls._DISPATCH_MAP, dict)

    def test_dispatch_map_covers_core_mnemonics(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        dm = SymbolicExecutor._DISPATCH_MAP
        core = [
            "mov", "add", "sub", "adc", "sbb",
            "and", "or", "xor", "not",
            "shl", "shr", "sar", "rol", "ror",
            "inc", "dec", "neg",
            "push", "pop", "lea",
            "movzx", "movsx", "movsxd",
            "cmp", "test", "xchg",
            "imul", "mul", "div", "idiv",
            "pushf", "pushfq", "pushfd",
            "popf", "popfq", "popfd",
            "cdq", "cqo", "cdqe", "cwde", "cwd",
            "bswap",
            "bt", "bts", "btr", "btc",
            "nop", "call", "ret", "retn",
        ]
        for mnem in core:
            assert mnem in dm, f"mnemonic '{mnem}' missing from _DISPATCH_MAP"

    def test_dispatch_map_min_size(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        assert len(SymbolicExecutor._DISPATCH_MAP) >= 45

    def test_all_handler_methods_exist(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        dm = SymbolicExecutor._DISPATCH_MAP
        method_names = set(dm.values())
        # Also include prefix-dispatched handlers
        method_names.add("_exec_cmovcc")
        method_names.add("_exec_setcc")
        for name in method_names:
            assert hasattr(SymbolicExecutor, name), f"handler method {name} not found"
            assert callable(getattr(SymbolicExecutor, name))

    def test_handler_method_signatures(self) -> None:
        """Each handler must accept (self, state, ops, insn, mnemonic)."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        dm = SymbolicExecutor._DISPATCH_MAP
        method_names = set(dm.values()) | {"_exec_cmovcc", "_exec_setcc"}
        for name in method_names:
            sig = inspect.signature(getattr(SymbolicExecutor, name))
            params = list(sig.parameters.keys())
            assert len(params) == 5, f"{name} has {len(params)} params, expected 5"
            assert params[0] == "self"
            assert "state" in params
            assert "ops" in params

    def test_apply_instruction_uses_dispatch(self) -> None:
        """_apply_instruction should contain getattr dispatch, not elif chain."""
        src = _EXECUTOR_PY.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_apply_instruction":
                body_src = ast.get_source_segment(src, node)
                assert body_src is not None
                assert "getattr" in body_src, "dispatch via getattr not found"
                assert "_DISPATCH_MAP" in body_src, "_DISPATCH_MAP reference not found"
                # Should NOT have old elif chain (exact-match branches)
                elif_count = body_src.count("elif mnemonic ==")
                assert elif_count == 0, f"old elif chain still present ({elif_count} branches)"
                break
        else:
            pytest.fail("_apply_instruction not found")

    def test_apply_instruction_compact(self) -> None:
        """The new _apply_instruction should be < 30 lines."""
        src = _EXECUTOR_PY.read_text(encoding="utf-8")
        in_method = False
        line_count = 0
        for line in src.splitlines():
            if "def _apply_instruction" in line:
                in_method = True
                line_count = 1
                continue
            if in_method:
                # Stop at next def at same indent level
                if line.strip() and not line.startswith("    ") and line.strip() != "":
                    break
                if line.startswith("    def ") or line.startswith("    # ── B80"):
                    break
                line_count += 1
        assert line_count < 30, f"_apply_instruction is {line_count} lines, expected < 30"


class TestCMOVccFix:
    """Verify the CMOVcc operator-precedence bug is fixed."""

    def test_no_hasattr_bool_pattern(self) -> None:
        """Old buggy pattern: ``hasattr(cond, '__bool__') is False or``."""
        src = _EXECUTOR_PY.read_text(encoding="utf-8")
        assert "hasattr(cond, '__bool__') is False" not in src, (
            "CMOVcc bug pattern still present"
        )

    def test_cmovcc_handler_exists(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        assert hasattr(SymbolicExecutor, "_exec_cmovcc")

    def test_setcc_handler_exists(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        assert hasattr(SymbolicExecutor, "_exec_setcc")


class TestImportReHoisted:
    """Verify ``import re`` at module level, not inside _sib_regex."""

    def test_module_level_import_re(self) -> None:
        src = _EXECUTOR_PY.read_text(encoding="utf-8")
        tree = ast.parse(src)
        # Check module-level imports
        found = False
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "re":
                        found = True
        assert found, "import re not found at module level"

    def test_no_inline_import_re_in_sib_regex(self) -> None:
        """No ``import re`` inside ``_sib_regex``."""
        src = _EXECUTOR_PY.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_sib_regex":
                for child in ast.walk(node):
                    if isinstance(child, ast.Import):
                        for alias in child.names:
                            assert alias.name != "re", (
                                "Inline 'import re' still in _sib_regex"
                            )


# ===================================================================
# ML pipeline — has_cmp_insn / has_test_insn features
# ===================================================================
class TestCmpTestFeatures:
    """Verify has_cmp_insn and has_test_insn are in the feature pipeline."""

    def test_feature_names_include_cmp_test(self) -> None:
        from dragonslayer.ml.pipeline import HANDLER_FEATURE_NAMES
        assert "has_cmp_insn" in HANDLER_FEATURE_NAMES
        assert "has_test_insn" in HANDLER_FEATURE_NAMES

    def test_extract_with_cmp(self) -> None:
        from dragonslayer.ml.pipeline import extract_handler_features
        handler: Dict[str, Any] = {
            "mnemonics": ["push", "cmp", "je", "pop"],
        }
        fv = extract_handler_features(handler)
        idx_cmp = fv.feature_names.index("has_cmp_insn")
        idx_test = fv.feature_names.index("has_test_insn")
        assert fv.values[idx_cmp] == 1.0
        assert fv.values[idx_test] == 0.0

    def test_extract_with_test(self) -> None:
        from dragonslayer.ml.pipeline import extract_handler_features
        handler: Dict[str, Any] = {
            "mnemonics": ["push", "test", "jne", "pop"],
        }
        fv = extract_handler_features(handler)
        idx_cmp = fv.feature_names.index("has_cmp_insn")
        idx_test = fv.feature_names.index("has_test_insn")
        assert fv.values[idx_cmp] == 0.0
        assert fv.values[idx_test] == 1.0

    def test_extract_with_both(self) -> None:
        from dragonslayer.ml.pipeline import extract_handler_features
        handler: Dict[str, Any] = {
            "mnemonics": ["cmp", "test", "cmove"],
        }
        fv = extract_handler_features(handler)
        idx_cmp = fv.feature_names.index("has_cmp_insn")
        idx_test = fv.feature_names.index("has_test_insn")
        assert fv.values[idx_cmp] == 1.0
        assert fv.values[idx_test] == 1.0

    def test_extract_without_either(self) -> None:
        from dragonslayer.ml.pipeline import extract_handler_features
        handler: Dict[str, Any] = {
            "mnemonics": ["push", "mov", "add", "pop"],
        }
        fv = extract_handler_features(handler)
        idx_cmp = fv.feature_names.index("has_cmp_insn")
        idx_test = fv.feature_names.index("has_test_insn")
        assert fv.values[idx_cmp] == 0.0
        assert fv.values[idx_test] == 0.0

    def test_feature_vector_length_matches_names(self) -> None:
        from dragonslayer.ml.pipeline import extract_handler_features
        handler: Dict[str, Any] = {"mnemonics": ["nop"]}
        fv = extract_handler_features(handler)
        assert len(fv.values) == len(fv.feature_names)


class TestComparisonHeuristicRules:
    """Verify comparison heuristic rules include the new features."""

    def test_comparison_rules_have_cmp_test(self) -> None:
        from dragonslayer.ml.model import _HEURISTIC_RULES
        rules = _HEURISTIC_RULES["comparison"]
        feature_names = [r[0] for r in rules]
        assert "has_cmp_insn" in feature_names
        assert "has_test_insn" in feature_names

    def test_cmp_test_weights_high(self) -> None:
        from dragonslayer.ml.model import _HEURISTIC_RULES
        rules = _HEURISTIC_RULES["comparison"]
        for feat, weight, _, _ in rules:
            if feat in ("has_cmp_insn", "has_test_insn"):
                assert weight >= 2.0, f"{feat} weight {weight} too low"


# ===================================================================
# Taint tracker — _VOLATILE_REGS module-level
# ===================================================================
class TestVolatileRegsModuleLevel:
    """Verify _VOLATILE_REGS is at module level in tracker.py."""

    def test_module_level_constant(self) -> None:
        from dragonslayer.analysis.taint_tracking import tracker as mod
        assert hasattr(mod, "_VOLATILE_REGS"), "_VOLATILE_REGS not at module level"
        assert isinstance(mod._VOLATILE_REGS, frozenset)

    def test_contains_expected_regs(self) -> None:
        from dragonslayer.analysis.taint_tracking.tracker import _VOLATILE_REGS
        for reg in ("rsp", "esp", "rip", "eip", "eflags", "rflags"):
            assert reg in _VOLATILE_REGS, f"{reg} missing from _VOLATILE_REGS"

    def test_not_defined_inside_method(self) -> None:
        """_VOLATILE_REGS should not be re-created inside any method body."""
        src = _TRACKER_PY.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(node):
                    if isinstance(child, ast.Assign):
                        for target in child.targets:
                            if isinstance(target, ast.Name) and target.id == "_VOLATILE_REGS":
                                pytest.fail(
                                    f"_VOLATILE_REGS redefined inside {node.name}"
                                )


# ===================================================================
# CI — security scanning
# ===================================================================
class TestCISecurity:
    """Verify CI has bandit and pip-audit steps."""

    @pytest.fixture()
    def ci_text(self) -> str:
        return _CI_YML.read_text(encoding="utf-8")

    def test_bandit_step(self, ci_text: str) -> None:
        assert "bandit" in ci_text.lower()
        assert "bandit -r dragonslayer/" in ci_text

    def test_pip_audit_step(self, ci_text: str) -> None:
        assert "pip-audit" in ci_text

    def test_security_job_exists(self, ci_text: str) -> None:
        assert "security:" in ci_text

    def test_py_typed_marker(self) -> None:
        marker = _REPO / "dragonslayer" / "py.typed"
        assert marker.exists(), "py.typed PEP 561 marker missing"
