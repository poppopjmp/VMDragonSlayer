"""
B77 Tests: Auto bind_pointer in _process_instruction, __init__.py fallback,
CI enforcement, and end-to-end integration pipeline.

Covers:
- Automatic pointer binding from concrete register values
- LEA/MOV destination binding
- MemoryAliasTracker fallback in __init__.py
- Integration: VM detection → pattern recognition → taint tracking → symbolic exec
- CI configuration validation (mypy enforcing, coverage 80%)
"""

from __future__ import annotations

import importlib
import pathlib
from pathlib import Path
import re
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

# ── Module imports ──────────────────────────────────────────────────────

from dragonslayer.analysis.taint_tracking.tracker import (
    ByteTaintMap,
    MemoryAliasTracker,
    TaintTag,
    TaintTracker,
)
from dragonslayer.analysis.taint_tracking import (
    MemoryAliasTracker as MAT_init,
)

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent

# ── Helpers ─────────────────────────────────────────────────────────────

def _insn(
    mnemonic: str = "nop",
    operands: str = "",
    reads: Optional[List[str]] = None,
    writes: Optional[List[str]] = None,
    address: int = 0,
    category: str = "unknown",
    registers: Optional[Dict[str, int]] = None,
):
    """Build a minimal instruction namespace for TaintTracker."""
    return SimpleNamespace(
        mnemonic=mnemonic,
        operands=operands,
        reads=reads or [],
        writes=writes or [],
        address=address,
        category=category,
        registers=registers or {},
    )


# =====================================================================
# 1. Auto bind_pointer tests
# =====================================================================


class TestAutoBindPointer:
    """_process_instruction should automatically bind pointer values."""

    def test_concrete_reg_values_auto_bound(self):
        """All concrete register values should be bound to the pointer tracker."""
        t = TaintTracker()
        insn = _insn(
            mnemonic="add",
            reads=["rax", "rbx"],
            writes=["rax"],
            registers={"rax": 0x1000, "rbx": 0x2000},
        )
        t.process_instruction(insn)
        assert t.pointer_tracker.resolve("rax") == 0x1000
        assert t.pointer_tracker.resolve("rbx") == 0x2000

    def test_non_int_values_ignored(self):
        """Non-integer register values should not be bound."""
        t = TaintTracker()
        insn = _insn(
            mnemonic="add",
            reads=["rax"],
            writes=["rax"],
            registers={"rax": "symbolic"},
        )
        t.process_instruction(insn)
        assert t.pointer_tracker.resolve("rax") is None

    def test_lea_destination_binding(self):
        """LEA instruction should bind the destination register."""
        t = TaintTracker()
        insn = _insn(
            mnemonic="lea",
            operands="rax, [rbp+0x10]",
            reads=["rbp"],
            writes=["rax"],
            registers={"rax": 0x7FF0, "rbp": 0x7FE0},
        )
        t.process_instruction(insn)
        # rax should be bound to its concrete value
        assert t.pointer_tracker.resolve("rax") == 0x7FF0
        assert t.pointer_tracker.resolve("rbp") == 0x7FE0

    def test_mov_destination_binding(self):
        """MOV instruction should bind the destination register if concrete."""
        t = TaintTracker()
        insn = _insn(
            mnemonic="mov",
            operands="rcx, 0xDEAD",
            reads=[],
            writes=["rcx"],
            registers={"rcx": 0xDEAD},
        )
        t.process_instruction(insn)
        assert t.pointer_tracker.resolve("rcx") == 0xDEAD

    def test_must_alias_after_instruction_sequence(self):
        """After processing instructions, registers with same address should alias."""
        t = TaintTracker()
        # First: mov rax, addr
        t.process_instruction(_insn(
            mnemonic="mov", reads=[], writes=["rax"],
            registers={"rax": 0x4000},
        ))
        # Second: mov rbx, addr (same)
        t.process_instruction(_insn(
            mnemonic="mov", reads=[], writes=["rbx"],
            registers={"rbx": 0x4000},
        ))
        assert t.must_alias("rax", "rbx")

    def test_pointer_taint_after_auto_bind(self):
        """Memory taint should be queryable via register after auto-bind."""
        t = TaintTracker()
        t.taint_memory(0x5000, TaintTag.INPUT)
        t.process_instruction(_insn(
            mnemonic="mov", reads=[], writes=["rdx"],
            registers={"rdx": 0x5000},
        ))
        tag = t.memory_taint_via_reg("rdx")
        assert tag & TaintTag.INPUT

    def test_empty_reg_values_no_error(self):
        """No register values should not cause errors."""
        t = TaintTracker()
        insn = _insn(mnemonic="nop", registers={})
        t.process_instruction(insn)
        # Should not raise

    def test_none_reg_values_no_error(self):
        """None register values map should not cause errors."""
        t = TaintTracker()
        insn = _insn(mnemonic="nop")
        insn.registers = None
        t.process_instruction(insn)
        # Should not raise

    def test_overwrite_binding_on_new_value(self):
        """Subsequent instruction should update the binding."""
        t = TaintTracker()
        t.process_instruction(_insn(
            mnemonic="mov", reads=[], writes=["rax"],
            registers={"rax": 0x1000},
        ))
        assert t.pointer_tracker.resolve("rax") == 0x1000
        # Second instruction updates rax
        t.process_instruction(_insn(
            mnemonic="add", reads=["rax", "rbx"], writes=["rax"],
            registers={"rax": 0x2000, "rbx": 0x1000},
        ))
        assert t.pointer_tracker.resolve("rax") == 0x2000

    def test_reset_clears_auto_bindings(self):
        """reset() should clear all auto-bound pointers."""
        t = TaintTracker()
        t.process_instruction(_insn(
            mnemonic="mov", reads=[], writes=["rax"],
            registers={"rax": 0x3000},
        ))
        assert t.pointer_tracker.resolve("rax") == 0x3000
        t.reset()
        assert t.pointer_tracker.resolve("rax") is None

    def test_non_lea_mov_no_write_bind(self):
        """Non-LEA/MOV instructions should still bind from reg_values
        but not do the special write-destination logic."""
        t = TaintTracker()
        insn = _insn(
            mnemonic="add",
            reads=["rax", "rbx"],
            writes=["rax"],
            registers={"rax": 0x100, "rbx": 0x200},
        )
        t.process_instruction(insn)
        # Both should be bound from the reg_values loop
        assert t.pointer_tracker.resolve("rax") == 0x100
        assert t.pointer_tracker.resolve("rbx") == 0x200


# =====================================================================
# 2. __init__.py fallback tests
# =====================================================================


class TestInitFallback:
    """MemoryAliasTracker exported from taint_tracking __init__."""

    def test_memory_alias_tracker_importable(self):
        """MemoryAliasTracker should be importable from the package."""
        assert MAT_init is not None
        assert MAT_init is MemoryAliasTracker

    def test_memory_alias_tracker_in_all(self):
        """MemoryAliasTracker should be in __all__."""
        import dragonslayer.analysis.taint_tracking as pkg
        assert "MemoryAliasTracker" in pkg.__all__

    def test_fallback_except_block_has_mat(self):
        """The except block should define MemoryAliasTracker = None."""
        init_path = PROJECT_ROOT / "dragonslayer" / "analysis" / "taint_tracking" / "__init__.py"
        source = init_path.read_text(encoding="utf-8")
        # Find the except block for the tracker import
        # Ensure MemoryAliasTracker appears after the except
        except_idx = source.find("except (ImportError, AttributeError):")
        assert except_idx != -1
        # Text between the first except and the next try
        block_end = source.find("try:", except_idx + 1)
        if block_end == -1:
            block_end = len(source)
        except_block = source[except_idx:block_end]
        assert "MemoryAliasTracker = None" in except_block


# =====================================================================
# 3. CI config validation tests
# =====================================================================


class TestCIConfig:
    """Validate CI workflow configuration."""

    @pytest.fixture()
    def ci_yaml(self):
        ci_path = PROJECT_ROOT / ".github" / "workflows" / "ci.yml"
        if not ci_path.exists():
            pytest.skip("CI workflow not found")
        return ci_path.read_text(encoding="utf-8")

    def test_coverage_threshold_80(self, ci_yaml):
        """Coverage fail-under should be >=80."""
        match = re.search(r"--cov-fail-under=(\d+)", ci_yaml)
        assert match, "No --cov-fail-under found in CI"
        threshold = int(match.group(1))
        assert threshold >= 80, f"Coverage threshold is {threshold}, expected >=80"

    def test_mypy_enforcing(self, ci_yaml):
        """Mypy should NOT have || true (must be enforcing)."""
        # Find the mypy run line
        mypy_lines = [
            line for line in ci_yaml.splitlines()
            if "mypy" in line.lower() and "run:" in line.lower()
        ]
        # Also check continuation of mypy lines
        for i, line in enumerate(ci_yaml.splitlines()):
            if "mypy dragonslayer" in line:
                assert "|| true" not in line, "Mypy has || true — not enforcing!"
                assert "|| :" not in line, "Mypy has || : — not enforcing!"

    def test_ci_has_test_job(self, ci_yaml):
        """CI should have a test job."""
        assert "test:" in ci_yaml or "tests:" in ci_yaml

    def test_ci_has_lint_job(self, ci_yaml):
        """CI should have a lint job."""
        assert "lint:" in ci_yaml

    def test_ci_has_typecheck_job(self, ci_yaml):
        """CI should have a typecheck job."""
        assert "typecheck:" in ci_yaml


# =====================================================================
# 4. End-to-end integration tests
# =====================================================================


class TestEndToEndIntegration:
    """
    Integration tests that exercise multiple subsystems together:
    VM detection → Pattern recognition → Taint tracking → Symbolic execution
    """

    def test_vm_detection_to_pattern_pipeline(self):
        """VMDetector + PatternRecognizer on a VMProtect-like binary."""
        from dragonslayer.analysis.vm_discovery.detector import VMDetector
        from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
        from dragonslayer.analysis.pattern_analysis.database import PatternDatabase

        # Build a minimal VMProtect-like PE binary
        pe_header = bytearray(1024)
        pe_header[0:2] = b"MZ"
        pe_header[0x3C:0x40] = (0x80).to_bytes(4, "little")  # PE offset
        pe_header[0x80:0x84] = b"PE\x00\x00"  # PE signature
        pe_header[0x84:0x86] = (0x8664).to_bytes(2, "little")  # AMD64

        # Add .vmp0 section marker
        pe_header[0x200:0x208] = b".vmp0\x00\x00\x00"

        binary_data = bytes(pe_header) + b"\x00" * 4096

        # Step 1: VM detection
        detector = VMDetector()
        result = detector.detect(binary_data)
        assert isinstance(result, dict)
        assert "vm_detected" in result
        assert "confidence" in result
        # VMProtect section should boost confidence
        has_vmp_indicator = any(
            ind.get("type") == "vm_sections" or
            "vmp" in str(ind).lower()
            for ind in result.get("indicators", [])
        )
        assert has_vmp_indicator or result.get("vm_detected")

        # Step 2: Pattern recognition on hex-encoded handler bytes
        db = PatternDatabase()
        patterns_file = PROJECT_ROOT / "data" / "patterns" / "vmprotect_handlers.json"
        if patterns_file.exists():
            db.load(patterns_file)
        recognizer = PatternRecognizer(db, use_yara=False)

        # A VMProtect ADD handler signature
        handler_hex = "4801C04889C1"
        matches = recognizer.recognize(handler_hex, min_confidence=0.5)
        # Should find at least a potential match
        assert isinstance(matches, list)

    def test_taint_tracking_full_trace(self):
        """Full taint tracking analysis on a handler instruction sequence."""
        t = TaintTracker()
        t.taint_register("rdi", TaintTag.INPUT)
        t.taint_register("rsi", TaintTag.VM_OPERAND)

        # Simulate a VM handler: reads input, computes, writes back
        instructions = [
            _insn("mov", "rax, rdi", reads=["rdi"], writes=["rax"],
                   address=0x1000, registers={"rdi": 0x10, "rax": 0x10}),
            _insn("add", "rax, rsi", reads=["rax", "rsi"], writes=["rax"],
                   address=0x1004, registers={"rax": 0x20, "rsi": 0x30}),
            _insn("mov", "[rbp+0x10], rax", reads=["rax", "rbp"],
                   writes=["mem"], address=0x1008,
                   registers={"rax": 0x50, "rbp": 0x7FFF0000}),
            _insn("test", "rax, rax", reads=["rax"], writes=["eflags"],
                   address=0x100C, category="flag_producer",
                   registers={"rax": 0x50}),
            _insn("jz", "0x1020", reads=["eflags"], writes=[],
                   address=0x1010, category="branch_conditional"),
        ]

        result = t.analyze(instructions)
        assert result.success
        assert result.instructions_analyzed == 5
        # rax should carry merged taint from rdi (INPUT) and rsi (VM_OPERAND)
        assert "rax" in result.tainted_registers

    def test_taint_with_auto_bind_pointer_integration(self):
        """Auto-bind pointers should enable alias-aware taint queries."""
        t = TaintTracker()
        t.taint_register("rdi", TaintTag.INPUT)

        # Instruction 1: mov rax, rdi (rax gets tainted)
        t.process_instruction(_insn(
            "mov", "rax, rdi", reads=["rdi"], writes=["rax"],
            address=0x100, registers={"rax": 0x1000, "rdi": 0x1000},
        ))
        # Both rax and rdi are auto-bound to the same address
        assert t.must_alias("rax", "rdi")
        # rax should now be tainted (propagated from rdi)
        assert t.is_tainted("rax")

        # Instruction 2: store rax to memory
        t.process_instruction(_insn(
            "mov", "[rbp+0x10], rax", reads=["rax"], writes=["mem"],
            address=0x104, registers={"rax": 0x1000, "rbp": 0x7FFF0000},
        ))

        # Instruction 3: load via rcx pointing to same address as rax
        t.process_instruction(_insn(
            "mov", "rcx, [rax]", reads=["rax"], writes=["rcx"],
            address=0x108, registers={"rcx": 0x1000, "rax": 0x1000},
        ))
        # rcx should alias rax (same concrete value)
        assert t.must_alias("rcx", "rax")

    def test_symbolic_executor_handler_analysis(self):
        """SymbolicExecutor + TaintTracker on a simple handler."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor

        executor = SymbolicExecutor(arch="x86_64", max_depth=50)

        # A trivial handler: push rbp; mov rbp, rsp; pop rbp; ret
        handler_bytes = bytes([
            0x55,                   # push rbp
            0x48, 0x89, 0xE5,      # mov rbp, rsp
            0x5D,                   # pop rbp
            0xC3,                   # ret
        ])

        summary = executor.execute_handler(handler_bytes, handler_address=0x1000)
        assert summary is not None
        assert hasattr(summary, "instruction_count")
        # Should have lifted at least a few instructions
        assert summary.instruction_count >= 1

    def test_interprocedural_taint_with_auto_bind(self):
        """push/pop_call_context with auto-bound pointers."""
        t = TaintTracker()
        t.taint_register("rdi", TaintTag.INPUT)

        # Pre-call setup
        t.process_instruction(_insn(
            "mov", "rax, rdi", reads=["rdi"], writes=["rax"],
            address=0x200, registers={"rax": 0xBEEF, "rdi": 0xBEEF},
        ))
        assert t.is_tainted("rax")
        assert t.pointer_tracker.resolve("rax") == 0xBEEF

        # Call
        t.push_call_context()
        assert t.call_depth == 1

        # Inside callee — rax pointer changes
        t.process_instruction(_insn(
            "mov", "rax, 0", reads=[], writes=["rax"],
            address=0x300, registers={"rax": 0},
        ))
        assert t.pointer_tracker.resolve("rax") == 0

        # Return — rax keeps callee taint, depth restores
        t.pop_call_context(return_regs=("rax",))
        assert t.call_depth == 0

    def test_ml_feature_extraction_from_handler(self):
        """ML pipeline: extract features from handler-like dicts."""
        from dragonslayer.ml.pipeline import (
            extract_handler_features,
            extract_extended_features,
        )

        handler = {
            "instructions": [
                {"mnemonic": "mov", "operands": "rax, [rdi]"},
                {"mnemonic": "add", "operands": "rax, rsi"},
                {"mnemonic": "mov", "operands": "[rdi+8], rax"},
            ],
            "mnemonics": ["mov", "add", "mov"],
            "reads": ["rdi", "rsi"],
            "writes": ["rax"],
            "block_count": 1,
            "operand_width": 64,
        }

        fv = extract_handler_features(handler)
        assert fv.dimension == 17
        assert len(fv.values) == 17
        assert all(isinstance(v, (int, float)) for v in fv.values)

        efv = extract_extended_features(handler)
        assert efv.dimension >= 100  # 132 expected
        assert len(efv.values) == efv.dimension

    def test_orchestrator_hybrid_analysis(self):
        """Orchestrator with HYBRID analysis type exercises both VM discovery and patterns."""
        from dragonslayer.core.orchestrator import Orchestrator, AnalysisType

        # Minimal VMProtect-like PE
        pe_header = bytearray(512)
        pe_header[0:2] = b"MZ"
        pe_header[0x3C:0x40] = (0x80).to_bytes(4, "little")
        pe_header[0x80:0x84] = b"PE\x00\x00"
        pe_header[0x84:0x86] = (0x8664).to_bytes(2, "little")
        pe_header[0x200:0x208] = b".vmp0\x00\x00\x00"

        binary_data = bytes(pe_header) + b"\x00" * 2048

        with Orchestrator() as orch:
            result = orch.analyze_binary(
                binary_data,
                analysis_type=AnalysisType.HYBRID,
            )
        assert result.success
        assert result.analysis_type
        assert isinstance(result.engine_results, list)
        # Should have run at least one engine
        assert len(result.engine_results) >= 1
