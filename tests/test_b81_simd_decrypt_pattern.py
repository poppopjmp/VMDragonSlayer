"""B81 — SIMD stubs, multi-round decrypt, version fingerprinting.

Tests cover:
  - Executor: SIMD entries in _DISPATCH_MAP, handler methods exist/callable,
    _exec_arith deduplicated conditional, handler unit tests with concrete state.
  - Decrypt: CipherOp/CipherStep enums, auto_detect_cipher_chain,
    decrypt_chained round-trip, multi-round sequencing.
  - Pattern: PatternRecognizer.version_fingerprint method, _VERSION_SIGS,
    YARA rule files existence.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any, Dict, List

import pytest

_REPO = Path(__file__).resolve().parent.parent


# ===================================================================
# Executor — SIMD stubs + _exec_arith fix
# ===================================================================
class TestSIMDDispatch:
    """Verify SIMD/SSE entries in the dispatch table."""

    def test_simd_mov_entries(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        dm = SymbolicExecutor._DISPATCH_MAP
        for mnem in ("movdqa", "movdqu", "movaps", "movups", "movd", "movq"):
            assert mnem in dm, f"{mnem} missing from _DISPATCH_MAP"
            assert dm[mnem] == "_exec_simd_mov"

    def test_simd_logic_entries(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        dm = SymbolicExecutor._DISPATCH_MAP
        for mnem in ("pxor", "por", "pand", "pandn", "xorps", "xorpd",
                      "andps", "andpd", "orps", "orpd"):
            assert mnem in dm, f"{mnem} missing from _DISPATCH_MAP"
            assert dm[mnem] == "_exec_simd_logic"

    def test_simd_shuffle_entries(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        dm = SymbolicExecutor._DISPATCH_MAP
        for mnem in ("pshufd", "shufps", "shufpd", "punpcklbw", "punpckhbw",
                      "punpckldq", "punpckhdq"):
            assert mnem in dm

    def test_simd_arith_entries(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        dm = SymbolicExecutor._DISPATCH_MAP
        for mnem in ("paddb", "paddw", "paddd", "paddq",
                      "psubb", "psubw", "psubd", "psubq"):
            assert mnem in dm

    def test_simd_handlers_callable(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        for name in ("_exec_simd_mov", "_exec_simd_logic",
                     "_exec_simd_shuffle", "_exec_simd_arith"):
            assert hasattr(SymbolicExecutor, name)
            assert callable(getattr(SymbolicExecutor, name))

    def test_simd_handler_signatures(self) -> None:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        for name in ("_exec_simd_mov", "_exec_simd_logic",
                     "_exec_simd_shuffle", "_exec_simd_arith"):
            sig = inspect.signature(getattr(SymbolicExecutor, name))
            assert len(sig.parameters) == 5  # self, state, ops, insn, mnemonic

    def test_dispatch_map_total_size(self) -> None:
        """With SIMD additions, dispatch map should have 70+ entries."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        assert len(SymbolicExecutor._DISPATCH_MAP) >= 70


class TestExecArithFix:
    """Verify _exec_arith no longer has redundant identical branches."""

    def test_no_duplicate_branch(self) -> None:
        src = (_REPO / "dragonslayer" / "analysis" / "symbolic_execution" / "executor.py").read_text("utf-8")
        # Find _exec_arith body
        in_method = False
        lines: list[str] = []
        for line in src.splitlines():
            if "def _exec_arith" in line:
                in_method = True
                lines = [line]
                continue
            if in_method:
                if line.strip().startswith("def "):
                    break
                lines.append(line)
        body = "\n".join(lines)
        # Should NOT have an "else:" followed by identical arithmetic
        # Old pattern was:  else:\n            result = (left + right)...
        assert body.count("result = (left + right)") == 1, (
            "_exec_arith still has duplicate result computation"
        )


class TestConcreteHandlerExecution:
    """Unit tests for individual handler methods with concrete state."""

    @pytest.fixture()
    def make_state(self) -> Any:
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        def _make(bit_width: int = 64, **regs: int) -> SymbolicState:
            state = SymbolicState(bit_width=bit_width)
            for name, val in regs.items():
                state.set_register(name, val)
            return state
        return _make

    @pytest.fixture()
    def executor(self) -> Any:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        return SymbolicExecutor.__new__(SymbolicExecutor)

    @pytest.fixture()
    def insn_factory(self) -> Any:
        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction
        def _make(mnemonic: str, operands: str, addr: int = 0x1000, size: int = 4) -> LiftedInstruction:
            return LiftedInstruction(
                address=addr,
                size=size,
                mnemonic=mnemonic,
                operands=operands,
                category="",
                raw_bytes=b"",
            )
        return _make

    def test_exec_mov(self, executor: Any, make_state: Any, insn_factory: Any) -> None:
        state = make_state(rax=0x42, rbx=0x100)
        insn = insn_factory("mov", "rax, rbx")
        executor._exec_mov(state, ["rax", "rbx"], insn, "mov")
        assert state.get_register("rax") == 0x100

    def test_exec_arith_add(self, executor: Any, make_state: Any, insn_factory: Any) -> None:
        state = make_state(rax=10, rbx=20)
        insn = insn_factory("add", "rax, rbx")
        executor._exec_arith(state, ["rax", "rbx"], insn, "add")
        assert state.get_register("rax") == 30

    def test_exec_arith_sub(self, executor: Any, make_state: Any, insn_factory: Any) -> None:
        state = make_state(rax=50, rbx=30)
        insn = insn_factory("sub", "rax, rbx")
        executor._exec_arith(state, ["rax", "rbx"], insn, "sub")
        assert state.get_register("rax") == 20

    def test_exec_logic_xor(self, executor: Any, make_state: Any, insn_factory: Any) -> None:
        state = make_state(rax=0xFF00, rbx=0x00FF)
        insn = insn_factory("xor", "rax, rbx")
        executor._exec_logic(state, ["rax", "rbx"], insn, "xor")
        assert state.get_register("rax") == 0xFFFF

    def test_exec_inc_dec(self, executor: Any, make_state: Any, insn_factory: Any) -> None:
        state = make_state(rcx=100)
        insn = insn_factory("inc", "rcx")
        executor._exec_inc_dec(state, ["rcx"], insn, "inc")
        assert state.get_register("rcx") == 101
        executor._exec_inc_dec(state, ["rcx"], insn, "dec")
        assert state.get_register("rcx") == 100

    def test_exec_not(self, executor: Any, make_state: Any, insn_factory: Any) -> None:
        state = make_state(rax=0)
        insn = insn_factory("not", "rax")
        executor._exec_not(state, ["rax"], insn, "not")
        assert state.get_register("rax") == ~0

    def test_exec_nop(self, executor: Any, make_state: Any, insn_factory: Any) -> None:
        state = make_state(rax=42)
        insn = insn_factory("nop", "")
        executor._exec_nop(state, [], insn, "nop")
        assert state.get_register("rax") == 42


# ===================================================================
# Decrypt — multi-round cipher chain
# ===================================================================
class TestCipherChain:
    """Verify CipherOp, CipherStep, and multi-round decrypt."""

    def test_cipher_op_values(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import CipherOp
        assert CipherOp.XOR.value == "xor"
        assert CipherOp.ADD.value == "add"
        assert CipherOp.ROL.value == "rol"
        assert CipherOp.BSWAP.value == "bswap"

    def test_cipher_step_creation(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import CipherStep, CipherOp
        step = CipherStep(op=CipherOp.XOR, operand_source="key")
        assert step.op == CipherOp.XOR
        assert step.operand_source == "key"

    def test_apply_cipher_step_xor(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import _apply_cipher_step, CipherStep, CipherOp
        step = CipherStep(op=CipherOp.XOR, operand_source="key")
        result = _apply_cipher_step(0xAB, step, key=0xFF, width=8)
        assert result == (0xAB ^ 0xFF)

    def test_apply_cipher_step_add(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import _apply_cipher_step, CipherStep, CipherOp
        step = CipherStep(op=CipherOp.ADD, operand_source="key")
        result = _apply_cipher_step(0xF0, step, key=0x20, width=8)
        assert result == (0xF0 + 0x20) & 0xFF

    def test_apply_cipher_step_not(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import _apply_cipher_step, CipherStep, CipherOp
        step = CipherStep(op=CipherOp.NOT, operand_source="")
        result = _apply_cipher_step(0x55, step, key=0, width=8)
        assert result == (~0x55) & 0xFF

    def test_apply_cipher_step_imm(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import _apply_cipher_step, CipherStep, CipherOp
        step = CipherStep(op=CipherOp.XOR, operand_source="imm:170")
        result = _apply_cipher_step(0xFF, step, key=0, width=8)
        assert result == (0xFF ^ 170) & 0xFF


class TestAutoDetectCipherChain:
    def test_with_opcode_transforms(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import (
            auto_detect_cipher_chain, KeyTransform, TransformOp,
        )
        transforms = [
            KeyTransform(op=TransformOp.XOR, operand_source="opcode"),
            KeyTransform(op=TransformOp.ADD, operand_source="opcode"),
            KeyTransform(op=TransformOp.NOT, operand_source=""),
        ]
        chain = auto_detect_cipher_chain(transforms)
        assert len(chain) == 2  # XOR and ADD (NOT has no opcode source)

    def test_empty_transforms(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import auto_detect_cipher_chain
        chain = auto_detect_cipher_chain([])
        assert len(chain) == 1  # Fallback single XOR


class TestDecryptChained:
    def test_single_xor_round_trip(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import (
            BytecodeDecryptor, CipherStep, CipherOp,
        )
        key = 0xAB
        plain = bytes([0x10, 0x20, 0x30])
        encrypted = bytes([b ^ key for b in plain])
        dec = BytecodeDecryptor(
            initial_key=key,
            key_width=8,
            opcode_width=1,
            cipher_chain=[CipherStep(op=CipherOp.XOR, operand_source="key")],
        )
        result, keys = dec.decrypt_chained(encrypted)
        # First byte should match (before key update)
        assert result[0] == plain[0]

    def test_multi_round_changes_output(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import (
            BytecodeDecryptor, CipherStep, CipherOp,
        )
        encrypted = bytes([0xFF])
        key = 0x55
        # XOR then NOT: value = ~(0xFF ^ 0x55) & 0xFF
        dec = BytecodeDecryptor(
            initial_key=key,
            key_width=8,
            opcode_width=1,
            cipher_chain=[
                CipherStep(op=CipherOp.XOR, operand_source="key"),
                CipherStep(op=CipherOp.NOT, operand_source=""),
            ],
        )
        result, keys = dec.decrypt_chained(encrypted)
        expected = (~(0xFF ^ 0x55)) & 0xFF
        assert result[0] == expected

    def test_chained_fallback_no_chain(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import BytecodeDecryptor, KeyTransform, TransformOp
        # A decryptor WITH a transform so decrypt() actually XOR-decodes,
        # but with no cipher_chain so decrypt_chained falls back to decrypt().
        dec = BytecodeDecryptor(
            initial_key=0xAB, key_width=8, opcode_width=1,
            transforms=[KeyTransform(op=TransformOp.XOR, operand_source="opcode")],
        )
        result, keys = dec.decrypt_chained(bytes([0xAB ^ 0x10]))
        assert result[0] == 0x10

    def test_cipher_chain_field_default(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import BytecodeDecryptor
        dec = BytecodeDecryptor()
        assert dec.cipher_chain == []


# ===================================================================
# Pattern — version fingerprinting
# ===================================================================
class TestVersionFingerprint:
    """Verify PatternRecognizer.version_fingerprint."""

    @pytest.fixture()
    def recognizer(self) -> Any:
        from dragonslayer.analysis.pattern_analysis.database import PatternDatabase
        from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
        db = PatternDatabase()
        return PatternRecognizer(db, use_yara=False)

    def test_method_exists(self) -> None:
        from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
        assert hasattr(PatternRecognizer, "version_fingerprint")
        assert callable(getattr(PatternRecognizer, "version_fingerprint"))

    def test_version_sigs_populated(self) -> None:
        from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
        assert len(PatternRecognizer._VERSION_SIGS) >= 6

    def test_unknown_bytes(self, recognizer: Any) -> None:
        result = recognizer.version_fingerprint("00000000")
        assert result["protector"] == "unknown"
        assert result["confidence"] == 0.0

    def test_vmp30_detection(self, recognizer: Any) -> None:
        # pushad (60) + B8 + 4-byte immediate
        result = recognizer.version_fingerprint("60B8DEADBEEF")
        assert result["protector"] == "VMProtect"
        assert "3.0" in result["version"]

    def test_themida_2x_detection(self, recognizer: Any) -> None:
        # pushfd(9C) + pushad(60) + call $+5(E800000000) + pop(5D)
        result = recognizer.version_fingerprint("9C60E8000000005D")
        assert result["protector"] == "Themida"
        assert "2.x" in result["version"]

    def test_returns_dict_shape(self, recognizer: Any) -> None:
        result = recognizer.version_fingerprint("CC")
        assert "protector" in result
        assert "version" in result
        assert "confidence" in result


class TestYARAFiles:
    """Verify YARA rule files exist under data/patterns/."""

    def test_vmprotect_yar(self) -> None:
        path = _REPO / "data" / "patterns" / "vmprotect.yar"
        assert path.exists()
        content = path.read_text("utf-8")
        assert "VMP_30" in content or "VMProtect" in content

    def test_themida_yar(self) -> None:
        path = _REPO / "data" / "patterns" / "themida.yar"
        assert path.exists()
        content = path.read_text("utf-8")
        assert "Themida" in content
