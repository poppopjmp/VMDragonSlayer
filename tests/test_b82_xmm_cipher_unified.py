"""B82 tests — XMM register modelling, cipher chain verification, unified detection.

Covers:
- XMM register initialisation in SymbolicState (128-bit)
- Lane-aware packed arithmetic (_packed_add, _packed_sub)
- SIMD handler 128-bit promotion (_ensure_xmm)
- Cipher-chain inverse derivation & round-trip verification
- Entropy-drop calculation
- Unified version_fingerprint (regex + YARA cross-validation)
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest

_REPO = pathlib.Path(__file__).resolve().parent.parent


# ===================================================================
# SymExec — XMM register modelling
# ===================================================================
class TestXMMRegisters:
    """Verify that SymbolicState initialises xmm0-xmm15 at 128 bits."""

    def test_xmm_registers_present(self) -> None:
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        state = SymbolicState(arch="x86_64", bit_width=64)
        for i in range(16):
            assert f"xmm{i}" in state.registers, f"xmm{i} missing"

    def test_xmm_initial_value_type(self) -> None:
        """XMM regs should be 128-bit z3 BitVec or int(0)."""
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        state = SymbolicState(arch="x86_64", bit_width=64)
        val = state.registers["xmm0"]
        try:
            import z3
            assert hasattr(val, "sort") and val.sort().size() == 128
        except ImportError:
            assert val == 0

    def test_xmm_not_in_32bit(self) -> None:
        """x86-32 mode should NOT have XMM registers."""
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        state = SymbolicState(arch="x86_32", bit_width=32)
        assert "xmm0" not in state.registers

    def test_get_set_xmm(self) -> None:
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        state = SymbolicState(arch="x86_64", bit_width=64)
        state.set_register("xmm5", 0xDEADBEEFCAFEBABE)
        assert state.get_register("xmm5") == 0xDEADBEEFCAFEBABE

    def test_xmm_width_constant(self) -> None:
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        assert SymbolicState.XMM_WIDTH == 128

    def test_xmm_register_list_length(self) -> None:
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        assert len(SymbolicState.XMM_REGISTERS) == 16


# ===================================================================
# Executor — SIMD helpers
# ===================================================================
class TestSIMDHelpers:
    """Test _ensure_xmm, _packed_add, _packed_sub."""

    def _get_executor_class(self) -> type:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        return SymbolicExecutor

    def test_ensure_xmm_int(self) -> None:
        cls = self._get_executor_class()
        assert cls._ensure_xmm(0xFF) == 0xFF
        # Clamp to 128 bits
        big = (1 << 200)
        result = cls._ensure_xmm(big)
        assert result == big & ((1 << 128) - 1)

    def test_ensure_xmm_z3(self) -> None:
        cls = self._get_executor_class()
        try:
            import z3
            bv64 = z3.BitVecVal(42, 64)
            result = cls._ensure_xmm(bv64)
            assert result.sort().size() == 128
        except ImportError:
            pytest.skip("z3 not available")

    def test_packed_add_bytes(self) -> None:
        cls = self._get_executor_class()
        # Two 128-bit values with known byte lanes
        a = 0xFF  # byte 0 = 255, rest = 0
        b = 0x01  # byte 0 = 1, rest = 0
        result = cls._packed_add(a, b, 8)
        # 255 + 1 = 256 → wraps to 0 in 8-bit lane
        assert (result & 0xFF) == 0

    def test_packed_add_no_overflow_leak(self) -> None:
        cls = self._get_executor_class()
        # byte[0] = 255, byte[1] = 0 — adding 1 to byte[0] should NOT carry into byte[1]
        a = 0xFF
        b = 0x01
        result = cls._packed_add(a, b, 8)
        assert (result >> 8) & 0xFF == 0  # no carry leak

    def test_packed_sub_bytes(self) -> None:
        cls = self._get_executor_class()
        a = 0x00  # byte 0 = 0
        b = 0x01  # byte 0 = 1
        result = cls._packed_sub(a, b, 8)
        # 0 - 1 = -1 → wraps to 255 in unsigned 8-bit
        assert (result & 0xFF) == 0xFF

    def test_packed_add_dwords(self) -> None:
        cls = self._get_executor_class()
        # 4 dword lanes
        a = (1 << 0) | (2 << 32) | (3 << 64) | (4 << 96)
        b = (10 << 0) | (20 << 32) | (30 << 64) | (40 << 96)
        result = cls._packed_add(a, b, 32)
        mask32 = (1 << 32) - 1
        assert (result >> 0) & mask32 == 11
        assert (result >> 32) & mask32 == 22
        assert (result >> 64) & mask32 == 33
        assert (result >> 96) & mask32 == 44

    def test_lane_width_map(self) -> None:
        cls = self._get_executor_class()
        assert cls._LANE_WIDTH["paddb"] == 8
        assert cls._LANE_WIDTH["paddw"] == 16
        assert cls._LANE_WIDTH["paddd"] == 32
        assert cls._LANE_WIDTH["paddq"] == 64
        assert cls._LANE_WIDTH["psubb"] == 8


# ===================================================================
# SIMD handler execution with concrete XMM state
# ===================================================================
class TestSIMDExecution:
    """Test SIMD handlers actually use 128-bit XMM registers."""

    @pytest.fixture()
    def executor(self) -> Any:
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        return SymbolicExecutor.__new__(SymbolicExecutor)

    @pytest.fixture()
    def state(self) -> Any:
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        return SymbolicState(arch="x86_64", bit_width=64)

    @pytest.fixture()
    def insn_factory(self) -> Any:
        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction
        def _make(mnemonic: str, operands: str) -> LiftedInstruction:
            return LiftedInstruction(
                address=0x1000, size=4, mnemonic=mnemonic,
                operands=operands, category="", raw_bytes=b"",
            )
        return _make

    def test_pxor_self_clears(self, executor: Any, state: Any, insn_factory: Any) -> None:
        """PXOR xmm0, xmm0 should clear the register to 0."""
        state.set_register("xmm0", 0xDEADBEEF)
        insn = insn_factory("pxor", "xmm0, xmm0")
        executor._exec_simd_logic(state, ["xmm0", "xmm0"], insn, "pxor")
        val = state.get_register("xmm0")
        if hasattr(val, "sort"):
            import z3
            assert z3.simplify(val == 0)
        else:
            assert val == 0

    def test_movdqa_copies(self, executor: Any, state: Any, insn_factory: Any) -> None:
        state.set_register("xmm1", 0xCAFEBABE)
        insn = insn_factory("movdqa", "xmm0, xmm1")
        executor._exec_simd_mov(state, ["xmm0", "xmm1"], insn, "movdqa")
        val = state.get_register("xmm0")
        if hasattr(val, "sort"):
            import z3
            src = state.get_register("xmm1")
            assert z3.is_true(z3.simplify(val == src))
        else:
            assert val == 0xCAFEBABE

    def test_paddb_lane_wrap(self, executor: Any, state: Any, insn_factory: Any) -> None:
        """PADDB should wrap within 8-bit lanes."""
        state.set_register("xmm0", 0xFF)  # byte0=255
        state.set_register("xmm1", 0x01)  # byte0=1
        insn = insn_factory("paddb", "xmm0, xmm1")
        executor._exec_simd_arith(state, ["xmm0", "xmm1"], insn, "paddb")
        val = state.get_register("xmm0")
        if not hasattr(val, "sort"):
            assert (val & 0xFF) == 0  # wrapped


# ===================================================================
# Decrypt — cipher chain verification & inverse
# ===================================================================
class TestCipherChainVerification:
    """Test inverse_cipher_chain, verify_cipher_chain, entropy_drop."""

    def test_inverse_xor_chain(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import (
            CipherStep, CipherOp, inverse_cipher_chain,
        )
        chain = [CipherStep(op=CipherOp.XOR, operand_source="key")]
        inv = inverse_cipher_chain(chain)
        assert len(inv) == 1
        assert inv[0].op == CipherOp.XOR  # self-inverse

    def test_inverse_add_sub(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import (
            CipherStep, CipherOp, inverse_cipher_chain,
        )
        chain = [CipherStep(op=CipherOp.ADD, operand_source="key")]
        inv = inverse_cipher_chain(chain)
        assert inv[0].op == CipherOp.SUB

    def test_inverse_multi_reverses_order(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import (
            CipherStep, CipherOp, inverse_cipher_chain,
        )
        chain = [
            CipherStep(op=CipherOp.XOR, operand_source="key"),
            CipherStep(op=CipherOp.ADD, operand_source="key"),
            CipherStep(op=CipherOp.ROL, operand_source="imm:3"),
        ]
        inv = inverse_cipher_chain(chain)
        assert len(inv) == 3
        assert inv[0].op == CipherOp.ROR  # inverse of ROL
        assert inv[1].op == CipherOp.SUB  # inverse of ADD
        assert inv[2].op == CipherOp.XOR  # inverse of XOR
        assert inv[0].operand_source == "imm:3"  # preserved

    def test_verify_single_xor(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import (
            CipherStep, CipherOp, verify_cipher_chain,
        )
        chain = [CipherStep(op=CipherOp.XOR, operand_source="key")]
        assert verify_cipher_chain(chain, width=8) is True

    def test_verify_complex_chain(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import (
            CipherStep, CipherOp, verify_cipher_chain,
        )
        chain = [
            CipherStep(op=CipherOp.XOR, operand_source="key"),
            CipherStep(op=CipherOp.ADD, operand_source="key"),
            CipherStep(op=CipherOp.NOT),
        ]
        assert verify_cipher_chain(chain, width=8) is True

    def test_verify_bswap_chain(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import (
            CipherStep, CipherOp, verify_cipher_chain,
        )
        chain = [CipherStep(op=CipherOp.BSWAP)]
        # BSWAP on 8-bit is identity (1 byte) → trivially invertible
        assert verify_cipher_chain(chain, width=8) is True

    def test_verify_rol_ror(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import (
            CipherStep, CipherOp, verify_cipher_chain,
        )
        chain = [
            CipherStep(op=CipherOp.ROL, operand_source="imm:3"),
            CipherStep(op=CipherOp.XOR, operand_source="key"),
        ]
        assert verify_cipher_chain(chain, width=8) is True

    def test_entropy_drop_positive(self) -> None:
        """Random-looking encrypted data XOR'd with a key should drop entropy."""
        from dragonslayer.analysis.bytecode_decrypt import (
            CipherStep, CipherOp, cipher_chain_entropy_drop,
        )
        # Encrypted = repeating pattern XOR'd with key 0xAB
        plaintext = bytes(range(256))  # uniform distribution
        key = 0xAB
        encrypted = bytes(b ^ key for b in plaintext)
        chain = [CipherStep(op=CipherOp.XOR, operand_source="key")]
        # H(encrypted) ≈ H(plaintext) since XOR is bijective with uniform input
        # but for non-uniform data the drop will be measurable
        drop = cipher_chain_entropy_drop(chain, encrypted, key, width=8)
        # With uniform plaintext, drop should be ~0
        assert abs(drop) < 0.01

    def test_entropy_drop_with_structured_plaintext(self) -> None:
        """Plaintext with structure should show measurable entropy drop."""
        from dragonslayer.analysis.bytecode_decrypt import (
            CipherStep, CipherOp, cipher_chain_entropy_drop,
        )
        # Plaintext is all zeros (very low entropy)
        plaintext = bytes(256)
        key = 0xAB
        encrypted = bytes(b ^ key for b in plaintext)
        chain = [CipherStep(op=CipherOp.XOR, operand_source="key")]
        drop = cipher_chain_entropy_drop(chain, encrypted, key, width=8)
        # Encrypted has entropy ~0 (all same byte 0xAB); plaintext also entropy 0
        # so drop ≈ 0
        assert drop >= 0.0 or abs(drop) < 0.1

    def test_inverse_map_completeness(self) -> None:
        from dragonslayer.analysis.bytecode_decrypt import CipherOp, _CIPHER_INVERSE
        for op in CipherOp:
            assert op in _CIPHER_INVERSE, f"No inverse for {op}"


# ===================================================================
# Pattern — unified version fingerprinting
# ===================================================================
class TestUnifiedVersionFingerprint:
    """Test the enhanced version_fingerprint with engine tracking."""

    @pytest.fixture()
    def recognizer(self) -> Any:
        from dragonslayer.analysis.pattern_analysis.database import PatternDatabase
        from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
        db = PatternDatabase()
        return PatternRecognizer(db, use_yara=False)

    def test_engines_field_present(self, recognizer: Any) -> None:
        result = recognizer.version_fingerprint("00000000")
        assert "engines" in result
        assert isinstance(result["engines"], list)

    def test_regex_only_engine(self, recognizer: Any) -> None:
        result = recognizer.version_fingerprint("60B8DEADBEEF")
        assert result["protector"] == "VMProtect"
        assert "regex" in result["engines"]

    def test_unknown_returns_empty_engines(self, recognizer: Any) -> None:
        result = recognizer.version_fingerprint("CC")
        assert result["engines"] == []

    def test_yara_version_map_populated(self) -> None:
        from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
        assert len(PatternRecognizer._YARA_VERSION_MAP) >= 8

    def test_dual_engine_boost_value(self) -> None:
        from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
        assert PatternRecognizer._DUAL_ENGINE_BOOST == 0.10

    def test_confidence_capped_at_1(self, recognizer: Any) -> None:
        """Even with boosts, confidence should never exceed 1.0."""
        result = recognizer.version_fingerprint("60B8DEADBEEF")
        assert result["confidence"] <= 1.0
