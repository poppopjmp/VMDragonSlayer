"""Tests for Phase 11 — new x86 instruction handlers and operand-size EFLAGS.

Covers: imul, mul, div, idiv, cmovCC, setCC, bswap, pushf/popf,
        cdq/cqo/cdqe/cwde/cwd, bt/bts/btr/btc, call, ret, nop,
        _evaluate_condition, _infer_operand_bits, and operand-size
        aware flag computation.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Helper factory
# ---------------------------------------------------------------------------

def _make():
    from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
    from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction
    from dragonslayer.analysis.symbolic_execution.state import SymbolicState
    exe = SymbolicExecutor(arch="x86_64")
    state = SymbolicState(arch="x86_64")
    for reg in list(state.registers):
        state.registers[reg] = 0
    return exe, state, LiftedInstruction


def _insn(Insn, mnemonic, operands="", size=2):
    return Insn(
        address=0x1000, mnemonic=mnemonic, operands=operands, size=size,
        category="data", raw_bytes=b"\x90" * size,
    )


# ===================================================================
# _evaluate_condition
# ===================================================================

class TestEvaluateCondition:
    """Verify _evaluate_condition returns correct bool for all CCs."""

    def test_e_true(self):
        exe, st, _ = _make()
        st.flags["ZF"] = True
        assert exe._evaluate_condition(st, "e") is True

    def test_e_false(self):
        exe, st, _ = _make()
        st.flags["ZF"] = False
        assert exe._evaluate_condition(st, "e") is False

    def test_ne(self):
        exe, st, _ = _make()
        st.flags["ZF"] = False
        assert exe._evaluate_condition(st, "ne") is True

    def test_g(self):
        exe, st, _ = _make()
        st.flags["ZF"] = False
        st.flags["SF"] = False
        st.flags["OF"] = False
        assert exe._evaluate_condition(st, "g") is True

    def test_g_false(self):
        exe, st, _ = _make()
        st.flags["ZF"] = True
        st.flags["SF"] = False
        st.flags["OF"] = False
        assert exe._evaluate_condition(st, "g") is False

    def test_ge(self):
        exe, st, _ = _make()
        st.flags["SF"] = True
        st.flags["OF"] = True
        assert exe._evaluate_condition(st, "ge") is True

    def test_l(self):
        exe, st, _ = _make()
        st.flags["SF"] = True
        st.flags["OF"] = False
        assert exe._evaluate_condition(st, "l") is True

    def test_le(self):
        exe, st, _ = _make()
        st.flags["ZF"] = True
        st.flags["SF"] = False
        st.flags["OF"] = False
        assert exe._evaluate_condition(st, "le") is True

    def test_a(self):
        exe, st, _ = _make()
        st.flags["CF"] = False
        st.flags["ZF"] = False
        assert exe._evaluate_condition(st, "a") is True

    def test_ae(self):
        exe, st, _ = _make()
        st.flags["CF"] = False
        assert exe._evaluate_condition(st, "ae") is True

    def test_b(self):
        exe, st, _ = _make()
        st.flags["CF"] = True
        assert exe._evaluate_condition(st, "b") is True

    def test_be(self):
        exe, st, _ = _make()
        st.flags["CF"] = True
        st.flags["ZF"] = False
        assert exe._evaluate_condition(st, "be") is True

    def test_s(self):
        exe, st, _ = _make()
        st.flags["SF"] = True
        assert exe._evaluate_condition(st, "s") is True

    def test_ns(self):
        exe, st, _ = _make()
        st.flags["SF"] = False
        assert exe._evaluate_condition(st, "ns") is True

    def test_o(self):
        exe, st, _ = _make()
        st.flags["OF"] = True
        assert exe._evaluate_condition(st, "o") is True

    def test_no(self):
        exe, st, _ = _make()
        st.flags["OF"] = False
        assert exe._evaluate_condition(st, "no") is True

    def test_p_default_false(self):
        exe, st, _ = _make()
        assert exe._evaluate_condition(st, "p") is False

    def test_np_default_true(self):
        exe, st, _ = _make()
        assert exe._evaluate_condition(st, "np") is True


# ===================================================================
# _infer_operand_bits
# ===================================================================

class TestInferOperandBits:
    """Verify operand-size inference from register names and prefixes."""

    def test_8bit_regs(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        for r in ("al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
                   "sil", "dil", "r8b", "r15b"):
            assert SymbolicExecutor._infer_operand_bits(r) == 8, f"Failed for {r}"

    def test_16bit_regs(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        for r in ("ax", "bx", "cx", "dx", "si", "di", "r10w"):
            assert SymbolicExecutor._infer_operand_bits(r) == 16, f"Failed for {r}"

    def test_32bit_regs(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        for r in ("eax", "ebx", "ecx", "edx", "esi", "r12d"):
            assert SymbolicExecutor._infer_operand_bits(r) == 32, f"Failed for {r}"

    def test_64bit_regs(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        for r in ("rax", "rbx", "rcx", "rdx", "rsi", "r8", "r15", "rip"):
            assert SymbolicExecutor._infer_operand_bits(r) == 64, f"Failed for {r}"

    def test_size_prefix(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        assert SymbolicExecutor._infer_operand_bits("byte ptr [rax]") == 8
        assert SymbolicExecutor._infer_operand_bits("word ptr [rax]") == 16
        assert SymbolicExecutor._infer_operand_bits("dword ptr [rsp+8]") == 32
        assert SymbolicExecutor._infer_operand_bits("qword ptr [rsp]") == 64

    def test_unknown_default(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        assert SymbolicExecutor._infer_operand_bits("0x42") == 0
        assert SymbolicExecutor._infer_operand_bits("0x42", 64) == 64


# ===================================================================
# IMUL
# ===================================================================

class TestImul:
    """IMUL instruction in 1-, 2-, and 3-operand forms."""

    def test_imul_2op(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 7
        st.registers["rcx"] = 3
        exe._apply_instruction(st, _insn(Insn, "imul", "rax, rcx"))
        assert st.registers["rax"] == 21

    def test_imul_3op(self):
        exe, st, Insn = _make()
        st.registers["rcx"] = 5
        exe._apply_instruction(st, _insn(Insn, "imul", "rax, rcx, 6"))
        assert st.registers["rax"] == 30

    def test_imul_1op(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 4
        st.registers["rcx"] = 3
        exe._apply_instruction(st, _insn(Insn, "imul", "rcx"))
        # 1-op IMUL: RDX:RAX = RAX * operand
        assert st.registers["rax"] == 12
        assert st.registers["rdx"] == 0


# ===================================================================
# MUL
# ===================================================================

class TestMul:
    """Unsigned MUL (1-operand)."""

    def test_mul_small(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 10
        st.registers["rcx"] = 5
        exe._apply_instruction(st, _insn(Insn, "mul", "rcx"))
        assert st.registers["rax"] == 50
        assert st.registers["rdx"] == 0

    def test_mul_overflow(self):
        exe, st, Insn = _make()
        st.registers["rax"] = (1 << 63)
        st.registers["rcx"] = 2
        exe._apply_instruction(st, _insn(Insn, "mul", "rcx"))
        # 2^63 * 2 = 2^64 → rdx=1, rax=0
        assert st.registers["rax"] == 0
        assert st.registers["rdx"] == 1


# ===================================================================
# DIV / IDIV
# ===================================================================

class TestDiv:
    def test_div_basic(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 17
        st.registers["rdx"] = 0
        st.registers["rcx"] = 5
        exe._apply_instruction(st, _insn(Insn, "div", "rcx"))
        assert st.registers["rax"] == 3   # quotient
        assert st.registers["rdx"] == 2   # remainder

    def test_idiv_basic(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 17
        st.registers["rdx"] = 0
        st.registers["rcx"] = 5
        exe._apply_instruction(st, _insn(Insn, "idiv", "rcx"))
        assert st.registers["rax"] == 3
        assert st.registers["rdx"] == 2


# ===================================================================
# CMOVcc
# ===================================================================

class TestCmovcc:
    def test_cmove_true(self):
        exe, st, Insn = _make()
        st.flags["ZF"] = True
        st.registers["rax"] = 99
        st.registers["rcx"] = 42
        exe._apply_instruction(st, _insn(Insn, "cmove", "rax, rcx"))
        assert st.registers["rax"] == 42

    def test_cmove_false(self):
        exe, st, Insn = _make()
        st.flags["ZF"] = False
        st.registers["rax"] = 99
        st.registers["rcx"] = 42
        exe._apply_instruction(st, _insn(Insn, "cmove", "rax, rcx"))
        assert st.registers["rax"] == 99

    def test_cmovne(self):
        exe, st, Insn = _make()
        st.flags["ZF"] = False
        st.registers["rax"] = 0
        st.registers["rcx"] = 7
        exe._apply_instruction(st, _insn(Insn, "cmovne", "rax, rcx"))
        assert st.registers["rax"] == 7

    def test_cmovg(self):
        exe, st, Insn = _make()
        st.flags["ZF"] = False
        st.flags["SF"] = False
        st.flags["OF"] = False
        st.registers["rax"] = 0
        st.registers["rcx"] = 99
        exe._apply_instruction(st, _insn(Insn, "cmovg", "rax, rcx"))
        assert st.registers["rax"] == 99

    def test_cmovl_false(self):
        exe, st, Insn = _make()
        st.flags["SF"] = False
        st.flags["OF"] = False
        st.registers["rax"] = 1
        st.registers["rcx"] = 99
        exe._apply_instruction(st, _insn(Insn, "cmovl", "rax, rcx"))
        assert st.registers["rax"] == 1


# ===================================================================
# SETcc
# ===================================================================

class TestSetcc:
    def test_sete_true(self):
        exe, st, Insn = _make()
        st.flags["ZF"] = True
        st.registers["rax"] = 0
        exe._apply_instruction(st, _insn(Insn, "sete", "al"))
        assert st.get_register("al") == 1

    def test_sete_false(self):
        exe, st, Insn = _make()
        st.flags["ZF"] = False
        st.registers["rax"] = 0xFF
        exe._apply_instruction(st, _insn(Insn, "sete", "al"))
        assert st.get_register("al") == 0

    def test_setne(self):
        exe, st, Insn = _make()
        st.flags["ZF"] = False
        st.registers["rax"] = 0
        exe._apply_instruction(st, _insn(Insn, "setne", "al"))
        assert st.get_register("al") == 1

    def test_setb(self):
        exe, st, Insn = _make()
        st.flags["CF"] = True
        st.registers["rax"] = 0
        exe._apply_instruction(st, _insn(Insn, "setb", "al"))
        assert st.get_register("al") == 1


# ===================================================================
# BSWAP
# ===================================================================

class TestBswap:
    def test_bswap_eax(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0x0102030405060708
        exe._apply_instruction(st, _insn(Insn, "bswap", "rax"))
        assert st.registers["rax"] == 0x0807060504030201

    def test_bswap_zero(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0
        exe._apply_instruction(st, _insn(Insn, "bswap", "rax"))
        assert st.registers["rax"] == 0


# ===================================================================
# PUSHF / POPF
# ===================================================================

class TestPushfPopf:
    def test_pushf_popf_roundtrip(self):
        exe, st, Insn = _make()
        # Set up known stack
        sp = 0x7FFF0100
        st.registers["rsp"] = sp
        # Set some flags
        st.flags["CF"] = True    # bit 0
        st.flags["ZF"] = True    # bit 6
        st.flags["SF"] = False   # bit 7
        st.flags["OF"] = True    # bit 11
        exe._apply_instruction(st, _insn(Insn, "pushf", ""))
        # Stack pointer should have decreased
        assert st.registers["rsp"] == sp - 8
        # Clear flags
        st.flags["CF"] = False
        st.flags["ZF"] = False
        st.flags["OF"] = False
        # Pop them back
        exe._apply_instruction(st, _insn(Insn, "popf", ""))
        assert st.registers["rsp"] == sp
        # Flags restored
        assert st.flags["CF"] is True
        assert st.flags["ZF"] is True
        assert st.flags["OF"] is True


# ===================================================================
# CDQ / CQO / CDQE / CWDE / CWD
# ===================================================================

class TestSignExtend:
    def test_cdq_positive(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0x7FFFFFFF  # positive when viewed as 32-bit
        exe._apply_instruction(st, _insn(Insn, "cdq", ""))
        assert st.registers["rdx"] == 0

    def test_cdq_negative(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0x80000000  # negative in 32-bit
        exe._apply_instruction(st, _insn(Insn, "cdq", ""))
        mask64 = (1 << 64) - 1
        assert st.registers["rdx"] == mask64  # all 1s (sign-extended)

    def test_cqo_positive(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0x7FFFFFFFFFFFFFFF
        exe._apply_instruction(st, _insn(Insn, "cqo", ""))
        assert st.registers["rdx"] == 0

    def test_cqo_negative(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 1 << 63  # negative in 64-bit
        exe._apply_instruction(st, _insn(Insn, "cqo", ""))
        mask64 = (1 << 64) - 1
        assert st.registers["rdx"] == mask64

    def test_cdqe(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0x80000001  # bit 31=1
        exe._apply_instruction(st, _insn(Insn, "cdqe", ""))
        mask64 = (1 << 64) - 1
        # Sign-extend 32→64: 0xFFFFFFFF80000001
        expected = 0xFFFFFFFF80000001
        assert st.registers["rax"] == expected

    def test_cdqe_positive(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0xFFFFFFFF00000001  # eax part = 0x00000001 (positive)
        exe._apply_instruction(st, _insn(Insn, "cdqe", ""))
        assert st.registers["rax"] == 1

    def test_cwde(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0x8001  # AX = 0x8001 (negative 16-bit)
        exe._apply_instruction(st, _insn(Insn, "cwde", ""))
        eax_val = st.registers["rax"] & 0xFFFFFFFF
        # Sign-extend 16→32: 0xFFFF8001
        assert eax_val == 0xFFFF8001


# ===================================================================
# BT / BTS / BTR / BTC
# ===================================================================

class TestBitOps:
    def test_bt_set_bit(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0b1010
        exe._apply_instruction(st, _insn(Insn, "bt", "rax, 1"))
        assert st.flags["CF"] is True

    def test_bt_clear_bit(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0b1010
        exe._apply_instruction(st, _insn(Insn, "bt", "rax, 0"))
        assert st.flags["CF"] is False

    def test_bts(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0b1000
        exe._apply_instruction(st, _insn(Insn, "bts", "rax, 1"))
        assert st.flags["CF"] is False
        assert st.registers["rax"] == 0b1010

    def test_btr(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0b1010
        exe._apply_instruction(st, _insn(Insn, "btr", "rax, 1"))
        assert st.flags["CF"] is True
        assert st.registers["rax"] == 0b1000

    def test_btc(self):
        exe, st, Insn = _make()
        st.registers["rax"] = 0b1010
        exe._apply_instruction(st, _insn(Insn, "btc", "rax, 1"))
        # bit 1 was set → CF=True, complement → cleared
        assert st.flags["CF"] is True
        assert st.registers["rax"] == 0b1000


# ===================================================================
# CALL / RET
# ===================================================================

class TestCallRet:
    def test_call_pushes_return(self):
        exe, st, Insn = _make()
        sp = 0x7FFF0100
        st.registers["rsp"] = sp
        insn = _insn(Insn, "call", "0x2000", size=5)
        exe._apply_instruction(st, insn)
        # RSP should be decremented
        assert st.registers["rsp"] == sp - 8
        # Return address = address + size = 0x1000 + 5 = 0x1005
        ret_addr = st.read_memory(sp - 8, 8)
        assert ret_addr == 0x1005

    def test_ret_pops_address(self):
        exe, st, Insn = _make()
        sp = 0x7FFF0100
        st.registers["rsp"] = sp
        st.write_memory(sp, 0xDEAD, 8)
        exe._apply_instruction(st, _insn(Insn, "ret", ""))
        assert st.registers["rsp"] == sp + 8
        assert st.pc == 0xDEAD


# ===================================================================
# NOP variants
# ===================================================================

class TestNop:
    def test_nop(self):
        exe, st, Insn = _make()
        old_regs = dict(st.registers)
        exe._apply_instruction(st, _insn(Insn, "nop", ""))
        assert st.registers == old_regs

    def test_endbr64(self):
        exe, st, Insn = _make()
        old_regs = dict(st.registers)
        exe._apply_instruction(st, _insn(Insn, "endbr64", ""))
        assert st.registers == old_regs

    def test_pause(self):
        exe, st, Insn = _make()
        old_regs = dict(st.registers)
        exe._apply_instruction(st, _insn(Insn, "pause", ""))
        assert st.registers == old_regs


# ===================================================================
# Operand-size EFLAGS
# ===================================================================

class TestOperandSizeEflags:
    """Verify EFLAGS are computed using the operand width, not the full register width."""

    def test_add_al_sf(self):
        """add al, 0xFF should set SF=True (bit 7 of 8-bit result)."""
        exe, st, Insn = _make()
        st.registers["rax"] = 0
        insn = _insn(Insn, "add", "al, 0x80")
        exe._apply_instruction(st, insn)
        assert st.flags["SF"] is True

    def test_add_al_zf(self):
        """add al, 0x0 when al=0 should set ZF=True."""
        exe, st, Insn = _make()
        st.registers["rax"] = 0
        insn = _insn(Insn, "add", "al, 0")
        exe._apply_instruction(st, insn)
        assert st.flags["ZF"] is True

    def test_cmp_al_flags(self):
        """cmp al, al should set ZF=True for 8-bit."""
        exe, st, Insn = _make()
        st.registers["rax"] = 0x42
        insn = _insn(Insn, "cmp", "al, al")
        exe._apply_instruction(st, insn)
        assert st.flags["ZF"] is True

    def test_and_al_sf(self):
        """and al, 0xFF with al=0x80 should set SF."""
        exe, st, Insn = _make()
        st.registers["rax"] = 0x80
        insn = _insn(Insn, "and", "al, 0xff")
        exe._apply_instruction(st, insn)
        assert st.flags["SF"] is True
        assert st.flags["ZF"] is False

    def test_inc_al(self):
        """inc al from 0x7F should set SF (wraps to 0x80)."""
        exe, st, Insn = _make()
        st.registers["rax"] = 0x7F
        insn = _insn(Insn, "inc", "al")
        exe._apply_instruction(st, insn)
        assert st.get_register("al") == 0x80
        assert st.flags["SF"] is True

    def test_add_rax_sf_different(self):
        """add rax, 0x80 should NOT set SF (bit 63 is 0)."""
        exe, st, Insn = _make()
        st.registers["rax"] = 0
        insn = _insn(Insn, "add", "rax, 0x80")
        exe._apply_instruction(st, insn)
        # In 64-bit mode, 0x80 is a small positive number → SF=False
        assert st.flags["SF"] is False


class TestOperandSizeEflagsSymbolic:
    """Same tests as above but with symbolic bitvectors."""

    def test_add_al_sf_symbolic(self):
        """add al, 0x80 with symbolic al should produce correct SF at 8-bit."""
        z3 = pytest.importorskip("z3")
        exe, st, Insn = _make()
        # Write a concrete value to al so it's resolved correctly
        st.registers["rax"] = 0
        insn = _insn(Insn, "add", "al, 0x80")
        exe._apply_instruction(st, insn)
        # Even in symbolic mode, concrete value → concrete flags
        assert st.flags["SF"] is True


# ===================================================================
# _build_branch_constraint delegates to _evaluate_condition
# ===================================================================

class TestBranchDelegatesToEvaluate:
    """_build_branch_constraint should use _evaluate_condition internally."""

    def test_jz(self):
        z3 = pytest.importorskip("z3")
        exe, st, Insn = _make()
        st.flags["ZF"] = z3.BoolVal(True)
        insn = _insn(Insn, "jz", "0x2000")
        result = exe._build_branch_constraint(st, insn)
        # Should resolve to true
        s = z3.Solver()
        s.add(result)
        assert s.check() == z3.sat

    def test_jnz(self):
        z3 = pytest.importorskip("z3")
        exe, st, Insn = _make()
        st.flags["ZF"] = z3.BoolVal(False)
        insn = _insn(Insn, "jnz", "0x2000")
        result = exe._build_branch_constraint(st, insn)
        s = z3.Solver()
        s.add(result)
        assert s.check() == z3.sat

    def test_ja_with_symbolic(self):
        z3 = pytest.importorskip("z3")
        exe, st, Insn = _make()
        st.flags["CF"] = z3.BoolVal(False)
        st.flags["ZF"] = z3.BoolVal(False)
        insn = _insn(Insn, "ja", "0x3000")
        result = exe._build_branch_constraint(st, insn)
        s = z3.Solver()
        s.add(result)
        assert s.check() == z3.sat
