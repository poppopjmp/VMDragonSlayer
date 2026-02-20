"""
Phase 10 — Sub-register aliasing, SIB addressing, and memory model tests.
"""

import pytest

# ---------------------------------------------------------------------------
# Sub-register aliasing in SymbolicState
# ---------------------------------------------------------------------------

class TestSubregisterAliasing:
    """Test that get_register / set_register handle x86 sub-register aliasing."""

    def _make_state(self, arch="x86_64", bw=64):
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        s = SymbolicState(arch=arch, bit_width=bw)
        # Seed with concrete values so we can verify bit manipulation
        for reg in list(s.registers):
            s.registers[reg] = 0
        return s

    # -- basic 64-bit aliasing ---

    def test_al_reads_low_byte_of_rax(self):
        s = self._make_state()
        s.registers["rax"] = 0xDEADBEEF_12345678
        assert s.get_register("al") == 0x78

    def test_ah_reads_second_byte_of_rax(self):
        s = self._make_state()
        s.registers["rax"] = 0xDEADBEEF_12345678
        assert s.get_register("ah") == 0x56

    def test_ax_reads_low_word_of_rax(self):
        s = self._make_state()
        s.registers["rax"] = 0xDEADBEEF_12345678
        assert s.get_register("ax") == 0x5678

    def test_eax_reads_low_dword_of_rax(self):
        s = self._make_state()
        s.registers["rax"] = 0xDEADBEEF_12345678
        assert s.get_register("eax") == 0x12345678

    # -- writes ---

    def test_set_al_preserves_upper_bits(self):
        s = self._make_state()
        s.registers["rax"] = 0xDEADBEEF_12345678
        s.set_register("al", 0xAA)
        # Only low byte changed
        assert s.registers["rax"] == 0xDEADBEEF_123456AA

    def test_set_ah_preserves_other_bits(self):
        s = self._make_state()
        s.registers["rax"] = 0xDEADBEEF_12345678
        s.set_register("ah", 0xBB)
        # byte at bits [15:8] changed
        assert s.registers["rax"] == 0xDEADBEEF_1234BB78

    def test_set_ax_preserves_upper_48(self):
        s = self._make_state()
        s.registers["rax"] = 0xDEADBEEF_12345678
        s.set_register("ax", 0xAAAA)
        assert s.registers["rax"] == 0xDEADBEEF_1234AAAA

    def test_set_eax_zero_extends(self):
        """Writing EAX on x64 zeros the top 32 bits (x86-64 zero-extension rule)."""
        s = self._make_state()
        s.registers["rax"] = 0xDEADBEEF_12345678
        s.set_register("eax", 0xCAFEBABE)
        assert s.registers["rax"] == 0x00000000_CAFEBABE

    # -- r8-r15 extended registers ---

    def test_r8b_reads_low_byte(self):
        s = self._make_state()
        s.registers["r8"] = 0xABCD
        assert s.get_register("r8b") == 0xCD

    def test_r8w_reads_low_word(self):
        s = self._make_state()
        s.registers["r8"] = 0x12345678
        assert s.get_register("r8w") == 0x5678

    def test_r8d_reads_low_dword(self):
        s = self._make_state()
        s.registers["r8"] = 0xDEADBEEF_12345678
        assert s.get_register("r8d") == 0x12345678

    def test_set_r8d_zero_extends(self):
        s = self._make_state()
        s.registers["r8"] = 0xFFFFFFFF_FFFFFFFF
        s.set_register("r8d", 0x42)
        assert s.registers["r8"] == 0x42

    def test_set_r10b_preserves_upper(self):
        s = self._make_state()
        s.registers["r10"] = 0x1234
        s.set_register("r10b", 0xFF)
        assert s.registers["r10"] == 0x12FF

    # -- special byte registers sil, dil, bpl, spl ---

    def test_sil_reads_low_byte_of_rsi(self):
        s = self._make_state()
        s.registers["rsi"] = 0xABCD
        assert s.get_register("sil") == 0xCD

    def test_set_spl(self):
        s = self._make_state()
        s.registers["rsp"] = 0x7FFF_0100
        s.set_register("spl", 0x42)
        assert s.get_register("spl") == 0x42
        # Upper bits preserved
        assert (s.registers["rsp"] & 0xFFFFFF00) == 0x7FFF_0100 & 0xFFFFFF00

    # -- 32-bit mode ---

    def test_32bit_al_reads_from_eax(self):
        s = self._make_state(arch="x86", bw=32)
        s.registers["eax"] = 0x12345678
        assert s.get_register("al") == 0x78

    def test_32bit_set_al(self):
        s = self._make_state(arch="x86", bw=32)
        s.registers["eax"] = 0x12345678
        s.set_register("al", 0xAA)
        assert s.registers["eax"] == 0x123456AA

    def test_32bit_ax(self):
        s = self._make_state(arch="x86", bw=32)
        s.registers["eax"] = 0x12345678
        assert s.get_register("ax") == 0x5678

    # -- unknown register returns 0 ---

    def test_unknown_register_returns_zero(self):
        s = self._make_state()
        assert s.get_register("xmm0") == 0

    # -- _subreg_info helper ---

    def test_subreg_info_known(self):
        s = self._make_state()
        info = s._subreg_info("al")
        assert info is not None
        parent, bit_lo, width, zero_ext = info
        assert parent == "rax"
        assert bit_lo == 0
        assert width == 8
        assert zero_ext is False

    def test_subreg_info_unknown(self):
        s = self._make_state()
        assert s._subreg_info("rax") is None
        assert s._subreg_info("xmm0") is None

    # -- z3 symbolic sub-register (if z3 available) ---

    def test_symbolic_al_extract(self):
        """If rax is symbolic, get_register('al') should return z3.Extract(7,0,rax)."""
        try:
            import z3
        except ImportError:
            pytest.skip("z3 not available")
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        s = SymbolicState(arch="x86_64")
        # rax is symbolic by default
        al_val = s.get_register("al")
        assert hasattr(al_val, "sort")
        assert al_val.sort().size() == 8

    def test_symbolic_eax_extract(self):
        try:
            import z3
        except ImportError:
            pytest.skip("z3 not available")
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        s = SymbolicState(arch="x86_64")
        eax_val = s.get_register("eax")
        assert hasattr(eax_val, "sort")
        assert eax_val.sort().size() == 32


# ---------------------------------------------------------------------------
# SIB addressing in SymbolicExecutor
# ---------------------------------------------------------------------------

class TestSIBAddressing:
    """Test _resolve_sib_address for various addressing modes."""

    def _make_executor_and_state(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        exe = SymbolicExecutor(arch="x86_64")
        state = SymbolicState(arch="x86_64")
        # Concrete register values for testing
        for reg in list(state.registers):
            state.registers[reg] = 0
        return exe, state

    def test_simple_register(self):
        exe, st = self._make_executor_and_state()
        st.registers["rax"] = 0x1000
        addr = exe._resolve_sib_address(st, "rax")
        assert addr == 0x1000

    def test_reg_plus_imm(self):
        exe, st = self._make_executor_and_state()
        st.registers["rsp"] = 0x7FFF0000
        addr = exe._resolve_sib_address(st, "rsp+0x8")
        assert addr == 0x7FFF0008

    def test_reg_minus_imm(self):
        exe, st = self._make_executor_and_state()
        st.registers["rbp"] = 0x1000
        addr = exe._resolve_sib_address(st, "rbp-0x10")
        assert addr == 0x1000 - 0x10

    def test_reg_plus_reg(self):
        exe, st = self._make_executor_and_state()
        st.registers["rax"] = 0x1000
        st.registers["rbx"] = 0x200
        addr = exe._resolve_sib_address(st, "rax+rbx")
        assert addr == 0x1200

    def test_base_plus_index_times_scale(self):
        exe, st = self._make_executor_and_state()
        st.registers["rax"] = 0x1000
        st.registers["rcx"] = 5
        addr = exe._resolve_sib_address(st, "rax+rcx*4")
        assert addr == 0x1000 + 5 * 4

    def test_base_plus_index_times_scale_plus_disp(self):
        exe, st = self._make_executor_and_state()
        st.registers["rbx"] = 0x2000
        st.registers["rsi"] = 3
        addr = exe._resolve_sib_address(st, "rbx+rsi*8+0x10")
        assert addr == 0x2000 + 3 * 8 + 0x10

    def test_base_plus_index_times_scale_minus_disp(self):
        exe, st = self._make_executor_and_state()
        st.registers["rax"] = 0x3000
        st.registers["rcx"] = 2
        addr = exe._resolve_sib_address(st, "rax+rcx*4-0x8")
        assert addr == 0x3000 + 2 * 4 - 0x8

    def test_absolute_address(self):
        exe, st = self._make_executor_and_state()
        addr = exe._resolve_sib_address(st, "0x401000")
        assert addr == 0x401000

    def test_empty_inner(self):
        exe, st = self._make_executor_and_state()
        addr = exe._resolve_sib_address(st, "")
        assert addr == 0


# ---------------------------------------------------------------------------
# Instruction-level integration: sub-regs + SIB through _apply_instruction
# ---------------------------------------------------------------------------

class TestInstructionIntegration:
    """Test that _apply_instruction correctly uses sub-registers and SIB."""

    def _make(self):
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        exe = SymbolicExecutor(arch="x86_64")
        state = SymbolicState(arch="x86_64")
        for reg in list(state.registers):
            state.registers[reg] = 0
        return exe, state, LiftedInstruction

    def _insn(self, Insn, mnemonic, operands, size=2):
        return Insn(
            address=0, mnemonic=mnemonic, operands=operands, size=size,
            category="data", raw_bytes=b"\x90" * size,
        )

    def test_mov_al_imm(self):
        exe, st, Insn = self._make()
        st.registers["rax"] = 0xFFFFFFFF_00000000
        insn = self._insn(Insn, "mov", "al, 0x42")
        exe._apply_instruction(st, insn)
        assert st.get_register("al") == 0x42
        # Upper bits preserved (al write does NOT zero-extend)
        assert (st.registers["rax"] >> 8) == (0xFFFFFFFF_00000000 >> 8)

    def test_mov_eax_zero_extends(self):
        exe, st, Insn = self._make()
        st.registers["rax"] = 0xFFFFFFFF_FFFFFFFF
        insn = self._insn(Insn, "mov", "eax, 0x1", size=5)
        exe._apply_instruction(st, insn)
        # eax write on x64 zero-extends to rax
        assert st.registers["rax"] == 1

    def test_add_cl_imm(self):
        exe, st, Insn = self._make()
        st.registers["rcx"] = 0x100
        insn = self._insn(Insn, "add", "cl, 0x5", size=3)
        exe._apply_instruction(st, insn)
        assert st.get_register("cl") == 0x5
        # Upper bits preserved
        assert (st.registers["rcx"] & 0xFF00) == 0x100

    def test_lea_sib(self):
        """LEA rax, [rbx+rcx*4+0x10] should compute address without deref."""
        exe, st, Insn = self._make()
        st.registers["rbx"] = 0x2000
        st.registers["rcx"] = 3
        insn = self._insn(Insn, "lea", "rax, [rbx+rcx*4+0x10]", size=7)
        exe._apply_instruction(st, insn)
        assert st.registers["rax"] == 0x2000 + 3 * 4 + 0x10

    def test_mov_memory_sib_write(self):
        """mov [rax+rbx*2], rcx should write rcx to computed address."""
        exe, st, Insn = self._make()
        st.registers["rax"] = 0x1000
        st.registers["rbx"] = 5
        st.registers["rcx"] = 0xBEEF
        insn = self._insn(Insn, "mov", "[rax+rbx*2], rcx", size=3)
        exe._apply_instruction(st, insn)
        addr = 0x1000 + 5 * 2
        assert st.memory.get(addr) == 0xBEEF

    def test_mov_memory_sib_read(self):
        """mov rdx, [rax+rbx*4+0x8] should read from computed address."""
        exe, st, Insn = self._make()
        st.registers["rax"] = 0x2000
        st.registers["rbx"] = 2
        target_addr = 0x2000 + 2 * 4 + 0x8
        st.memory[target_addr] = 0xCAFE
        insn = self._insn(Insn, "mov", "rdx, [rax+rbx*4+0x8]", size=7)
        exe._apply_instruction(st, insn)
        assert st.registers["rdx"] == 0xCAFE

    def test_resolve_operand_size_prefix(self):
        """dword ptr [rsp+0x8] should resolve correctly."""
        exe, st, Insn = self._make()
        st.registers["rsp"] = 0x7FFF0000
        st.memory[0x7FFF0008] = 42
        val = exe._resolve_operand(st, "dword ptr [rsp+0x8]")
        assert val == 42

    def test_write_operand_size_prefix(self):
        """Writing to dword ptr [rsp+0x10] should work."""
        exe, st, Insn = self._make()
        st.registers["rsp"] = 0x7FFF0000
        exe._write_operand(st, "dword ptr [rsp+0x10]", 99)
        assert st.memory.get(0x7FFF0010) == 99
