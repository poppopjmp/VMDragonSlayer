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
        assert st.read_memory(addr, 8) == 0xBEEF

    def test_mov_memory_sib_read(self):
        """mov rdx, [rax+rbx*4+0x8] should read from computed address."""
        exe, st, Insn = self._make()
        st.registers["rax"] = 0x2000
        st.registers["rbx"] = 2
        target_addr = 0x2000 + 2 * 4 + 0x8
        st.write_memory(target_addr, 0xCAFE, size=8)
        insn = self._insn(Insn, "mov", "rdx, [rax+rbx*4+0x8]", size=7)
        exe._apply_instruction(st, insn)
        assert st.registers["rdx"] == 0xCAFE

    def test_resolve_operand_size_prefix(self):
        """dword ptr [rsp+0x8] should resolve correctly."""
        exe, st, Insn = self._make()
        st.registers["rsp"] = 0x7FFF0000
        st.write_memory(0x7FFF0008, 42, size=4)
        val = exe._resolve_operand(st, "dword ptr [rsp+0x8]")
        assert val == 42

    def test_write_operand_size_prefix(self):
        """Writing to dword ptr [rsp+0x10] should work."""
        exe, st, Insn = self._make()
        st.registers["rsp"] = 0x7FFF0000
        exe._write_operand(st, "dword ptr [rsp+0x10]", 99)
        # With byte-granular memory, value 99 is split into bytes
        assert st.read_memory(0x7FFF0010, 8) == 99


# ---------------------------------------------------------------------------
# Multi-byte memory model
# ---------------------------------------------------------------------------

class TestMultiByteMemory:
    """Test read_memory / write_memory with byte-granular storage."""

    def _make_state(self, arch="x86_64", bw=64):
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        s = SymbolicState(arch=arch, bit_width=bw)
        for reg in list(s.registers):
            s.registers[reg] = 0
        return s

    def test_write_read_4bytes(self):
        s = self._make_state()
        s.write_memory(0x1000, 0xDEADBEEF, size=4)
        assert s.read_memory(0x1000, 4) == 0xDEADBEEF

    def test_write_read_8bytes(self):
        s = self._make_state()
        s.write_memory(0x2000, 0x0102030405060708, size=8)
        assert s.read_memory(0x2000, 8) == 0x0102030405060708

    def test_write_read_1byte(self):
        s = self._make_state()
        s.write_memory(0x3000, 0xAB, size=1)
        assert s.read_memory(0x3000, 1) == 0xAB

    def test_write_read_2bytes(self):
        s = self._make_state()
        s.write_memory(0x4000, 0xCAFE, size=2)
        assert s.read_memory(0x4000, 2) == 0xCAFE

    def test_byte_granularity(self):
        """Individual bytes should be stored separately."""
        s = self._make_state()
        s.write_memory(0x1000, 0x04030201, size=4)
        # Little-endian: byte at 0x1000 = 0x01
        assert s.memory.get(0x1000) == 0x01
        assert s.memory.get(0x1001) == 0x02
        assert s.memory.get(0x1002) == 0x03
        assert s.memory.get(0x1003) == 0x04

    def test_partial_read(self):
        """Reading fewer bytes than written should return the low portion."""
        s = self._make_state()
        s.write_memory(0x1000, 0xDEADBEEF, size=4)
        # Low 2 bytes = 0xBEEF
        assert s.read_memory(0x1000, 2) == 0xBEEF

    def test_overlapping_write(self):
        """A second write should overwrite only the affected bytes."""
        s = self._make_state()
        s.write_memory(0x1000, 0xAAAABBBB, size=4)
        # Overwrite just the low 2 bytes
        s.write_memory(0x1000, 0xCCDD, size=2)
        # Result should have low 2 bytes replaced
        assert s.read_memory(0x1000, 4) == 0xAAAACCDD

    def test_read_uninitialized_returns_zero_no_z3(self):
        """Reading uninitialised memory without z3 should return 0."""
        from dragonslayer.analysis.symbolic_execution import state as st_mod
        original = st_mod._Z3_AVAILABLE
        try:
            st_mod._Z3_AVAILABLE = False
            s = self._make_state()
            val = s.read_memory(0xDEAD, 4)
            assert val == 0
        finally:
            st_mod._Z3_AVAILABLE = original

    def test_symbolic_write_read(self):
        """z3 symbolic values should round-trip through byte store."""
        try:
            import z3
        except ImportError:
            pytest.skip("z3 not available")
        s = self._make_state()
        sym = z3.BitVecVal(0xCAFEBABE, 32)
        s.write_memory(0x5000, sym, size=4)
        result = s.read_memory(0x5000, 4)
        # Should simplify back to 0xCAFEBABE
        assert z3.simplify(result == z3.BitVecVal(0xCAFEBABE, 32))

    def test_memory_log_records(self):
        s = self._make_state()
        s.write_memory(0x1000, 42, size=4)
        s.write_memory(0x2000, 99, size=8)
        assert len(s._memory_log) == 2
        assert s._memory_log[0].address == 0x1000
        assert s._memory_log[0].size == 4
        assert s._memory_log[1].size == 8

    def test_fork_preserves_memory(self):
        s = self._make_state()
        s.write_memory(0x1000, 0xBEEF, size=2)
        s2 = s.fork()
        assert s2.read_memory(0x1000, 2) == 0xBEEF
        # Writes to fork don't affect original
        s2.write_memory(0x1000, 0xDEAD, size=2)
        assert s.read_memory(0x1000, 2) == 0xBEEF
        assert s2.read_memory(0x1000, 2) == 0xDEAD


# ---------------------------------------------------------------------------
# INC/DEC CF preservation bug fix
# ---------------------------------------------------------------------------

class TestIncDecCFPreservation:
    """Verify that INC/DEC does NOT modify the carry flag."""

    def _make_state(self):
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState
        s = SymbolicState(arch="x86_64", bit_width=64)
        for reg in list(s.registers):
            s.registers[reg] = 0
        return s

    def test_inc_preserves_cf_concrete(self):
        s = self._make_state()
        s.flags["CF"] = True
        s.registers["rax"] = 5
        result = 6
        s.update_flags_inc_dec(result, 5, is_dec=False)
        # CF must remain True
        assert s.flags["CF"] is True

    def test_dec_preserves_cf_concrete(self):
        s = self._make_state()
        s.flags["CF"] = False
        s.registers["rax"] = 5
        result = 4
        s.update_flags_inc_dec(result, 5, is_dec=True)
        assert s.flags["CF"] is False

    def test_inc_sets_zf_correctly(self):
        s = self._make_state()
        s.flags["CF"] = True
        # INC from max → 0
        result = 0
        original = 0xFFFFFFFF_FFFFFFFF
        s.update_flags_inc_dec(result, original, is_dec=False)
        # ZF should be set (result is 0)
        assert s.flags["ZF"] is True or s.flags["ZF"] == True
        # CF must still be True
        assert s.flags["CF"] is True

    def test_executor_inc_preserves_cf(self):
        """Integration test: INC via executor should preserve CF."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
        from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction
        from dragonslayer.analysis.symbolic_execution.state import SymbolicState

        exe = SymbolicExecutor(arch="x86_64")
        st = SymbolicState(arch="x86_64")
        for reg in list(st.registers):
            st.registers[reg] = 0
        st.registers["rax"] = 10
        st.flags["CF"] = True

        insn = LiftedInstruction(
            address=0, mnemonic="inc", operands="rax", size=3,
            category="arithmetic", raw_bytes=b"\x48\xFF\xC0",
        )
        exe._apply_instruction(st, insn)
        assert st.registers["rax"] == 11
        assert st.flags["CF"] is True
