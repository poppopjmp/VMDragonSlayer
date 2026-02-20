"""Tests for VMProtect-specific dispatcher identification.

Tests the pattern-matching logic in
:mod:`dragonslayer.analysis.vm_discovery.dispatcher` that identifies
the canonical VMProtect fetch→decode→advance→dispatch cycle.
"""

import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import pytest

from dragonslayer.analysis.vm_discovery.dispatcher import (
    VMProtectDispatcherMatch,
    find_vmprotect_dispatcher,
    find_dispatcher_in_trace,
    _find_fetch_candidates,
    _find_advance_candidates,
    _find_dispatch_candidates,
    _find_decode_candidates,
    _score_dispatcher_candidate,
    _extract_handler_table_binary,
    _extract_handlers_from_trace_visits,
    _identify_vip_from_trace_registers,
    _GP_REGS_64,
    _GP_REGS_32,
    _GP_ALL_WIDTHS_64,
)


# ── Pseudo-instruction helper ──────────────────────────────────────────────

@dataclass
class FakeInsn:
    """Lightweight instruction-like object for testing."""
    address: int = 0
    mnemonic: str = ""
    operands: str = ""
    is_branch: bool = False
    branch_target: Optional[int] = None
    category: str = "unknown"
    size: int = 1
    reads: List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)


def _make_vmprotect_dispatcher_insns(
    *,
    vip_reg: str = "rsi",
    fetch_reg: str = "ecx",
    table_reg: str = "r12",
    fetch_width: str = "byte",
    decode_key: int = 0,
    advance_delta: int = 1,
    base_addr: int = 0x401000,
) -> List[FakeInsn]:
    """Build a synthetic VMProtect dispatcher instruction sequence.

    Generates the canonical pattern::

        movzx fetch_reg, <width> ptr [vip_reg]      ; opcode fetch
        {xor fetch_reg, key}                          ; optional decode
        {add|inc} vip_reg, delta                      ; vIP advance
        jmp qword ptr [table_reg + fetch_reg * 8]    ; dispatch
    """
    insns: List[FakeInsn] = []
    addr = base_addr

    # ── Fetch instruction ──
    fetch_src = f"{fetch_width} ptr [{vip_reg}]"
    insns.append(FakeInsn(
        address=addr, mnemonic="movzx", operands=f"{fetch_reg}, {fetch_src}",
        reads=[vip_reg], writes=[fetch_reg], size=4,
    ))
    addr += 4

    # ── Optional decode (XOR with key) ──
    if decode_key:
        insns.append(FakeInsn(
            address=addr, mnemonic="xor", operands=f"{fetch_reg}, {hex(decode_key)}",
            reads=[fetch_reg], writes=[fetch_reg], size=3,
        ))
        addr += 3

    # ── vIP advance ──
    if advance_delta == 1:
        insns.append(FakeInsn(
            address=addr, mnemonic="inc", operands=vip_reg,
            reads=[vip_reg], writes=[vip_reg], size=3,
        ))
    elif advance_delta == -1:
        insns.append(FakeInsn(
            address=addr, mnemonic="dec", operands=vip_reg,
            reads=[vip_reg], writes=[vip_reg], size=3,
        ))
    elif advance_delta > 0:
        insns.append(FakeInsn(
            address=addr, mnemonic="add", operands=f"{vip_reg}, {advance_delta}",
            reads=[vip_reg], writes=[vip_reg], size=4,
        ))
    else:
        insns.append(FakeInsn(
            address=addr, mnemonic="sub", operands=f"{vip_reg}, {abs(advance_delta)}",
            reads=[vip_reg], writes=[vip_reg], size=4,
        ))
    addr += 4

    # ── Dispatch ──
    # Use the wide register name for the scale operand
    wide_fetch = fetch_reg
    if fetch_reg.startswith("e"):
        # 32-bit register in table lookup — use the 64-bit parent
        wide_fetch = "r" + fetch_reg[1:]
    insns.append(FakeInsn(
        address=addr, mnemonic="jmp",
        operands=f"qword ptr [{table_reg}+{wide_fetch}*8]",
        is_branch=True, branch_target=None,
        reads=[table_reg, wide_fetch], size=4,
    ))
    addr += 4

    return insns


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Candidate Extraction
# ═══════════════════════════════════════════════════════════════════════════

class TestFetchCandidates:
    """Test opcode-fetch candidate extraction."""

    def test_movzx_byte_ptr(self):
        insns = [FakeInsn(address=0, mnemonic="movzx", operands="ecx, byte ptr [rsi]")]
        cands = _find_fetch_candidates(insns, _GP_REGS_64)
        assert len(cands) == 1
        assert cands[0].vip_reg == "rsi"
        assert cands[0].fetch_reg == "ecx"
        assert cands[0].width == 1

    def test_movzx_word_ptr(self):
        insns = [FakeInsn(address=0, mnemonic="movzx", operands="ecx, word ptr [rdi]")]
        cands = _find_fetch_candidates(insns, _GP_REGS_64)
        assert len(cands) == 1
        assert cands[0].vip_reg == "rdi"
        assert cands[0].width == 2

    def test_mov_with_mem_deref(self):
        insns = [FakeInsn(address=0, mnemonic="mov", operands="cl, byte ptr [rbx]")]
        cands = _find_fetch_candidates(insns, _GP_REGS_64)
        assert len(cands) == 1
        assert cands[0].vip_reg == "rbx"
        assert cands[0].width == 1

    def test_no_memory_deref_ignored(self):
        insns = [FakeInsn(address=0, mnemonic="movzx", operands="ecx, dl")]
        cands = _find_fetch_candidates(insns, _GP_REGS_64)
        assert len(cands) == 0

    def test_32bit_registers(self):
        insns = [FakeInsn(address=0, mnemonic="movzx", operands="ecx, byte ptr [esi]")]
        cands = _find_fetch_candidates(insns, _GP_REGS_32)
        assert len(cands) == 1
        assert cands[0].vip_reg == "esi"

    def test_reg_plus_displacement(self):
        """Fetch like movzx ecx, byte ptr [rsi+0x10] should still detect rsi."""
        insns = [FakeInsn(address=0, mnemonic="movzx", operands="ecx, byte ptr [rsi+0x10]")]
        cands = _find_fetch_candidates(insns, _GP_REGS_64)
        assert len(cands) == 1
        assert cands[0].vip_reg == "rsi"


class TestAdvanceCandidates:
    """Test vIP-advance candidate extraction."""

    def test_inc_register(self):
        insns = [FakeInsn(address=0, mnemonic="inc", operands="rsi")]
        cands = _find_advance_candidates(insns, _GP_REGS_64)
        assert len(cands) == 1
        assert cands[0].reg == "rsi"
        assert cands[0].delta == 1

    def test_dec_register(self):
        insns = [FakeInsn(address=0, mnemonic="dec", operands="rdi")]
        cands = _find_advance_candidates(insns, _GP_REGS_64)
        assert len(cands) == 1
        assert cands[0].delta == -1

    def test_add_immediate(self):
        insns = [FakeInsn(address=0, mnemonic="add", operands="rsi, 2")]
        cands = _find_advance_candidates(insns, _GP_REGS_64)
        assert len(cands) == 1
        assert cands[0].delta == 2

    def test_sub_immediate(self):
        insns = [FakeInsn(address=0, mnemonic="sub", operands="rsi, 1")]
        cands = _find_advance_candidates(insns, _GP_REGS_64)
        assert len(cands) == 1
        assert cands[0].delta == -1

    def test_lea_advance(self):
        insns = [FakeInsn(address=0, mnemonic="lea", operands="rsi, [rsi+2]")]
        cands = _find_advance_candidates(insns, _GP_REGS_64)
        assert len(cands) == 1
        assert cands[0].delta == 2

    def test_large_delta_rejected(self):
        """Delta > 8 should not be considered a vIP advance."""
        insns = [FakeInsn(address=0, mnemonic="add", operands="rsi, 100")]
        cands = _find_advance_candidates(insns, _GP_REGS_64)
        assert len(cands) == 0

    def test_non_gp_register_ignored(self):
        insns = [FakeInsn(address=0, mnemonic="inc", operands="rsp")]
        cands = _find_advance_candidates(insns, _GP_REGS_64)
        assert len(cands) == 0  # rsp not in _GP_REGS_64


class TestDispatchCandidates:
    """Test dispatch (indirect jump) candidate extraction."""

    def test_jmp_register(self):
        insns = [FakeInsn(address=0, mnemonic="jmp", operands="rax", is_branch=True)]
        cands = _find_dispatch_candidates(insns, _GP_REGS_64)
        assert len(cands) == 1
        assert cands[0].target_reg == "rax"
        assert not cands[0].uses_memory

    def test_jmp_memory_indirect(self):
        insns = [FakeInsn(
            address=0, mnemonic="jmp",
            operands="qword ptr [r12+rcx*8]", is_branch=True,
        )]
        cands = _find_dispatch_candidates(insns, _GP_REGS_64)
        assert len(cands) == 1
        assert cands[0].uses_memory

    def test_jmp_with_table_scale(self):
        insns = [FakeInsn(
            address=0, mnemonic="jmp",
            operands="[rbx+rax*4]", is_branch=True,
        )]
        cands = _find_dispatch_candidates(insns, _GP_REGS_64)
        assert len(cands) == 1
        assert "rax*4" in cands[0].table_base_expr

    def test_direct_jmp_ignored(self):
        """A direct jmp with a concrete target should NOT be a dispatch candidate."""
        insns = [FakeInsn(
            address=0, mnemonic="jmp", operands="0x401000",
            is_branch=True, branch_target=0x401000,
        )]
        cands = _find_dispatch_candidates(insns, _GP_REGS_64)
        assert len(cands) == 0


class TestDecodeCandidates:
    """Test opcode decode/transform candidate extraction."""

    def test_xor_decode(self):
        insns = [FakeInsn(address=0, mnemonic="xor", operands="ecx, 0x37")]
        cands = _find_decode_candidates(insns, _GP_ALL_WIDTHS_64)
        assert len(cands) == 1
        assert cands[0].operation == "xor"

    def test_not_decode(self):
        insns = [FakeInsn(address=0, mnemonic="not", operands="ecx")]
        cands = _find_decode_candidates(insns, _GP_ALL_WIDTHS_64)
        assert len(cands) == 1
        assert cands[0].operation == "not"

    def test_non_decode_mnemonic_ignored(self):
        insns = [FakeInsn(address=0, mnemonic="mov", operands="ecx, eax")]
        cands = _find_decode_candidates(insns, _GP_REGS_64)
        assert len(cands) == 0


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Scoring
# ═══════════════════════════════════════════════════════════════════════════

class TestDispatcherScoring:
    """Test the scoring algorithm for (fetch, dispatch) pairs."""

    def test_canonical_vmprotect_pattern_high_score(self):
        """Full VMProtect dispatcher pattern should score >= 0.6."""
        insns = _make_vmprotect_dispatcher_insns()
        fetches = _find_fetch_candidates(insns, _GP_REGS_64)
        advances = _find_advance_candidates(insns, _GP_REGS_64)
        dispatches = _find_dispatch_candidates(insns, _GP_REGS_64)
        decodes = _find_decode_candidates(insns, _GP_REGS_64)

        assert len(fetches) >= 1
        assert len(dispatches) >= 1

        score, info = _score_dispatcher_candidate(
            fetches[0], dispatches[0], advances, decodes,
            insns, _GP_REGS_64, 64, None, 0,
        )
        assert score >= 0.6
        assert info is not None
        assert info.vip_register == "rsi"
        assert info.fetch_register == "ecx"

    def test_with_decode_key_scores_higher(self):
        """Adding a decode XOR should increase the score."""
        insns_plain = _make_vmprotect_dispatcher_insns(decode_key=0)
        insns_decode = _make_vmprotect_dispatcher_insns(decode_key=0x37)

        def _score(insns):
            f = _find_fetch_candidates(insns, _GP_REGS_64)
            a = _find_advance_candidates(insns, _GP_REGS_64)
            d = _find_dispatch_candidates(insns, _GP_REGS_64)
            dc = _find_decode_candidates(insns, _GP_REGS_64)
            s, _ = _score_dispatcher_candidate(f[0], d[0], a, dc, insns, _GP_REGS_64, 64, None, 0)
            return s

        score_plain = _score(insns_plain)
        score_decode = _score(insns_decode)
        assert score_decode >= score_plain

    def test_fetch_after_dispatch_scores_zero(self):
        """If fetch comes after dispatch, score should be zero."""
        insns = [
            FakeInsn(address=0, mnemonic="jmp", operands="rax", is_branch=True),
            FakeInsn(address=4, mnemonic="movzx", operands="ecx, byte ptr [rsi]"),
        ]
        f = _find_fetch_candidates(insns, _GP_REGS_64)
        d = _find_dispatch_candidates(insns, _GP_REGS_64)
        assert f and d
        score, info = _score_dispatcher_candidate(f[0], d[0], [], [], insns, _GP_REGS_64, 64, None, 0)
        assert score == 0.0
        assert info is None

    def test_backward_vip_advance(self):
        """VMProtect variants with backward vIP should still score well."""
        insns = _make_vmprotect_dispatcher_insns(advance_delta=-1)
        fetches = _find_fetch_candidates(insns, _GP_REGS_64)
        dispatches = _find_dispatch_candidates(insns, _GP_REGS_64)
        advances = _find_advance_candidates(insns, _GP_REGS_64)
        decodes = _find_decode_candidates(insns, _GP_REGS_64)
        score, info = _score_dispatcher_candidate(
            fetches[0], dispatches[0], advances, decodes,
            insns, _GP_REGS_64, 64, None, 0,
        )
        assert score >= 0.5
        assert info is not None
        assert info.vip_delta == -1

    def test_word_opcode_fetch(self):
        """2-byte opcode fetch (word ptr) should be detected."""
        insns = _make_vmprotect_dispatcher_insns(fetch_width="word", advance_delta=2)
        result = find_vmprotect_dispatcher(insns, bit_width=64)
        assert result is not None
        assert result.fetch_width == 2


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Full find_vmprotect_dispatcher
# ═══════════════════════════════════════════════════════════════════════════

class TestFindVMProtectDispatcher:
    """End-to-end tests for find_vmprotect_dispatcher."""

    def test_canonical_pattern(self):
        """Standard VMProtect dispatcher is detected with high confidence."""
        insns = _make_vmprotect_dispatcher_insns()
        result = find_vmprotect_dispatcher(insns, bit_width=64)
        assert result is not None
        assert isinstance(result, VMProtectDispatcherMatch)
        assert result.confidence >= 0.5
        assert result.vip_register == "rsi"
        assert result.fetch_register == "ecx"

    def test_with_handler_backedges(self):
        """Handlers jumping back to dispatcher boost confidence."""
        dispatcher = _make_vmprotect_dispatcher_insns(base_addr=0x401000)
        # Add some handler blocks that jump back to the dispatcher
        handler1 = [
            FakeInsn(address=0x402000, mnemonic="push", operands="rax"),
            FakeInsn(address=0x402001, mnemonic="add", operands="rax, rbx"),
            FakeInsn(address=0x402004, mnemonic="jmp", operands="0x401000",
                     is_branch=True, branch_target=0x401000),
        ]
        handler2 = [
            FakeInsn(address=0x403000, mnemonic="xor", operands="rax, rcx"),
            FakeInsn(address=0x403003, mnemonic="jmp", operands="0x401000",
                     is_branch=True, branch_target=0x401000),
        ]
        insns = dispatcher + handler1 + handler2
        result = find_vmprotect_dispatcher(insns, bit_width=64)
        assert result is not None
        assert result.confidence >= 0.6

    def test_32bit_mode(self):
        """32-bit VMProtect dispatcher detection."""
        insns = _make_vmprotect_dispatcher_insns(
            vip_reg="esi", fetch_reg="ecx", table_reg="ebx",
        )
        # Change the dispatch operand for 32-bit
        insns[-1] = FakeInsn(
            address=insns[-1].address, mnemonic="jmp",
            operands="dword ptr [ebx+ecx*4]",
            is_branch=True, branch_target=None,
        )
        result = find_vmprotect_dispatcher(insns, bit_width=32)
        assert result is not None
        assert result.vip_register == "esi"

    def test_empty_instructions_returns_none(self):
        assert find_vmprotect_dispatcher([], bit_width=64) is None

    def test_no_indirect_jump_returns_none(self):
        insns = [
            FakeInsn(address=0, mnemonic="movzx", operands="ecx, byte ptr [rsi]"),
            FakeInsn(address=4, mnemonic="inc", operands="rsi"),
            FakeInsn(address=8, mnemonic="mov", operands="rax, rcx"),
        ]
        assert find_vmprotect_dispatcher(insns, bit_width=64) is None

    def test_no_fetch_returns_none(self):
        insns = [
            FakeInsn(address=0, mnemonic="add", operands="rax, 1"),
            FakeInsn(address=4, mnemonic="jmp", operands="rax", is_branch=True),
        ]
        assert find_vmprotect_dispatcher(insns, bit_width=64) is None

    def test_different_vip_registers(self):
        """Test detection with various vIP register choices."""
        for vip in ("rdi", "rbp", "rbx", "r14"):
            insns = _make_vmprotect_dispatcher_insns(vip_reg=vip)
            result = find_vmprotect_dispatcher(insns, bit_width=64)
            assert result is not None, f"Failed to detect dispatcher with vIP={vip}"
            assert result.vip_register == vip

    def test_jmp_register_dispatch(self):
        """Test jmp reg dispatch (with preceding table load)."""
        insns = [
            FakeInsn(address=0, mnemonic="movzx", operands="ecx, byte ptr [rsi]"),
            FakeInsn(address=4, mnemonic="inc", operands="rsi"),
            FakeInsn(address=8, mnemonic="mov", operands="rax, qword ptr [r12+rcx*8]"),
            FakeInsn(address=12, mnemonic="jmp", operands="rax", is_branch=True),
        ]
        result = find_vmprotect_dispatcher(insns, bit_width=64)
        assert result is not None
        assert result.vip_register == "rsi"

    def test_to_dict_serialization(self):
        """VMProtectDispatcherMatch.to_dict() produces valid dict."""
        insns = _make_vmprotect_dispatcher_insns()
        result = find_vmprotect_dispatcher(insns, bit_width=64)
        assert result is not None
        d = result.to_dict()
        assert "vip_register" in d
        assert "fetch_register" in d
        assert "confidence" in d
        assert isinstance(d["handler_addresses"], list)

    def test_with_junk_instructions(self):
        """Dispatcher mixed with junk code should still be detected."""
        junk = [
            FakeInsn(address=0x400000 + i * 4, mnemonic="nop", operands="")
            for i in range(5)
        ]
        dispatcher = _make_vmprotect_dispatcher_insns(base_addr=0x400020)
        more_junk = [
            FakeInsn(address=0x400100 + i * 4, mnemonic="nop", operands="")
            for i in range(5)
        ]
        insns = junk + dispatcher + more_junk
        result = find_vmprotect_dispatcher(insns, bit_width=64)
        assert result is not None
        assert result.vip_register == "rsi"


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Handler table extraction from binary
# ═══════════════════════════════════════════════════════════════════════════

class TestHandlerTableExtraction:
    """Test binary handler table reading."""

    def test_extract_64bit_table(self):
        """Read 64-bit handler addresses from binary data."""
        base = 0x400000
        table_base = 0x401000
        handlers = [0x402000, 0x402100, 0x402200]
        table_data = b"".join(struct.pack("<Q", h) for h in handlers) + b"\x00" * 8
        # Pad binary so all handler addresses fall within [base, base+len)
        binary = b"\x00" * (table_base - base) + table_data + b"\x00" * 0x2000
        result = _extract_handler_table_binary(binary, base, table_base, 8, 64)
        assert result == handlers

    def test_extract_32bit_table(self):
        """Read 32-bit handler addresses from binary data."""
        base = 0x400000
        table_base = 0x401000
        handlers = [0x402000, 0x402100]
        table_data = b"".join(struct.pack("<I", h) for h in handlers) + b"\x00" * 4
        binary = b"\x00" * (table_base - base) + table_data + b"\x00" * 0x2000
        result = _extract_handler_table_binary(binary, base, table_base, 4, 32)
        assert result == handlers

    def test_null_terminated(self):
        """Table reading stops at null entry."""
        base = 0x400000
        table_base = 0x400000
        binary = struct.pack("<QQ", 0x401000, 0) + b"\x00" * 0x2000
        result = _extract_handler_table_binary(binary, base, table_base, 8, 64)
        assert result == [0x401000]

    def test_out_of_range_base(self):
        """If table_base is outside binary, return empty."""
        binary = b"\x00" * 100
        result = _extract_handler_table_binary(binary, 0x400000, 0x500000, 8, 64)
        assert result == []


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Trace-based dispatcher identification
# ═══════════════════════════════════════════════════════════════════════════

class TestTraceDispatcher:
    """Test dispatcher identification from execution traces."""

    def _make_trace(self, dispatch_addr=0x401010, handler_addrs=None, visits=5):
        """Build a synthetic trace with repeated dispatcher visits."""
        if handler_addrs is None:
            handler_addrs = [0x402000, 0x402100, 0x402200]
        records = []
        for visit in range(visits):
            # Dispatcher block
            records.append({
                "address": dispatch_addr - 8,
                "disassembly": "movzx ecx, byte ptr [rsi]",
                "registers": {"rsi": 0x500000 + visit, "rcx": visit % 3},
            })
            records.append({
                "address": dispatch_addr - 4,
                "disassembly": "inc rsi",
                "registers": {"rsi": 0x500001 + visit},
            })
            records.append({
                "address": dispatch_addr,
                "disassembly": f"jmp qword ptr [r12+rcx*8]",
                "registers": {"rsi": 0x500001 + visit, "rcx": visit % 3},
            })
            # Handler entry
            handler_addr = handler_addrs[visit % len(handler_addrs)]
            records.append({
                "address": handler_addr,
                "disassembly": "push rax",
            })
            records.append({
                "address": handler_addr + 4,
                "disassembly": f"jmp 0x{dispatch_addr - 8:x}",
            })
        return records

    def test_trace_dispatcher_found(self):
        """Dispatcher should be identified from repeated trace visits."""
        records = self._make_trace(visits=5)
        result = find_dispatcher_in_trace(records, bit_width=64)
        assert result is not None
        assert isinstance(result, VMProtectDispatcherMatch)
        assert result.confidence >= 0.3

    def test_trace_handler_addresses_extracted(self):
        """Handler addresses should be extracted from post-dispatch targets."""
        handler_addrs = [0x402000, 0x402100, 0x402200]
        records = self._make_trace(handler_addrs=handler_addrs, visits=6)
        result = find_dispatcher_in_trace(records, bit_width=64)
        assert result is not None
        for h in handler_addrs:
            assert h in result.handler_addresses

    def test_empty_trace(self):
        assert find_dispatcher_in_trace([], bit_width=64) is None

    def test_trace_too_few_visits(self):
        """Fewer than 3 visits → not enough evidence."""
        records = self._make_trace(visits=2)
        result = find_dispatcher_in_trace(records, bit_width=64)
        # May or may not find it with only 2 visits
        # The freq threshold is 3, so it should be None
        assert result is None

    def test_extract_handlers_from_trace_visits(self):
        """_extract_handlers_from_trace_visits collects post-dispatch addresses."""
        dispatch_addr = 0x401010
        records = [
            {"address": dispatch_addr},
            {"address": 0x402000},  # handler A
            {"address": dispatch_addr},
            {"address": 0x402100},  # handler B
            {"address": dispatch_addr},
            {"address": 0x402000},  # handler A again
        ]
        result = _extract_handlers_from_trace_visits(records, dispatch_addr)
        assert result == [0x402000, 0x402100]

    def test_identify_vip_monotonic(self):
        """vIP register identified by monotonically increasing values."""
        dispatch_addr = 0x401010
        records = [
            {"address": dispatch_addr, "registers": {"rsi": 100, "rax": 42}},
            {"address": 0x402000},
            {"address": dispatch_addr, "registers": {"rsi": 101, "rax": 99}},
            {"address": 0x402100},
            {"address": dispatch_addr, "registers": {"rsi": 102, "rax": 7}},
        ]
        reg = _identify_vip_from_trace_registers(records, dispatch_addr)
        assert reg == "rsi"


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Integration with SymbolicExecutor
# ═══════════════════════════════════════════════════════════════════════════

class TestExecutorIntegration:
    """Test that SymbolicExecutor uses the new dispatcher identification."""

    def test_execution_result_has_vmprotect_field(self):
        """ExecutionResult should have vmprotect_dispatcher field."""
        from dragonslayer.analysis.symbolic_execution.executor import ExecutionResult
        r = ExecutionResult(success=True)
        assert hasattr(r, "vmprotect_dispatcher")
        d = r.to_dict()
        assert "vmprotect_dispatcher" in d

    def test_vmprotect_dispatcher_match_to_dict_roundtrip(self):
        """VMProtectDispatcherMatch serializes and has all fields."""
        match = VMProtectDispatcherMatch(
            entry_address=0x401000,
            indirect_jump_address=0x401010,
            vip_register="rsi",
            fetch_register="ecx",
            fetch_width=1,
            table_base=0x500000,
            table_scale=8,
            vip_delta=1,
            handler_addresses=[0x402000, 0x402100],
            confidence=0.85,
            context_registers={"rsi": "vIP"},
            decode_transforms=["xor ecx, 0x37"],
        )
        d = match.to_dict()
        assert d["entry_address"] == 0x401000
        assert d["vip_register"] == "rsi"
        assert d["fetch_width"] == 1
        assert d["table_scale"] == 8
        assert len(d["handler_addresses"]) == 2
        assert d["confidence"] == 0.85
        assert len(d["decode_transforms"]) == 1


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Edge cases
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Edge cases and unusual patterns."""

    def test_multiple_fetches_picks_best(self):
        """When multiple fetch candidates exist, the best-scoring one wins."""
        insns = [
            # Decoy fetch using rbx
            FakeInsn(address=0, mnemonic="movzx", operands="edx, byte ptr [rbx]"),
            # Real dispatch loop
            FakeInsn(address=8, mnemonic="movzx", operands="ecx, byte ptr [rsi]"),
            FakeInsn(address=12, mnemonic="inc", operands="rsi"),
            FakeInsn(address=16, mnemonic="jmp",
                     operands="qword ptr [r12+rcx*8]", is_branch=True),
        ]
        result = find_vmprotect_dispatcher(insns, bit_width=64)
        assert result is not None
        # Should pick rsi as vIP (the one with advance + data flow)
        assert result.vip_register == "rsi"

    def test_lea_advance_variant(self):
        """LEA-based vIP advance (lea rsi, [rsi+1])."""
        insns = [
            FakeInsn(address=0, mnemonic="movzx", operands="ecx, byte ptr [rsi]"),
            FakeInsn(address=4, mnemonic="lea", operands="rsi, [rsi+1]"),
            FakeInsn(address=8, mnemonic="jmp",
                     operands="qword ptr [r12+rcx*8]", is_branch=True),
        ]
        result = find_vmprotect_dispatcher(insns, bit_width=64)
        assert result is not None
        assert result.vip_delta == 1

    def test_various_table_scales(self):
        """Test detection with different table scales (4, 8)."""
        for scale in (4, 8):
            insns = [
                FakeInsn(address=0, mnemonic="movzx", operands="ecx, byte ptr [rsi]"),
                FakeInsn(address=4, mnemonic="inc", operands="rsi"),
                FakeInsn(
                    address=8, mnemonic="jmp",
                    operands=f"qword ptr [r12+rcx*{scale}]", is_branch=True,
                ),
            ]
            result = find_vmprotect_dispatcher(insns, bit_width=64)
            assert result is not None, f"Failed with scale={scale}"
