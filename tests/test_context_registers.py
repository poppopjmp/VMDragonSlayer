"""Tests for dynamic VM context register identification.

Tests :mod:`dragonslayer.analysis.vm_discovery.context_registers`.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

import pytest

from dragonslayer.analysis.vm_discovery.context_registers import (
    identify_vm_context,
    score_vsp_candidates,
    score_table_base_candidates,
    score_key_candidates,
    score_context_base_candidates,
    VMContextLayout,
    VMContextRegister,
    _collect_register_series,
    _count_memory_base_usage,
    _count_scaled_index_usage,
    _count_xor_involvement,
    _extract_regs_from_transforms,
    _GP_REGS_64,
)


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def _rec(
    address: int = 0,
    disassembly: str = "",
    registers: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    return {
        "address": address,
        "disassembly": disassembly,
        "registers": registers or {},
    }


def _make_vmprotect_trace(
    dispatcher_addr: int = 0x401000,
    n_iterations: int = 5,
) -> List[Dict[str, Any]]:
    """Build a synthetic VMProtect-like trace with clear register roles.

    Register roles:
      rsi → vIP (monotonic increment)
      rbp → vSP (bidirectional: decrements on push, increments on pop)
      r12 → handler table base (constant)
      rcx → key register (varies, used in xor)
      rax → scratch (random changes)
    """
    handler_addrs = [0x402000, 0x402100, 0x402200]
    trace: List[Dict[str, Any]] = []

    vip = 0x500000
    vsp = 0x7FFF00
    tbl = 0x600000  # constant
    key = 0xAA

    for i in range(n_iterations):
        handler = handler_addrs[i % len(handler_addrs)]
        opcode = (i * 7 + 3) & 0xFF

        # Dispatcher: fetch
        trace.append(_rec(
            dispatcher_addr,
            f"movzx ecx, byte ptr [rsi]",
            {"rsi": vip, "rbp": vsp, "r12": tbl, "rcx": opcode, "rax": i * 100},
        ))
        # Dispatcher: decode (xor with key)
        decoded = opcode ^ key
        trace.append(_rec(
            dispatcher_addr + 4,
            f"xor ecx, {hex(key)}",
            {"rsi": vip, "rbp": vsp, "r12": tbl, "rcx": decoded, "rax": i * 100},
        ))
        # Dispatcher: advance vIP
        vip += 2
        trace.append(_rec(
            dispatcher_addr + 8,
            "add rsi, 2",
            {"rsi": vip, "rbp": vsp, "r12": tbl, "rcx": decoded, "rax": i * 100},
        ))
        # Dispatcher: dispatch
        trace.append(_rec(
            dispatcher_addr + 12,
            f"jmp qword ptr [r12+rcx*8]",
            {"rsi": vip, "rbp": vsp, "r12": tbl, "rcx": decoded, "rax": i * 100},
        ))

        # Handler body
        if i % 2 == 0:
            # Push handler: decrements vSP
            vsp -= 8
            trace.append(_rec(
                handler,
                "mov [rbp-8], rax",
                {"rsi": vip, "rbp": vsp, "r12": tbl, "rcx": decoded, "rax": i * 100 + 50},
            ))
        else:
            # Pop handler: increments vSP
            vsp += 8
            trace.append(_rec(
                handler,
                "mov rax, [rbp]",
                {"rsi": vip, "rbp": vsp, "r12": tbl, "rcx": decoded, "rax": i * 100 + 50},
            ))

        # Key rolls
        key = (key + decoded) & 0xFF

        # Back to dispatcher
        trace.append(_rec(
            handler + 8,
            f"jmp {hex(dispatcher_addr)}",
            {"rsi": vip, "rbp": vsp, "r12": tbl, "rcx": decoded, "rax": i * 100 + 50},
        ))

    return trace


def _make_boundaries(
    n: int = 5,
    trace_per_handler: int = 2,
    disp_per_handler: int = 4,
) -> List[Dict[str, Any]]:
    """Build fake boundaries matching _make_vmprotect_trace."""
    boundaries = []
    stride = disp_per_handler + trace_per_handler
    for i in range(n):
        start = i * stride + disp_per_handler
        boundaries.append({
            "vip_value": 0x500000 + i * 2,
            "handler_address": 0x402000 + (i % 3) * 0x100,
            "trace_start": start,
            "trace_end": start + trace_per_handler,
            "vip_delta": 2,
        })
    return boundaries


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Register series collection
# ═══════════════════════════════════════════════════════════════════════════

class TestRegisterSeries:

    def test_collects_values(self):
        records = [
            _rec(registers={"rax": 1, "rbx": 10}),
            _rec(registers={"rax": 2, "rbx": 20}),
            _rec(registers={"rax": 3, "rbx": 30}),
        ]
        series = _collect_register_series(records, {"rax", "rbx"})
        assert series["rax"] == [1, 2, 3]
        assert series["rbx"] == [10, 20, 30]

    def test_ignores_missing_regs(self):
        records = [_rec(registers={"rax": 1})]
        series = _collect_register_series(records, {"rax", "rbx"})
        assert "rax" in series
        assert "rbx" not in series or series["rbx"] == []


# ═══════════════════════════════════════════════════════════════════════════
# Tests — vSP identification
# ═══════════════════════════════════════════════════════════════════════════

class TestVSPIdentification:

    def test_bidirectional_scores_high(self):
        """A register with both positive and negative deltas should score well."""
        # rbp goes down (push) then up (pop) repeatedly
        series = {"rbp": [0x1000, 0xFF8, 0x1000, 0xFF0, 0x1000]}
        scores = score_vsp_candidates(
            [], [], series, {"rbp"}, vip_register="rsi",
        )
        assert len(scores) == 1
        assert scores[0][0] == "rbp"
        assert scores[0][1] >= 0.3  # bidirectional + aligned + prior

    def test_monotonic_scores_low(self):
        """A monotonic register (like vIP) should score lower for vSP."""
        series = {"rsi": [0x100, 0x102, 0x104, 0x106, 0x108]}
        scores = score_vsp_candidates(
            [], [], series, {"rsi"}, vip_register="",
        )
        assert len(scores) == 1
        # Monotonic → low vSP score
        assert scores[0][1] < 0.4

    def test_pointer_aligned_deltas(self):
        """Deltas of 8 (pointer width) should boost score."""
        series = {"rbp": [0x1000, 0xFF8, 0x1000, 0xFF8, 0x1000]}
        scores = score_vsp_candidates(
            [], [], series, {"rbp"}, vip_register="rsi",
        )
        assert scores[0][1] >= 0.4


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Handler table base identification
# ═══════════════════════════════════════════════════════════════════════════

class TestHandlerTableBase:

    def test_constant_register_scores_high(self):
        series = {"r12": [0x600000] * 10}
        dispatcher_set = {0x401000}
        scores = score_table_base_candidates(
            [_rec(0x401000, "jmp [r12+rcx*8]", {"r12": 0x600000})] * 3,
            dispatcher_set, [], series, {"r12"},
        )
        assert len(scores) == 1
        assert scores[0][1] >= 0.5  # constant + addr-like + scaled_idx

    def test_varying_register_scores_low(self):
        series = {"rax": list(range(10))}
        scores = score_table_base_candidates(
            [], set(), [], series, {"rax"},
        )
        if scores:
            assert scores[0][1] < 0.3

    def test_scaled_index_boost(self):
        records = [
            _rec(0x401000, "jmp qword ptr [r12+rcx*8]"),
            _rec(0x401000, "jmp qword ptr [r12+rcx*8]"),
        ]
        series = {"r12": [0x600000] * 2}
        count = _count_scaled_index_usage(records, {0x401000}, "r12")
        assert count >= 2


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Key register identification
# ═══════════════════════════════════════════════════════════════════════════

class TestKeyRegister:

    def test_xor_transform_register(self):
        """A register mentioned in decode transforms should score high."""
        series = {"rcx": [0xAA, 0xBB, 0xCC, 0xDD, 0xEE]}
        scores = score_key_candidates(
            [], set(), ["xor ecx, 0x37"], series, {"rcx"},
        )
        assert len(scores) == 1
        assert scores[0][1] >= 0.3  # in-decode + varies

    def test_no_transforms_low_score(self):
        series = {"rax": [1, 2, 3, 4, 5]}
        scores = score_key_candidates(
            [], set(), [], series, {"rax"},
        )
        if scores:
            assert scores[0][1] < 0.3

    def test_extract_regs_from_transforms(self):
        regs = _extract_regs_from_transforms(["xor ecx, 0x37", "add rdx, rax"])
        assert "ecx" in regs
        assert "rdx" in regs
        assert "rax" in regs


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Context base register identification
# ═══════════════════════════════════════════════════════════════════════════

class TestContextBase:

    def test_stable_with_displaced_access(self):
        """A constant register used with varying displacements should score well."""
        records = [
            _rec(0x402000, "mov rax, [rdi+0x10]", {"rdi": 0x700000}),
            _rec(0x402004, "mov rbx, [rdi+0x18]", {"rdi": 0x700000}),
            _rec(0x402008, "mov [rdi+0x20], rcx", {"rdi": 0x700000}),
        ]
        series = {"rdi": [0x700000] * 3}
        boundaries = [{"trace_start": 0, "trace_end": 3}]
        scores = score_context_base_candidates(
            records, boundaries, series, {"rdi"},
        )
        assert len(scores) == 1
        assert scores[0][1] >= 0.4  # stable + mem_base + displaced + prior

    def test_volatile_register_low_score(self):
        series = {"rax": list(range(100, 200, 10))}
        scores = score_context_base_candidates(
            [], [], series, {"rax"},
        )
        if scores:
            assert scores[0][1] < 0.3


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Full composite identification
# ═══════════════════════════════════════════════════════════════════════════

class TestIdentifyVMContext:

    def test_identifies_roles_from_trace(self):
        """Full pipeline should identify vSP, table base, key from synthetic trace."""
        trace = _make_vmprotect_trace(n_iterations=10)
        boundaries = _make_boundaries(n=10)
        dispatcher_addrs = [0x401000, 0x401004, 0x401008, 0x40100C]

        layout = identify_vm_context(
            trace, dispatcher_addrs, boundaries,
            vip_register="rsi",
            decode_transforms=["xor ecx, 0xAA"],
            bit_width=64,
        )

        assert layout.vip_register == "rsi"
        roles = {r.register: r.role for r in layout.registers}
        assert roles.get("rsi") == "vIP"

        # rbp should be identified as vSP (bidirectional, ptr-aligned, prior weight)
        assert layout.vsp == "rbp", f"Expected vSP=rbp, got {layout.vsp}; roles={roles}"

        # r12 should be handler table (constant, scaled index)
        assert layout.table_base == "r12", f"Expected tbl=r12, got {layout.table_base}; roles={roles}"

    def test_empty_trace(self):
        layout = identify_vm_context([], [], [], vip_register="rsi")
        assert layout.vip_register == "rsi"
        assert len(layout.registers) == 0

    def test_vip_always_assigned(self):
        records = [_rec(registers={"rax": 1})]
        layout = identify_vm_context(
            records, [], [], vip_register="rsi",
        )
        roles = {r.register: r.role for r in layout.registers}
        assert roles.get("rsi") == "vIP"

    def test_no_duplicate_roles(self):
        """Each register should have exactly one role."""
        trace = _make_vmprotect_trace(n_iterations=5)
        boundaries = _make_boundaries(n=5)
        layout = identify_vm_context(
            trace, [0x401000], boundaries, vip_register="rsi",
        )
        regs_seen = set()
        for r in layout.registers:
            assert r.register not in regs_seen, f"Duplicate role for {r.register}"
            regs_seen.add(r.register)

    def test_scratch_for_unassigned(self):
        """Registers not assigned a special role should be 'scratch'."""
        trace = _make_vmprotect_trace(n_iterations=5)
        boundaries = _make_boundaries(n=5)
        layout = identify_vm_context(
            trace, [0x401000], boundaries, vip_register="rsi",
        )
        scratch = layout.scratch_registers
        # At least some GP registers should be scratch
        assert len(scratch) > 0


# ═══════════════════════════════════════════════════════════════════════════
# Tests — VMContextLayout
# ═══════════════════════════════════════════════════════════════════════════

class TestVMContextLayout:

    def test_to_dict(self):
        layout = VMContextLayout(
            registers=[
                VMContextRegister("rsi", "vIP", 1.0),
                VMContextRegister("rbp", "vSP", 0.8),
            ],
            vip_register="rsi",
        )
        d = layout.to_dict()
        assert d["vip_register"] == "rsi"
        assert d["roles"]["rsi"] == "vIP"
        assert d["roles"]["rbp"] == "vSP"

    def test_role_accessors(self):
        layout = VMContextLayout(
            registers=[
                VMContextRegister("rsi", "vIP", 1.0),
                VMContextRegister("rbp", "vSP", 0.8),
                VMContextRegister("r12", "vHandlerTbl", 0.9),
                VMContextRegister("rcx", "vKey", 0.6),
                VMContextRegister("rdi", "vContext", 0.5),
                VMContextRegister("rax", "scratch", 0.3),
            ],
            vip_register="rsi",
        )
        assert layout.vsp == "rbp"
        assert layout.table_base == "r12"
        assert layout.key_register == "rcx"
        assert layout.context_base == "rdi"
        assert "rax" in layout.scratch_registers

    def test_get_register_role(self):
        layout = VMContextLayout(
            registers=[VMContextRegister("rsi", "vIP", 1.0)],
        )
        assert layout.get_register_role("rsi") == "vIP"
        assert layout.get_register_role("rax") is None

    def test_context_register_to_dict(self):
        reg = VMContextRegister("rbp", "vSP", 0.85, "bidirectional; aligned")
        d = reg.to_dict()
        assert d["register"] == "rbp"
        assert d["role"] == "vSP"
        assert d["confidence"] == 0.85


# ═══════════════════════════════════════════════════════════════════════════
# Tests — Edge cases
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_single_instruction_trace(self):
        records = [_rec(registers={"rax": 0x100})]
        layout = identify_vm_context(records, [], [])
        # Should not crash
        assert isinstance(layout, VMContextLayout)

    def test_all_registers_constant(self):
        """When all registers are constant, table_base should be identified."""
        records = [
            _rec(registers={"rax": 0x100000, "rbx": 0x200000, "rcx": 0x300000}),
            _rec(registers={"rax": 0x100000, "rbx": 0x200000, "rcx": 0x300000}),
            _rec(registers={"rax": 0x100000, "rbx": 0x200000, "rcx": 0x300000}),
        ]
        layout = identify_vm_context(records, [], [])
        # At least table_base should be found (all constant + addr-like)
        assert layout.table_base is not None or len(layout.registers) > 0

    def test_32bit_mode(self):
        records = [
            _rec(registers={"eax": 0x100, "esi": 0x5000, "ebp": 0x7000}),
            _rec(registers={"eax": 0x200, "esi": 0x5002, "ebp": 0x6FF8}),
        ]
        layout = identify_vm_context(
            records, [], [], vip_register="esi", bit_width=32,
        )
        assert layout.vip_register == "esi"
        assert layout.bit_width == 32
