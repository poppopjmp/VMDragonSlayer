"""Structural VM-detection capability matrix across dispatch shapes.

Pushes :func:`analyse_vm_structure` past the friendly cmp/je and jump-table
fixtures with a *zoo* of compiled interpreters that each stress a different
structural assumption (see ``tests/fixtures/build_vm_zoo.py``):

* ret-trampoline dispatch (``push <handler>; ret`` — no ``jmp``)
* call-table dispatch (``call [table + op*8]``; handlers ``ret``)
* stack-based VM (a competing monotonic pointer, vSP, races the real vIP)
* direct-threaded code (dispatch inlined into every handler — no hot loop)
* wide opcode set (12 handlers — scale)

Each VM is first executed under Unicorn to prove it is a *valid* program,
then the unmodified detector is run against its trace.

Requires the optional ``unicorn`` backend; skipped otherwise.
"""
from __future__ import annotations

import pytest

from dragonslayer.analysis.trace_engine import UNICORN_AVAILABLE

pytestmark = pytest.mark.skipif(
    not UNICORN_AVAILABLE, reason="requires the optional 'unicorn' emulation backend"
)

ZOO = [
    "ret_trampoline",
    "call_table",
    "stack_vm",
    "threaded",
    "wide_opcode",
]


def _trace_zoo(name: str):
    from tests.fixtures import build_vm_zoo as zoo
    from dragonslayer.analysis.trace_engine import TraceConfig, TraceEngine

    elf, meta = zoo._ALL[name]()
    tr = TraceEngine(
        arch="x86_64", config=TraceConfig(max_instructions=4000),
    ).trace(elf, entry_va=meta["entry_va"], image_base=meta["base"])
    return tr, meta


def _final_ebx(trace):
    last = None
    for ti in trace.instructions:
        regs = ti.registers or {}
        val = regs.get("ebx", regs.get("rbx"))
        if isinstance(val, int):
            last = val & 0xFFFFFFFF
    return last


@pytest.mark.parametrize("name", ZOO)
def test_zoo_sample_is_a_valid_program(name):
    """Each zoo VM actually runs to its expected result under Unicorn."""
    trace, meta = _trace_zoo(name)
    assert len(trace.instructions) > 8
    expected = meta.get("expected_result")
    if expected is not None:
        assert _final_ebx(trace) == expected


@pytest.mark.parametrize("name", ZOO)
def test_structural_detection_flags_every_dispatch_shape(name):
    """The protector-agnostic detector flags every dispatch shape as a VM,
    and recovers the real vIP (rsi) in each."""
    from dragonslayer.analysis.vm_discovery.structural import analyse_vm_structure

    trace, _ = _trace_zoo(name)
    report = analyse_vm_structure(trace)
    assert report["is_vm"], report
    assert report["vip_register"] == "rsi", report


def test_stack_vm_picks_vip_not_vsp():
    """A stack VM has a competing pointer (vSP=r11); the detector must still
    pick the real vIP (rsi), not the stack pointer."""
    from dragonslayer.analysis.vm_discovery.structural import analyse_vm_structure

    trace, _ = _trace_zoo("stack_vm")
    assert analyse_vm_structure(trace)["vip_register"] == "rsi"


def test_direct_threaded_dispatch_is_recognised():
    """Direct-threaded code (dispatch inlined per handler, no hot loop) is
    recognised via the threaded-dispatch signal rather than a tight loop."""
    from dragonslayer.analysis.vm_discovery.structural import analyse_vm_structure

    trace, _ = _trace_zoo("threaded")
    report = analyse_vm_structure(trace)
    assert report["is_vm"], report
    assert report["threaded_dispatch"] is True, report
    assert report["dispatch_loop"] is False, report  # no single hot address


def test_wide_opcode_set_estimates_many_handlers():
    """A 12-opcode VM is detected and reports a handler estimate at scale."""
    from dragonslayer.analysis.vm_discovery.structural import analyse_vm_structure

    trace, _ = _trace_zoo("wide_opcode")
    report = analyse_vm_structure(trace)
    assert report["is_vm"]
    assert report["estimated_handlers"] >= 10


@pytest.mark.parametrize("name", ["ret_trampoline", "call_table"])
@pytest.mark.xfail(
    reason="find_dispatcher_in_trace (the VMProtect-specific path) only "
    "matches indirect 'jmp' dispatch; ret-trampoline and call-table dispatch "
    "are covered by the protector-agnostic structural detector instead. "
    "Tracked as a known enhancement opportunity.",
    strict=True,
)
def test_vmprotect_finder_handles_ret_and_call_dispatch(name):
    """Documents the boundary of the VMProtect dispatcher finder."""
    from dragonslayer.analysis.vm_discovery.dispatcher import find_dispatcher_in_trace

    trace, _ = _trace_zoo(name)
    records = [ti.to_dict() for ti in trace.instructions]
    assert find_dispatcher_in_trace(records, bit_width=64) is not None
