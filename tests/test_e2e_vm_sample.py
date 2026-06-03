"""End-to-end devirtualization test on a real compiled bytecode-VM binary.

Unlike the rest of the suite (which feeds handcrafted byte sequences), this
test drives the **built-in Unicorn trace engine** over a genuine ELF
executable that contains a fetch -> decode -> dispatch interpreter loop
(see ``tests/fixtures/build_vm_sample.py``), then runs the full
trace -> vIP -> boundaries -> semantics -> pseudocode chain and asserts the
recovered structure is meaningful.

Requires the optional ``unicorn`` backend; skipped automatically otherwise.
"""
from __future__ import annotations

import pytest

from dragonslayer.analysis.trace_engine import (
    UNICORN_AVAILABLE,
    TraceConfig,
    TraceEngine,
)

pytestmark = pytest.mark.skipif(
    not UNICORN_AVAILABLE, reason="requires the optional 'unicorn' emulation backend"
)


@pytest.fixture(scope="module")
def sample():
    from tests.fixtures.build_vm_sample import build

    return build()  # (elf_bytes, metadata)


@pytest.fixture(scope="module")
def trace(sample):
    elf, meta = sample
    engine = TraceEngine(arch="x86_64", config=TraceConfig(max_instructions=500))
    return engine.trace(
        elf,
        entry_va=meta["entry_va"],
        image_base=meta["base"],
        initial_regs={"rsi": meta["bytecode_va"]},
    )


def test_builtin_engine_executes_the_vm(trace):
    """The Unicorn engine actually runs the interpreter to completion."""
    mnems = [ti.disassembly.split()[0] for ti in trace.instructions]
    assert len(trace.instructions) > 10, "trace is suspiciously short"
    # Dispatch loop ran multiple times (fetch + compare/branch dispatch).
    assert mnems.count("cmp") >= 3
    assert "movzx" in mnems  # opcode fetch
    # Handlers executed (LOAD uses mov; ADD/XOR handlers present).
    assert "xor" in mnems
    # Interpreter reached its HALT.
    assert "hlt" in mnems


def test_vip_register_is_recovered(trace, sample):
    """The vIP (rsi in our VM) is correctly identified as the bytecode pointer."""
    from dragonslayer.analysis.vm_discovery.handler_boundaries import (
        identify_vip_register,
    )

    _, meta = sample
    vip = identify_vip_register(trace, [meta["entry_va"]])
    assert vip is not None, "no vIP candidate found"
    assert vip.name == "rsi", f"expected vIP=rsi, got {vip.name}"
    assert vip.monotonic_ratio > 0.5  # vIP advances monotonically through bytecode


def test_handlers_segmented_and_pseudocode_emitted(trace, sample):
    """The full chain segments handlers and emits non-empty pseudocode."""
    from dragonslayer.analysis.handler_semantics import analyse_handler_semantics
    from dragonslayer.analysis.pseudocode import emit_linear
    from dragonslayer.analysis.vm_discovery.handler_boundaries import (
        identify_vip_register,
        segment_trace,
    )

    _, meta = sample
    disp = [meta["dispatch_va"]]
    vip = identify_vip_register(trace, disp)
    seg = segment_trace(trace, vip, disp)
    # The bytecode is LOAD / ADD / XOR / HALT -> several handler invocations.
    assert len(seg.boundaries) >= 3

    opcode_table = analyse_handler_semantics(trace, seg.boundaries)
    assert len(opcode_table.entries) >= 1
    # Every classified handler carries a concrete VM operation label.
    assert all(e.semantic.operation for e in opcode_table.entries)

    result = emit_linear(opcode_table, seg.boundaries)
    assert result.text.strip(), "pseudocode listing is empty"
    assert result.line_count >= 1
