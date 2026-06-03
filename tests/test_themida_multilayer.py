"""Capstone: end-to-end recovery of a 3-layer, per-layer-encrypted nested VM.

Drives the production devirtualization stage sequence over the Themida-grade
fixture (``tests/fixtures/build_vm_themida.py``): three interpreter layers
with different dispatcher shapes and vIPs (rsi / rdi / r8), each inner layer's
bytecode XOR-encrypted with a different key and decrypted on entry, plus a
mutated duplicate handler in the inner layer.

Asserts that the pipeline:
* runs the real (decrypted) computation to the right answer,
* recovers the outer layer (vIP=rsi) and its arithmetic ops,
* peels *both* inner layers (depth 1 and depth 2), recovering all three vIPs,
* recovers the middle layer's MUL — which lives two layers deep, behind a
  cmp/je dispatcher and a decrypt loop.

Requires the optional ``unicorn`` backend; skipped otherwise.
"""
from __future__ import annotations

import pytest

from dragonslayer.analysis.trace_engine import UNICORN_AVAILABLE

pytestmark = pytest.mark.skipif(
    not UNICORN_AVAILABLE, reason="requires the optional 'unicorn' emulation backend"
)


def _run_devirt(elf: bytes):
    from dragonslayer.core.devirt_stages import (
        DevirtWorkspace,
        step_analyze_semantics,
        step_build_cfgs,
        step_build_hook_set,
        step_decrypt_bytecode,
        step_detect_nested_vms,
        step_emit_pseudocode,
        step_extract_handlers,
        step_identify_context,
        step_identify_dispatcher,
        step_ingest_trace,
        step_locate_vm_entries,
        step_segment_handlers,
    )

    ws = DevirtWorkspace(binary_data=elf, shared_data={})
    step_ingest_trace(ws)
    assert ws.trace is not None and ws.trace.instructions
    step_build_hook_set(ws)
    step_locate_vm_entries(ws)
    step_identify_dispatcher(ws)
    step_decrypt_bytecode(ws)
    assert step_segment_handlers(ws)
    step_extract_handlers(ws)
    step_identify_context(ws)
    step_analyze_semantics(ws)
    step_build_cfgs(ws)
    step_emit_pseudocode(ws)
    step_detect_nested_vms(ws)
    return ws


@pytest.fixture(scope="module")
def result():
    from tests.fixtures.build_vm_themida import load
    from dragonslayer.analysis.trace_engine import TraceConfig, TraceEngine

    elf, meta = load()
    # Validity: the encrypted, 3-layer program runs to the expected result.
    tr = TraceEngine(
        arch="x86_64", config=TraceConfig(max_instructions=8000),
    ).trace(elf, entry_va=meta["entry_va"], image_base=meta["base"])
    final = None
    for ti in tr.instructions:
        regs = ti.registers or {}
        v = regs.get("ebx", regs.get("rbx"))
        if isinstance(v, int):
            final = v & 0xFFFFFFFF
    ws = _run_devirt(elf)
    return ws, meta, final


def test_multilayer_is_a_valid_program(result):
    _ws, meta, final = result
    assert final == meta["expected_result"] == 42


def test_outer_layer_recovered(result):
    ws, _meta, _ = result
    assert ws.vip_candidate is not None
    assert ws.vip_candidate.name == "rsi"
    outer_ops = {e.semantic.operation for e in ws.opcode_table.entries}
    # Layer-1 arithmetic (LOAD/ADD/XOR) recovered at the outer level.
    assert {"vm_load", "vm_add", "vm_xor"} <= outer_ops, outer_ops


def test_both_inner_layers_peeled(result):
    ws, _meta, _ = result
    assert len(ws.nested_layers) >= 2, ws.nested_layers
    depths = {layer.get("depth") for layer in ws.nested_layers}
    assert {1, 2} <= depths, f"expected depth-1 and depth-2 layers, got {depths}"


def test_all_three_vips_recovered(result):
    ws, _meta, _ = result
    vips = {ws.vip_candidate.name}
    vips |= {layer.get("vip_register") for layer in ws.nested_layers}
    assert {"rsi", "rdi", "r8"} <= vips, vips


def test_encrypted_middle_layer_mul_recovered(result):
    """The middle layer's MUL — encrypted, behind a cmp/je dispatcher, two
    layers deep — is recovered."""
    ws, _meta, _ = result
    nested_ops: set[str] = set()
    for layer in ws.nested_layers:
        nested_ops |= set(layer.get("operations") or [])
    assert any("mul" in op.lower() for op in nested_ops), nested_ops
