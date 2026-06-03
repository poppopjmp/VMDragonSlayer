"""End-to-end nested-VM recovery on the hard VM sample.

Drives the *production* devirtualization stage sequence (the same steps the
pipeline's ``_run_devirtualization`` runs) over a compiled VM whose VMCALL
opcode enters a second, inner interpreter with a different dispatch shape
(``cmp/je`` chain) and its own vIP.  Asserts that:

* the outer VM is recovered (vIP = rsi), and
* the inner VM is detected structurally and its MUL operation — which the
  single-layer pipeline drops entirely — is recovered.

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
    assert ws.trace is not None and ws.trace.instructions, "no trace produced"
    step_build_hook_set(ws)
    step_locate_vm_entries(ws)
    step_identify_dispatcher(ws)
    step_decrypt_bytecode(ws)
    assert step_segment_handlers(ws), "segmentation failed"
    step_extract_handlers(ws)
    step_identify_context(ws)
    step_analyze_semantics(ws)
    step_build_cfgs(ws)
    step_emit_pseudocode(ws)
    step_detect_nested_vms(ws)
    return ws


@pytest.fixture(scope="module")
def ws():
    from tests.fixtures.build_vm_sample_hard import build

    elf, _meta = build()
    return _run_devirt(elf)


def test_outer_vm_recovered(ws):
    """Outer jump-table VM is recovered with the correct vIP."""
    assert ws.vip_candidate is not None
    assert ws.vip_candidate.name == "rsi"
    assert len(ws.boundaries) >= 4


def test_nested_vm_detected(ws):
    """The inner VM (entered via VMCALL) is detected structurally."""
    assert ws.nested_layers, "no nested VM layer recovered"
    structural = [
        layer for layer in ws.nested_layers
        if layer.get("detection") == "structural"
    ]
    assert structural, f"no structural nested layer; got {ws.nested_layers}"
    # The inner interpreter uses a *different* vIP than the outer (rsi).
    assert any(layer.get("vip_register") == "rdi" for layer in structural)


def test_inner_mul_recovered(ws):
    """The inner VM's MUL — dropped by single-layer analysis — is recovered."""
    ops: set[str] = set()
    for layer in ws.nested_layers:
        ops.update(layer.get("operations") or [])
    assert any("mul" in op.lower() for op in ops), (
        f"inner MUL not recovered; recovered nested ops = {sorted(ops)}"
    )
