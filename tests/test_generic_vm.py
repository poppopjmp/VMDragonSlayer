"""Protector-agnostic capabilities: structural detection of unknown/custom
VMs, and z3-proven handler-equivalence merging of obfuscated variants.
"""
from __future__ import annotations

import importlib.util

import pytest

from dragonslayer.analysis.trace_engine import (
    UNICORN_AVAILABLE,
    TraceConfig,
    TraceEngine,
)

unicorn_only = pytest.mark.skipif(
    not UNICORN_AVAILABLE, reason="requires the optional 'unicorn' backend"
)


def _trace(build):
    elf, meta = build()
    tr = TraceEngine(arch="x86_64", config=TraceConfig(max_instructions=300)).trace(
        elf, entry_va=meta["entry_va"], image_base=meta["base"],
    )
    return tr, meta


@unicorn_only
def test_structural_detection_flags_custom_vms():
    """Both custom fixtures (no commercial-protector signature) are flagged
    as VMs purely from their interpreter structure."""
    from dragonslayer.analysis.vm_discovery.structural import analyse_vm_structure
    from tests.fixtures.build_vm_sample import build as cmp_je
    from tests.fixtures.build_vm_sample_jumptable import build as jumptable

    for build in (cmp_je, jumptable):
        tr, _ = _trace(build)
        r = analyse_vm_structure(tr)
        assert r["is_vm"], r
        assert r["confidence"] >= 0.7
        assert r["vip_register"] == "rsi"

    # The jump-table VM additionally shows indirect/handler-table dispatch.
    tr, _ = _trace(jumptable)
    assert analyse_vm_structure(tr)["indirect_dispatch"] is True


@unicorn_only
def test_structural_detection_rejects_non_vm():
    """A flat straight-line code trace is not mistaken for a VM."""
    from dragonslayer.analysis.trace_ingestion import ExecutionTrace, TraceInstruction
    from dragonslayer.analysis.vm_discovery.structural import analyse_vm_structure

    flat = ExecutionTrace(instructions=[
        TraceInstruction(address=0x1000 + i * 3, size=3, raw_bytes=b"\x01\xd8",
                         disassembly="add eax, ebx")
        for i in range(24)
    ])
    assert analyse_vm_structure(flat)["is_vm"] is False


@unicorn_only
def test_detector_reports_generic_vm_for_custom_binary():
    """VMDetector flags the custom VM as ``generic_vm`` via the structural
    fallback (signature scan alone would miss it)."""
    from dragonslayer.analysis.vm_discovery.detector import VMDetector
    from tests.fixtures.build_vm_sample_jumptable import build

    elf, _ = build()
    res = VMDetector().detect(elf)
    assert res["vm_detected"] is True
    assert res["protector"] == "generic_vm"
    assert res["structural"]["is_vm"] is True


@pytest.mark.skipif(
    importlib.util.find_spec("z3") is None, reason="requires z3",
)
def test_z3_merges_mba_obfuscated_handler_variants():
    """Two handlers computing the same function in different (MBA) forms are
    proven equivalent by z3 and merged."""
    from dragonslayer.analysis.handler_clustering import (
        NormalizedEffect,
        are_semantically_equivalent,
    )

    plain = NormalizedEffect(operation="vm_add", operand_width=4, input_slots=2,
                             canonical_expression="slot_0 + slot_1", confidence=0.9)
    mba_expr = "(slot_0 ^ slot_1) + 2 * (slot_0 & slot_1)"
    mba = NormalizedEffect(operation="vm_add", operand_width=4, input_slots=2,
                           canonical_expression=mba_expr, confidence=0.9)
    eq, conf = are_semantically_equivalent(plain, mba)
    assert eq is True and conf > 0.0

    # Genuinely different operations must NOT be merged.
    sub = NormalizedEffect(operation="vm_add", operand_width=4, input_slots=2,
                           canonical_expression="slot_0 - slot_1", confidence=0.9)
    assert are_semantically_equivalent(plain, sub)[0] is False
