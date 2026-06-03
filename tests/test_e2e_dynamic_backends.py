"""End-to-end tests for the dynamic-analysis backends and the full
devirtualization pipeline, exercised over real compiled bytecode-VM ELFs.

These complement ``test_e2e_vm_sample.py``:
  * the jump-table fixture exercises the ``find_dispatcher`` detection path,
  * the devirt-pipeline test drives the whole trace -> dispatcher/vIP ->
    boundaries -> semantics -> pseudocode chain via ``DevirtWorkspace``,
  * the Triton/angr tests confirm those backends run and feed the pipeline.

Each test skips automatically when its optional backend is absent.
"""
from __future__ import annotations

import pytest

from dragonslayer.analysis.trace_engine import (
    UNICORN_AVAILABLE,
    TraceConfig,
    TraceEngine,
)

unicorn_only = pytest.mark.skipif(
    not UNICORN_AVAILABLE, reason="requires the optional 'unicorn' backend"
)


def _have(mod: str) -> bool:
    import importlib.util

    return importlib.util.find_spec(mod) is not None


# ---------------------------------------------------------------------------
# Jump-table dispatcher detection
# ---------------------------------------------------------------------------

@unicorn_only
def test_jumptable_dispatcher_is_detected():
    """find_dispatcher recognises the canonical jump-table VM dispatch."""
    from dragonslayer.analysis.vm_discovery.dispatcher import find_dispatcher
    from tests.fixtures.build_vm_sample_jumptable import build

    elf, meta = build()
    trace = TraceEngine(arch="x86_64", config=TraceConfig(max_instructions=300)).trace(
        elf, entry_va=meta["entry_va"], image_base=meta["base"],
    )
    # The dispatch loop runs the indirect ``jmp [r10+rax*8]`` several times.
    assert any(
        ti.disassembly.startswith("jmp") and "[" in ti.disassembly
        for ti in trace.instructions
    )
    records = [ti.to_dict() for ti in trace.instructions]
    match = find_dispatcher(records, bit_width=64)
    assert match is not None, "jump-table dispatcher was not detected"
    assert match.to_dict().get("dispatch_address")


# ---------------------------------------------------------------------------
# Full devirtualization pipeline (DevirtWorkspace)
# ---------------------------------------------------------------------------

@unicorn_only
def test_devirt_pipeline_recovers_vip_and_pseudocode():
    """The orchestrated devirt steps trace, segment, and emit pseudocode
    end to end — using the built-in Unicorn trace fallback (no plugins)."""
    from dragonslayer.core.devirt_stages import (
        DevirtWorkspace,
        step_analyze_semantics,
        step_emit_pseudocode,
        step_ingest_trace,
        step_segment_handlers,
    )
    from tests.fixtures.build_vm_sample import build

    elf, _ = build()
    ws = DevirtWorkspace(binary_data=elf, shared_data={})
    step_ingest_trace(ws)
    assert ws.trace is not None and ws.trace.instructions, "no trace produced"

    assert step_segment_handlers(ws) is True
    assert ws.vip_candidate is not None and ws.vip_candidate.name == "rsi"
    assert ws.boundaries

    step_analyze_semantics(ws)
    assert ws.opcode_table is not None and ws.opcode_table.entries

    step_emit_pseudocode(ws)
    assert ws.pseudocode_result is not None
    assert ws.pseudocode_result.text.strip()


# ---------------------------------------------------------------------------
# Dynamic backends feed the pipeline
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _have("triton"), reason="needs optional 'triton' backend")
def test_triton_backend_produces_ingestable_trace():
    """The Triton plugin executes the binary and its trace ingests into an
    ExecutionTrace (the data path that feeds taint / symbolic stages)."""
    from pathlib import Path

    from dragonslayer.analysis.trace_ingestion import from_shared_data
    from dragonslayer.plugins import PluginContext
    from dragonslayer.plugins.dynamic.triton_analyzer import TritonAnalyzer

    data = Path("tests/fixtures/vm_sample.elf").read_bytes()
    ctx = PluginContext(shared_data={})
    result = TritonAnalyzer().safe_execute("tests/fixtures/vm_sample.elf", data, ctx)
    assert result.success, f"triton failed: {result.error}"
    assert result.data.get("instructions_executed", 0) > 0

    ctx.shared_data["triton"] = result.data
    trace = from_shared_data(ctx.shared_data)
    assert trace.instructions, "triton trace did not ingest into ExecutionTrace"


@pytest.mark.skipif(not _have("angr"), reason="requires the optional 'angr' backend")
def test_angr_backend_runs_and_extracts_functions():
    """The angr plugin loads the binary and recovers CFG/function data."""
    from pathlib import Path

    from dragonslayer.plugins import PluginContext
    from dragonslayer.plugins.dynamic.angr_analyzer import AngrAnalyzer

    data = Path("tests/fixtures/vm_sample.elf").read_bytes()
    result = AngrAnalyzer().safe_execute(
        "tests/fixtures/vm_sample.elf", data, PluginContext(shared_data={})
    )
    assert result.success, f"angr failed: {result.error}"
    assert "functions" in result.data
    assert result.data.get("entry_point")
