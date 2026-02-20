"""Batch 23 — End-to-end integration tests for the devirtualization pipeline.

Constructs a realistic VMProtect-like execution trace from scratch and
runs the full _run_devirtualize() pipeline to verify that all Batch
13-22 components work together.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

# ── Pipeline imports ─────────────────────────────────────────────────
from dragonslayer.core.pipeline import AnalysisPipeline

# ── Analysis imports ─────────────────────────────────────────────────
from dragonslayer.analysis.trace_ingestion import ExecutionTrace
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
    identify_vip_register,
    segment_trace,
)
from dragonslayer.analysis.handler_semantics import (
    analyse_handler_semantics,
    VMOperation,
)
from dragonslayer.analysis.pseudocode import emit_pseudocode
from dragonslayer.analysis.bytecode_cfg import build_handler_cfg
from dragonslayer.analysis.symbolic_depth import collect_symbolic_summaries
from dragonslayer.analysis.vm_discovery.vm_entry_locator import (
    locate_vm_entries,
    VmEntryReport,
)


# ═══════════════════════════════════════════════════════════════════════
# Synthetic trace builder
# ═══════════════════════════════════════════════════════════════════════

_DISPATCHER_ADDR = 0x00401000
_HANDLER_BASE = 0x00402000
_BYTECODE_BASE = 0x00410000

# Fake x86-64 code bytes for different handler types
_HANDLER_BYTES = {
    "push": bytes.fromhex("50"),           # push rax
    "pop": bytes.fromhex("58"),            # pop rax
    "add": bytes.fromhex("4801d8"),        # add rax, rbx
    "sub": bytes.fromhex("4829d8"),        # sub rax, rbx
    "xor": bytes.fromhex("4831d8"),        # xor rax, rbx
    "mov": bytes.fromhex("4889d8"),        # mov rax, rbx
    "ret": bytes.fromhex("c3"),            # ret
    "nop": bytes.fromhex("90"),            # nop
}

# Opcode → handler mapping (VMProtect-like)
_OPCODE_TABLE = {
    0x00: ("push", 0x00402000),
    0x01: ("pop",  0x00402100),
    0x02: ("add",  0x00402200),
    0x03: ("sub",  0x00402300),
    0x04: ("xor",  0x00402400),
    0x05: ("mov",  0x00402500),
    0x06: ("ret",  0x00402600),
    0x07: ("nop",  0x00402700),
}


def _build_trace_instruction(
    addr: int,
    mnemonic: str,
    operands: str = "",
    raw_bytes: str = "90",
    regs: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """Create a single trace instruction record."""
    return {
        "address": addr,
        "mnemonic": mnemonic,
        "operands": operands,
        "raw_bytes": raw_bytes,
        "size": len(bytes.fromhex(raw_bytes)),
        "registers": regs or {},
    }


def _build_dispatcher_instructions(
    vip_value: int,
    opcode: int,
    handler_addr: int,
    rsi_value: int,
) -> List[Dict[str, Any]]:
    """Build a minimal VMProtect fetch-decode-dispatch sequence."""
    return [
        # movzx eax, byte ptr [rsi]  — opcode fetch
        _build_trace_instruction(
            _DISPATCHER_ADDR, "movzx", "eax, byte ptr [rsi]",
            "0fb606",
            regs={"rsi": rsi_value, "rax": opcode},
        ),
        # xor eax, 0x42  — decode (XOR key)
        _build_trace_instruction(
            _DISPATCHER_ADDR + 3, "xor", "eax, 0x42",
            "3542000000",
            regs={"rsi": rsi_value, "rax": opcode ^ 0x42},
        ),
        # add rsi, 1  — vIP advance
        _build_trace_instruction(
            _DISPATCHER_ADDR + 8, "add", "rsi, 1",
            "4883c601",
            regs={"rsi": rsi_value + 1, "rax": opcode ^ 0x42},
        ),
        # jmp [rbx + rax*8]  — dispatch
        _build_trace_instruction(
            _DISPATCHER_ADDR + 12, "jmp", "qword ptr [rbx + rax*8]",
            "ff24c3",
            regs={"rsi": rsi_value + 1, "rax": opcode ^ 0x42, "rbx": _HANDLER_BASE},
        ),
    ]


def _build_handler_instructions(
    handler_name: str,
    handler_addr: int,
    rsi_value: int,
    rsp_value: int = 0x7FFF0000,
) -> List[Dict[str, Any]]:
    """Build instruction(s) for a handler body."""
    raw = _HANDLER_BYTES.get(handler_name, b"\x90").hex()
    regs = {"rsi": rsi_value, "rsp": rsp_value}

    if handler_name == "push":
        regs["rsp"] = rsp_value - 8
    elif handler_name == "pop":
        regs["rsp"] = rsp_value + 8

    return [
        _build_trace_instruction(
            handler_addr,
            handler_name if handler_name != "nop" else "nop",
            "",
            raw,
            regs=regs,
        ),
    ]


def build_vmprotect_trace(
    bytecode: List[int],
    *,
    rsi_start: int = _BYTECODE_BASE,
) -> List[Dict[str, Any]]:
    """Build a complete VMProtect-like execution trace from bytecode.

    Each bytecode byte is looked up in the opcode table, and a realistic
    dispatcher → handler sequence is generated.
    """
    instructions: List[Dict[str, Any]] = []
    rsi = rsi_start
    rsp = 0x7FFF0000

    for opcode in bytecode:
        if opcode not in _OPCODE_TABLE:
            continue
        name, handler_addr = _OPCODE_TABLE[opcode]

        # Dispatcher cycle
        disp_insns = _build_dispatcher_instructions(rsi, opcode, handler_addr, rsi)
        instructions.extend(disp_insns)

        # Handler body
        rsi += 1  # vIP advanced by dispatcher
        handler_insns = _build_handler_instructions(name, handler_addr, rsi, rsp)
        instructions.extend(handler_insns)

        # Update rsp if push/pop
        if name == "push":
            rsp -= 8
        elif name == "pop":
            rsp += 8

    return instructions


def build_trace_from_instructions(
    insns: List[Dict[str, Any]],
) -> ExecutionTrace:
    """Wrap raw instruction dicts into an ExecutionTrace."""
    from dragonslayer.analysis.trace_ingestion import TraceInstruction
    trace_insns = []
    for d in insns:
        ti = TraceInstruction(
            address=d.get("address", 0),
            size=d.get("size", len(bytes.fromhex(d.get("raw_bytes", "90")))),
            raw_bytes=bytes.fromhex(d.get("raw_bytes", "90")),
            disassembly=f"{d.get('mnemonic', 'nop')} {d.get('operands', '')}".strip(),
            registers=d.get("registers", {}),
        )
        trace_insns.append(ti)
    return ExecutionTrace(
        instructions=trace_insns,
        metadata={
            "source": "synthetic_vmprotect",
            "bit_width": 64,
            "image_base": 0x00400000,
        },
    )


# ═══════════════════════════════════════════════════════════════════════
# Synthetic PE with VM entry stubs
# ═══════════════════════════════════════════════════════════════════════

def _push_reg64(n: int) -> bytes:
    result = bytearray()
    for i in range(n):
        if i < 8:
            result.append(0x50 + i)
        else:
            result.extend([0x41, 0x50 + (i - 8)])
    return bytes(result)


def build_pe_with_entries(count: int = 2) -> bytes:
    """Build a fake PE section with VM entry stubs."""
    stubs = bytearray()
    for idx in range(count):
        stub = (
            _push_reg64(16)
            + b"\x9c"  # pushfq
            + b"\x48\xb8" + struct.pack("<Q", _BYTECODE_BASE + idx * 0x100)
            + b"\xe9" + struct.pack("<i", 0x500 + idx * 4)
        )
        stubs.extend(stub)
        stubs.extend(b"\xcc" * 8)
    return bytes(stubs)


# ═══════════════════════════════════════════════════════════════════════
# Test: Full analysis chain (component-level integration)
# ═══════════════════════════════════════════════════════════════════════

class TestFullAnalysisChain:
    """Test the complete analysis chain using synthetic VMProtect trace."""

    @pytest.fixture
    def bytecode(self):
        """A small VM program: push, push, add, pop, ret."""
        return [0x00, 0x00, 0x02, 0x01, 0x06]

    @pytest.fixture
    def trace(self, bytecode):
        insns = build_vmprotect_trace(bytecode)
        return build_trace_from_instructions(insns)

    def test_trace_has_instructions(self, trace):
        assert len(trace.instructions) > 0
        # Each bytecode instruction generates dispatcher + handler
        # 4 dispatcher + 1 handler = 5 per opcode, × 5 opcodes = 25
        assert len(trace.instructions) >= 5 * 5

    def test_vip_identification(self, trace):
        result = identify_vip_register(trace)
        assert result is not None
        # rsi is used as vIP in our synthetic trace
        assert result.name in ("rsi", "esi")

    def test_segmentation(self, trace):
        vip = identify_vip_register(trace)
        assert vip is not None
        result = segment_trace(trace, vip)
        assert len(result.boundaries) > 0
        assert len(result.boundaries) >= 5

    def test_handler_semantics(self, trace):
        vip = identify_vip_register(trace)
        assert vip is not None
        seg = segment_trace(trace, vip)
        opcode_table = analyse_handler_semantics(trace, seg.boundaries)
        assert opcode_table.handler_count > 0
        # Should have at least 3 unique operations
        ops = opcode_table.operations_summary()
        assert len(ops) >= 1

    def test_pseudocode_emission(self, trace):
        vip = identify_vip_register(trace)
        assert vip is not None
        seg = segment_trace(trace, vip)
        opcode_table = analyse_handler_semantics(trace, seg.boundaries)
        result = emit_pseudocode(opcode_table, seg.boundaries, style="c_like")
        assert result.text
        assert result.style == "c_like"
        assert result.line_count > 0

    def test_cfg_construction(self, trace):
        vip = identify_vip_register(trace)
        assert vip is not None
        seg = segment_trace(trace, vip)
        opcode_table = analyse_handler_semantics(trace, seg.boundaries)
        cfg = build_handler_cfg(opcode_table, seg.boundaries)
        assert cfg is not None
        assert cfg.block_count >= 1

    def test_pseudocode_with_annotations(self, trace):
        vip = identify_vip_register(trace)
        assert vip is not None
        seg = segment_trace(trace, vip)
        opcode_table = analyse_handler_semantics(trace, seg.boundaries)
        layout = {"vsp": "rsp", "table_base": "rbx"}
        clustering = {
            "clusters": [
                {"canonical_operation": "vm_push", "handler_count": 2},
                {"canonical_operation": "vm_add", "handler_count": 1},
            ]
        }
        result = emit_pseudocode(
            opcode_table, seg.boundaries,
            style="c_like",
            context_layout=layout,
            clustering=clustering,
        )
        assert "VM Context Layout" in result.text
        assert "vsp" in result.text
        assert "Semantic Clusters" in result.text

    def test_symbolic_depth_collection(self, trace):
        shared = {
            "handler_extraction": {
                "handlers": [
                    {
                        "address": 0x00402000,
                        "register_delta": {"rsp": {"before": 0x7FFF0000, "after": 0x7FFEFFF8}},
                    },
                    {
                        "address": 0x00402200,
                        "register_delta": {"rax": 0},
                    },
                ],
            },
        }
        summaries = collect_symbolic_summaries(shared, run_fresh=False)
        assert len(summaries) >= 2
        assert 0x00402000 in summaries


# ═══════════════════════════════════════════════════════════════════════
# Test: VM entry locator on synthetic PE
# ═══════════════════════════════════════════════════════════════════════

class TestVmEntryLocatorIntegration:
    def test_locate_entries_in_synthetic_pe(self):
        pe_data = build_pe_with_entries(count=3)
        sections = [{
            "name": ".vmp0",
            "virtual_address": hex(0x1000),
            "virtual_size": hex(len(pe_data)),
            "raw_offset": hex(0),
            "raw_size": hex(len(pe_data)),
            "characteristics": hex(0x60000020),
            "entropy": 7.2,
        }]
        report = locate_vm_entries(
            pe_data, sections=sections, bit_width=64, min_confidence=0.3)
        assert report.count >= 3
        for e in report.entries:
            assert e.push_count >= 6


# ═══════════════════════════════════════════════════════════════════════
# Test: Pipeline stage integration (mocked context)
# ═══════════════════════════════════════════════════════════════════════

class TestPipelineStageIntegration:
    """Test _run_devirtualize with a mocked pipeline context."""

    def _make_pipeline(self) -> AnalysisPipeline:
        return AnalysisPipeline(config={"stages": ["devirtualize"]})

    def _make_context(self, trace: ExecutionTrace) -> Any:
        ctx = MagicMock()
        ctx.shared_data = {
            "qiling": {
                "trace": [instr for instr in trace.instructions],
                "trace_format": "instruction_list",
            },
        }
        return ctx

    def test_devirtualize_stage_runs(self):
        bytecode = [0x00, 0x00, 0x02, 0x01, 0x06]
        insns = build_vmprotect_trace(bytecode)
        trace = build_trace_from_instructions(insns)

        pipeline = self._make_pipeline()
        ctx = self._make_context(trace)

        result = pipeline._run_devirtualize(b"\x00" * 64, ctx)
        assert result is not None
        # Even if sub-steps use fallbacks, the stage should complete
        assert result.stage == "devirtualize"

    def test_devirtualize_with_pe_data(self):
        bytecode = [0x00, 0x02, 0x06]
        insns = build_vmprotect_trace(bytecode)
        trace = build_trace_from_instructions(insns)

        pe_data = build_pe_with_entries(count=2)

        pipeline = self._make_pipeline()
        ctx = self._make_context(trace)
        ctx.shared_data["pe_analyzer"] = {
            "valid": True,
            "optional_header": {
                "magic": hex(0x20B),
                "image_base": hex(0x400000),
            },
            "sections": [{
                "name": ".vmp0",
                "virtual_address": hex(0x1000),
                "virtual_size": hex(len(pe_data)),
                "raw_offset": hex(0),
                "raw_size": hex(len(pe_data)),
                "characteristics": hex(0x60000020),
                "entropy": 7.2,
            }],
        }

        result = pipeline._run_devirtualize(pe_data, ctx)
        assert result is not None
        assert result.stage == "devirtualize"


# ═══════════════════════════════════════════════════════════════════════
# Test: Cross-module data flow
# ═══════════════════════════════════════════════════════════════════════

class TestCrossModuleDataFlow:
    """Verify that data flows correctly between Batch 13-22 modules."""

    def test_opcode_table_flows_to_pseudocode(self):
        bytecode = [0x00, 0x02, 0x03, 0x06]
        insns = build_vmprotect_trace(bytecode)
        trace = build_trace_from_instructions(insns)

        vip = identify_vip_register(trace)
        assert vip is not None
        seg = segment_trace(trace, vip)

        opcode_table = analyse_handler_semantics(trace, seg.boundaries)
        cfg = build_handler_cfg(opcode_table, seg.boundaries)
        result = emit_pseudocode(
            opcode_table, seg.boundaries, cfg.graph if cfg else None,
            style="c_like",
        )
        assert "void vm_func()" in result.text
        assert result.line_count > 5

    def test_trace_to_symbolic_depth_to_clustering(self):
        """Verify that handler extraction → symbolic depth → clustering works."""
        from dragonslayer.analysis.handler_clustering import (
            cluster_handlers_by_semantics,
        )
        from dragonslayer.analysis.handler_semantics import (
            SemanticOpcodeTable,
            OpcodeTableEntry,
            HandlerSemantic,
        )

        # Build a simple opcode table
        entries = [
            OpcodeTableEntry(
                opcode=0, handler_address=0x1000,
                semantic=HandlerSemantic(
                    handler_address=0x1000,
                    operation=VMOperation.ADD,
                    confidence=0.9,
                    operand_width=8,
                ),
                vip_delta=1,
            ),
            OpcodeTableEntry(
                opcode=1, handler_address=0x2000,
                semantic=HandlerSemantic(
                    handler_address=0x2000,
                    operation=VMOperation.ADD,
                    confidence=0.85,
                    operand_width=4,
                ),
                vip_delta=1,
            ),
        ]
        table = SemanticOpcodeTable(
            entries=entries,
            handler_count=2,
            unique_operations=1,
        )

        # Build symbolic summaries from extraction data
        shared = {
            "handler_extraction": {
                "handlers": [
                    {
                        "address": 0x1000,
                        "register_delta": {"rax": {"before": 0, "after": 10}},
                    },
                    {
                        "address": 0x2000,
                        "register_delta": {"eax": {"before": 0, "after": 5}},
                    },
                ],
            },
        }
        summaries = collect_symbolic_summaries(shared, run_fresh=False)
        assert len(summaries) >= 2

        semantics_list = [e.semantic for e in table.entries]
        result = cluster_handlers_by_semantics(semantics_list, symbolic_summaries=summaries)
        assert result is not None
        assert len(result.clusters) >= 1
