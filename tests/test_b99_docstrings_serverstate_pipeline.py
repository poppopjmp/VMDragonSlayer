"""B99 — Docstring coverage, ServerState dataclass, pipeline shared pool, return types.

Tests verify:
1. ``to_dict()`` methods across 12 modules return well-formed dicts.
2. ``@property`` accessors on data-model classes.
3. ``ServerState`` is a proper dataclass with typed attributes.
4. Pipeline uses a shared ``ThreadPoolExecutor`` (no per-stage leaks).
5. New ``-> None`` / ``-> T`` return-type annotations exist.
6. AnalysisResult.to_dict() returns an AnalysisResultDict.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import textwrap
import time
from dataclasses import fields as dc_fields, is_dataclass
from typing import Any, Dict, get_type_hints
from unittest.mock import MagicMock, patch

import pytest


# ═══════════════════════════════════════════════════════════════════════════════
# 1. to_dict() smoke tests across all data-model modules
# ═══════════════════════════════════════════════════════════════════════════════

class TestToDictDocstrings:
    """Every ``to_dict`` we touched in B99 should have a docstring."""

    @staticmethod
    def _has_docstring(method) -> bool:
        return bool(inspect.getdoc(method))

    # -- trace_ingestion.py -------------------------------------------------

    def test_trace_instruction_to_dict(self):
        from dragonslayer.analysis.trace_ingestion import TraceInstruction
        ti = TraceInstruction(address=0x401000, size=4, raw_bytes=b"\x90\x90\x90\x90",
                             disassembly="nop")
        d = ti.to_dict()
        assert isinstance(d, dict)
        assert "address" in d
        assert self._has_docstring(ti.to_dict)

    def test_trace_memory_access_to_dict(self):
        from dragonslayer.analysis.trace_ingestion import TraceMemoryAccess
        tma = TraceMemoryAccess(type="read", address=0x7FFF0000, size=8)
        d = tma.to_dict()
        assert isinstance(d, dict) and "type" in d
        assert self._has_docstring(tma.to_dict)

    def test_trace_control_flow_to_dict(self):
        from dragonslayer.analysis.trace_ingestion import TraceControlFlow
        cf = TraceControlFlow(type="call", source=0x1000, target=0x2000)
        d = cf.to_dict()
        assert isinstance(d, dict) and "source" in d
        assert self._has_docstring(cf.to_dict)

    def test_handler_marker_to_dict(self):
        from dragonslayer.analysis.trace_ingestion import HandlerMarker
        hm = HandlerMarker(handler_id=1, address=0x5000)
        d = hm.to_dict()
        assert isinstance(d, dict) and "handler_id" in d
        assert self._has_docstring(hm.to_dict)

    def test_execution_trace_to_dict(self):
        from dragonslayer.analysis.trace_ingestion import ExecutionTrace
        et = ExecutionTrace()
        d = et.to_dict()
        assert isinstance(d, dict) and "instruction_count" in d
        assert self._has_docstring(et.to_dict)

    # -- bytecode_extract.py ------------------------------------------------

    def test_vm_opcode_to_dict(self):
        from dragonslayer.analysis.bytecode_extract import VMOpcode
        op = VMOpcode(offset=0, value=0xAB, size=1, handler_address=0x5000)
        d = op.to_dict()
        assert isinstance(d, dict) and "offset" in d
        assert self._has_docstring(op.to_dict)

    def test_opcode_map_to_dict(self):
        from dragonslayer.analysis.bytecode_extract import OpcodeMap
        om = OpcodeMap()
        om.add(0x10, 0x5000, "math")
        d = om.to_dict()
        assert isinstance(d, dict)
        assert self._has_docstring(om.to_dict)

    def test_bytecode_stream_to_dict(self):
        from dragonslayer.analysis.bytecode_extract import BytecodeStream
        bs = BytecodeStream(base_address=0x1000, raw_bytes=b"\x00\x01")
        d = bs.to_dict()
        assert isinstance(d, dict) and "base_address" in d
        assert self._has_docstring(bs.to_dict)

    # -- bytecode_cfg.py ----------------------------------------------------

    def test_vm_instruction_to_dict(self):
        from dragonslayer.analysis.bytecode_cfg import VMInstruction, VMOperation
        vi = VMInstruction(vip=0x100, opcode=0xAA, handler_address=0x5000,
                           operation=VMOperation.ADD)
        d = vi.to_dict()
        assert isinstance(d, dict)
        assert self._has_docstring(vi.to_dict)

    def test_handler_basic_block_to_dict(self):
        from dragonslayer.analysis.bytecode_cfg import HandlerBasicBlock
        bb = HandlerBasicBlock(block_id=0, start_vip=0x100)
        d = bb.to_dict()
        assert isinstance(d, dict)
        assert self._has_docstring(bb.to_dict)

    def test_cfg_edge_to_dict(self):
        from dragonslayer.analysis.bytecode_cfg import CFGEdge
        e = CFGEdge(source_block=0, target_block=1, edge_type="jump")
        d = e.to_dict()
        assert isinstance(d, dict) and "source" in d
        assert self._has_docstring(e.to_dict)

    def test_handler_cfg_to_dict(self):
        from dragonslayer.analysis.bytecode_cfg import HandlerCFG, HandlerBasicBlock
        cfg = HandlerCFG(blocks=[HandlerBasicBlock(block_id=0, start_vip=0)])
        d = cfg.to_dict()
        assert isinstance(d, dict) and "block_count" in d
        assert self._has_docstring(cfg.to_dict)

    def test_natural_loop_to_dict(self):
        from dragonslayer.analysis.bytecode_cfg import NaturalLoop
        nl = NaturalLoop(header=0, body={0, 1})
        d = nl.to_dict()
        assert "header" in d and "body" in d
        assert self._has_docstring(nl.to_dict)

    def test_loop_tree_to_dict(self):
        from dragonslayer.analysis.bytecode_cfg import LoopTree
        lt = LoopTree()
        d = lt.to_dict()
        assert "loop_count" in d
        assert self._has_docstring(lt.to_dict)

    # -- anti_evasion -------------------------------------------------------

    def test_hook_descriptor_to_dict(self):
        from dragonslayer.analysis.anti_evasion.runtime_hooks import HookDescriptor, HookCategory
        hd = HookDescriptor(name="cpuid", category=HookCategory.TIMING, description="CPUID hook")
        d = hd.to_dict()
        assert isinstance(d, dict) and "name" in d
        assert self._has_docstring(hd.to_dict)

    def test_hook_set_to_dict(self):
        from dragonslayer.analysis.anti_evasion.runtime_hooks import HookSet
        hs = HookSet()
        d = hs.to_dict()
        assert "hook_count" in d
        assert self._has_docstring(hs.to_dict)

    def test_hook_install_result_to_dict(self):
        from dragonslayer.analysis.anti_evasion.runtime_hooks import HookInstallResult
        r = HookInstallResult()
        d = r.to_dict()
        assert "installed_count" in d
        assert self._has_docstring(r.to_dict)

    def test_evasion_indicator_to_dict(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import (
            EvasionIndicator, EvasionCategory,
        )
        ei = EvasionIndicator(category=EvasionCategory.ANTI_VM, name="vmtools_key",
                             description="VMware tools registry key")
        d = ei.to_dict()
        assert "category" in d
        assert self._has_docstring(ei.to_dict)

    def test_patch_to_dict(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import Patch
        p = Patch(offset=0x100, original=b"\x00", replacement=b"\x01",
                 description="test patch", indicator_name="test")
        d = p.to_dict()
        assert "offset" in d
        assert self._has_docstring(p.to_dict)

    def test_normalization_report_to_dict(self):
        from dragonslayer.analysis.anti_evasion.environment_normalizer import NormalizationReport
        nr = NormalizationReport()
        d = nr.to_dict()
        assert "indicators" in d
        assert self._has_docstring(nr.to_dict)

    # -- handler_clustering.py ----------------------------------------------

    def test_semantic_cluster_to_dict(self):
        from dragonslayer.analysis.handler_clustering import SemanticCluster
        sc = SemanticCluster(cluster_id=0, operation="ADD", operand_width=4)
        d = sc.to_dict()
        assert "cluster_id" in d
        assert self._has_docstring(sc.to_dict)

    def test_clustering_result_to_dict(self):
        from dragonslayer.analysis.handler_clustering import ClusteringResult
        cr = ClusteringResult()
        d = cr.to_dict()
        assert "cluster_count" in d
        assert self._has_docstring(cr.to_dict)

    # -- pseudocode.py ------------------------------------------------------

    def test_pseudocode_result_to_dict(self):
        from dragonslayer.analysis.pseudocode import PseudocodeResult
        pr = PseudocodeResult(text="x = 1\n", style="c_like")
        d = pr.to_dict()
        assert "line_count" in d
        assert self._has_docstring(pr.to_dict)

    # -- vm_discovery -------------------------------------------------------

    def test_vm_context_register_to_dict(self):
        from dragonslayer.analysis.vm_discovery.context_registers import VMContextRegister
        cr = VMContextRegister(register="rax", role="vIP")
        d = cr.to_dict()
        assert "register" in d
        assert self._has_docstring(cr.to_dict)

    def test_vm_context_layout_to_dict(self):
        from dragonslayer.analysis.vm_discovery.context_registers import VMContextLayout
        cl = VMContextLayout(vip_register="rsi")
        d = cl.to_dict()
        assert "vip_register" in d
        assert self._has_docstring(cl.to_dict)

    def test_handler_boundary_to_dict(self):
        from dragonslayer.analysis.vm_discovery.handler_boundaries import HandlerBoundary
        hb = HandlerBoundary(vip_value=0x100, handler_address=0x5000,
                            trace_start=0, trace_end=10, instruction_count=5)
        d = hb.to_dict()
        assert "vip_value" in d
        assert self._has_docstring(hb.to_dict)

    def test_segmentation_result_to_dict(self):
        from dragonslayer.analysis.vm_discovery.handler_boundaries import SegmentationResult
        sr = SegmentationResult(vip_register="rsi")
        d = sr.to_dict()
        assert "vip_register" in d
        assert self._has_docstring(sr.to_dict)

    def test_vm_entry_candidate_to_dict(self):
        from dragonslayer.analysis.vm_discovery.vm_entry_locator import VmEntryCandidate
        vc = VmEntryCandidate(rva=0x1000, va=0x401000, file_offset=0x400,
                             section_name=".text", confidence=0.9)
        d = vc.to_dict()
        assert "rva" in d
        assert self._has_docstring(vc.to_dict)

    def test_vm_entry_report_to_dict(self):
        from dragonslayer.analysis.vm_discovery.vm_entry_locator import VmEntryReport
        vr = VmEntryReport()
        d = vr.to_dict()
        assert "count" in d
        assert self._has_docstring(vr.to_dict)

    # -- taint_tracking -----------------------------------------------------

    def test_handler_taint_summary_to_dict(self):
        from dragonslayer.analysis.taint_tracking.inter_handler import HandlerTaintSummary
        ts = HandlerTaintSummary(handler_id=0)
        d = ts.to_dict()
        assert "handler_id" in d
        assert self._has_docstring(ts.to_dict)

    def test_inter_handler_flow_edge_to_dict(self):
        from dragonslayer.analysis.taint_tracking.inter_handler import InterHandlerFlowEdge
        e = InterHandlerFlowEdge(source=0, target=1, register="rax")
        d = e.to_dict()
        assert "source" in d
        assert self._has_docstring(e.to_dict)

    def test_inter_handler_flow_result_to_dict(self):
        from dragonslayer.analysis.taint_tracking.inter_handler import InterHandlerFlowResult
        r = InterHandlerFlowResult()
        d = r.to_dict()
        assert "summary_count" in d
        assert self._has_docstring(r.to_dict)

    # -- binary_format.py ---------------------------------------------------

    def test_parsed_binary_to_dict(self):
        from dragonslayer.analysis.binary_format import ParsedBinary
        pb = ParsedBinary.__new__(ParsedBinary)
        pb.format = MagicMock(value="PE")
        pb.architecture = MagicMock(value="x86_64")
        pb.image_base = 0x400000
        pb.entry_point = 0x401000
        pb.sections = []
        pb.imports = []
        pb.exports = []
        pb.data = b""
        d = pb.to_dict()
        assert "format" in d
        assert self._has_docstring(pb.to_dict)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. @property docstrings
# ═══════════════════════════════════════════════════════════════════════════════

class TestPropertyDocstrings:
    """Properties added in B99 should have docstrings."""

    def test_bytecode_stream_length(self):
        from dragonslayer.analysis.bytecode_extract import BytecodeStream
        assert BytecodeStream.length.fget.__doc__

    def test_bytecode_stream_opcode_count(self):
        from dragonslayer.analysis.bytecode_extract import BytecodeStream
        assert BytecodeStream.opcode_count.fget.__doc__

    def test_handler_basic_block_instruction_count(self):
        from dragonslayer.analysis.bytecode_cfg import HandlerBasicBlock
        assert HandlerBasicBlock.instruction_count.fget.__doc__

    def test_handler_cfg_block_count(self):
        from dragonslayer.analysis.bytecode_cfg import HandlerCFG
        assert HandlerCFG.block_count.fget.__doc__

    def test_handler_cfg_edge_count(self):
        from dragonslayer.analysis.bytecode_cfg import HandlerCFG
        assert HandlerCFG.edge_count.fget.__doc__

    def test_natural_loop_is_innermost(self):
        from dragonslayer.analysis.bytecode_cfg import NaturalLoop
        assert NaturalLoop.is_innermost.fget.__doc__

    def test_loop_tree_all_loops(self):
        from dragonslayer.analysis.bytecode_cfg import LoopTree
        assert LoopTree.all_loops.fget.__doc__

    def test_loop_tree_loop_count(self):
        from dragonslayer.analysis.bytecode_cfg import LoopTree
        assert LoopTree.loop_count.fget.__doc__

    def test_hook_install_result_success_count(self):
        from dragonslayer.analysis.anti_evasion.runtime_hooks import HookInstallResult
        assert HookInstallResult.success_count.fget.__doc__

    def test_vm_context_layout_vsp(self):
        from dragonslayer.analysis.vm_discovery.context_registers import VMContextLayout
        assert VMContextLayout.vsp.fget.__doc__

    def test_vm_context_layout_table_base(self):
        from dragonslayer.analysis.vm_discovery.context_registers import VMContextLayout
        assert VMContextLayout.table_base.fget.__doc__

    def test_vm_context_layout_key_register(self):
        from dragonslayer.analysis.vm_discovery.context_registers import VMContextLayout
        assert VMContextLayout.key_register.fget.__doc__

    def test_vm_context_layout_context_base(self):
        from dragonslayer.analysis.vm_discovery.context_registers import VMContextLayout
        assert VMContextLayout.context_base.fget.__doc__

    def test_vm_context_layout_scratch_registers(self):
        from dragonslayer.analysis.vm_discovery.context_registers import VMContextLayout
        assert VMContextLayout.scratch_registers.fget.__doc__

    def test_handler_slice_address_range(self):
        from dragonslayer.analysis.vm_discovery.handler_boundaries import HandlerSlice
        assert HandlerSlice.address_range.fget.__doc__

    def test_vm_entry_report_count(self):
        from dragonslayer.analysis.vm_discovery.vm_entry_locator import VmEntryReport
        assert VmEntryReport.count.fget.__doc__

    def test_writable_sections_property(self):
        from dragonslayer.analysis.binary_format import ParsedBinary
        assert ParsedBinary.writable_sections.fget.__doc__


# ═══════════════════════════════════════════════════════════════════════════════
# 3. ServerState dataclass
# ═══════════════════════════════════════════════════════════════════════════════

class TestServerState:
    """ServerState should be a proper dataclass with typed fields."""

    def test_is_dataclass(self):
        from dragonslayer.api.server import ServerState
        assert is_dataclass(ServerState)

    def test_has_expected_fields(self):
        from dragonslayer.api.server import ServerState
        names = {f.name for f in dc_fields(ServerState)}
        expected = {"start_time", "total_requests", "active_requests",
                    "analysis_count", "api", "rate_limiter"}
        assert expected <= names

    def test_default_values(self):
        from dragonslayer.api.server import ServerState
        s = ServerState()
        assert s.total_requests == 0
        assert s.active_requests == 0
        assert s.analysis_count == 0
        assert s.api is None
        assert isinstance(s.rate_limiter, dict)

    def test_attribute_mutation(self):
        from dragonslayer.api.server import ServerState
        s = ServerState()
        s.total_requests += 5
        assert s.total_requests == 5

    def test_rate_limiter_is_defaultdict(self):
        """rate_limiter should behave like a defaultdict(list)."""
        from dragonslayer.api.server import ServerState
        s = ServerState()
        s.rate_limiter["10.0.0.1"].append(time.time())
        assert len(s.rate_limiter["10.0.0.1"]) == 1

    def test_server_state_module_instance(self):
        """Module-level server_state should be a ServerState instance."""
        from dragonslayer.api.server import server_state, ServerState
        assert isinstance(server_state, ServerState)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Pipeline shared pool (no per-stage executor leak)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPipelineSharedPool:
    """Pipeline should use a single ThreadPoolExecutor for all stages."""

    def test_no_per_stage_executor_creation(self):
        """Source code should not create a ThreadPoolExecutor inside the loop body."""
        import dragonslayer.core.pipeline as pipeline_mod
        source = inspect.getsource(pipeline_mod.AnalysisPipeline.run)
        # The old pattern created the pool inside the for-loop.
        # The new pattern creates it once before the loop.
        # Count how many times ThreadPoolExecutor appears — should be exactly 1
        # in the run method.
        count = source.count("ThreadPoolExecutor(max_workers=1)")
        assert count == 1, f"Expected 1 shared pool creation, got {count}"

    def test_shared_pool_submits_stages(self):
        """Stage handler should be submitted to a pool and the result awaited."""
        import dragonslayer.core.pipeline as pipeline_mod
        source = inspect.getsource(pipeline_mod.AnalysisPipeline.run)
        assert "stage_pool.submit(handler)" in source


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Return-type annotations
# ═══════════════════════════════════════════════════════════════════════════════

class TestReturnTypeAnnotations:
    """Methods fixed in B99 should have return type annotations."""

    def test_exception_init_returns_none(self):
        from dragonslayer.core.exceptions import VMDragonSlayerError
        hints = get_type_hints(VMDragonSlayerError.__init__)
        assert hints.get("return") is type(None)

    def test_pattern_recognizer_init_returns_none(self):
        from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
        hints = get_type_hints(PatternRecognizer.__init__)
        assert hints.get("return") is type(None)

    def test_analyze_binary_has_return_type(self):
        from dragonslayer.api.server import analyze_binary
        hints = get_type_hints(analyze_binary)
        assert "return" in hints

    def test_upload_and_analyze_has_return_type(self):
        from dragonslayer.api.server import upload_and_analyze
        hints = get_type_hints(upload_and_analyze)
        assert "return" in hints

    def test_analysis_result_to_dict_returns_typed_dict(self):
        """AnalysisResult.to_dict() should return AnalysisResultDict."""
        from dragonslayer.core.orchestrator import AnalysisResult
        hints = get_type_hints(AnalysisResult.to_dict)
        ret = hints.get("return")
        assert ret is not None
        assert ret.__name__ == "AnalysisResultDict" if hasattr(ret, "__name__") else "AnalysisResultDict" in str(ret)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. VMInstruction predicates (bytecode_cfg.py)
# ═══════════════════════════════════════════════════════════════════════════════

class TestVMInstructionPredicates:
    """VMInstruction boolean predicates should have docstrings."""

    @pytest.fixture
    def vm_instruction(self):
        from dragonslayer.analysis.bytecode_cfg import VMInstruction, VMOperation
        return VMInstruction(vip=0, opcode=0, handler_address=0,
                             operation=VMOperation.JMP)

    def test_is_branch_docstring(self, vm_instruction):
        assert vm_instruction.is_branch.__doc__

    def test_is_unconditional_jump_docstring(self, vm_instruction):
        assert vm_instruction.is_unconditional_jump.__doc__

    def test_is_conditional_jump_docstring(self, vm_instruction):
        assert vm_instruction.is_conditional_jump.__doc__

    def test_is_call_docstring(self, vm_instruction):
        assert vm_instruction.is_call.__doc__

    def test_is_return_docstring(self, vm_instruction):
        assert vm_instruction.is_return.__doc__

    def test_is_terminator_docstring(self, vm_instruction):
        assert vm_instruction.is_terminator.__doc__

    def test_jmp_is_branch(self, vm_instruction):
        assert vm_instruction.is_branch() is True

    def test_jmp_is_unconditional(self, vm_instruction):
        assert vm_instruction.is_unconditional_jump() is True

    def test_jmp_is_terminator(self, vm_instruction):
        assert vm_instruction.is_terminator() is True


# ═══════════════════════════════════════════════════════════════════════════════
# 7. HandlerCFG query methods
# ═══════════════════════════════════════════════════════════════════════════════

class TestHandlerCFGQueries:
    """HandlerCFG methods should have docstrings and work correctly."""

    @pytest.fixture
    def sample_cfg(self):
        from dragonslayer.analysis.bytecode_cfg import (
            HandlerCFG, HandlerBasicBlock, CFGEdge,
        )
        b0 = HandlerBasicBlock(block_id=0, start_vip=0x100, is_entry=True)
        b1 = HandlerBasicBlock(block_id=1, start_vip=0x200, is_exit=True)
        edges = [
            CFGEdge(source_block=0, target_block=1, edge_type="jump"),
            CFGEdge(source_block=1, target_block=0, edge_type="back_edge"),
        ]
        return HandlerCFG(blocks=[b0, b1], edges=edges)

    def test_find_block(self, sample_cfg):
        b = sample_cfg.find_block(1)
        assert b is not None and b.start_vip == 0x200
        assert sample_cfg.find_block.__doc__

    def test_find_block_by_vip(self, sample_cfg):
        b = sample_cfg.find_block_by_vip(0x100)
        assert b is not None and b.block_id == 0
        assert sample_cfg.find_block_by_vip.__doc__

    def test_back_edges(self, sample_cfg):
        bes = sample_cfg.back_edges()
        assert len(bes) == 1
        assert sample_cfg.back_edges.__doc__

    def test_exit_blocks(self, sample_cfg):
        exits = sample_cfg.exit_blocks()
        assert len(exits) == 1 and exits[0].block_id == 1
        assert sample_cfg.exit_blocks.__doc__

    def test_summary_has_docstring(self, sample_cfg):
        s = sample_cfg.summary()
        assert isinstance(s, str) and "block" in s.lower()
        assert sample_cfg.summary.__doc__


# ═══════════════════════════════════════════════════════════════════════════════
# 8. LoopTree queries
# ═══════════════════════════════════════════════════════════════════════════════

class TestLoopTreeQueries:
    """LoopTree methods should have docstrings."""

    @pytest.fixture
    def loop_tree(self):
        from dragonslayer.analysis.bytecode_cfg import LoopTree
        raw_loops = [
            {"header": 0, "back_edge_source": 2, "body": {0, 1, 2}},
            {"header": 1, "back_edge_source": 1, "body": {1}},
        ]
        return LoopTree(loops=raw_loops)

    def test_get_loop(self, loop_tree):
        lp = loop_tree.get_loop(0)
        assert lp is not None
        assert loop_tree.get_loop.__doc__

    def test_innermost_loops(self, loop_tree):
        inner = loop_tree.innermost_loops()
        assert len(inner) >= 1
        assert loop_tree.innermost_loops.__doc__

    def test_loop_for_block(self, loop_tree):
        lp = loop_tree.loop_for_block(1)
        assert lp is not None
        assert loop_tree.loop_for_block.__doc__

    def test_is_reducible(self, loop_tree):
        assert loop_tree.is_reducible() is True


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Additional coverage: OpcodeMap, BytecodeStream, context_registers
# ═══════════════════════════════════════════════════════════════════════════════

class TestOpcodeMapMethods:
    """OpcodeMap.add / .handler_for should have docstrings."""

    def test_add_has_docstring(self):
        from dragonslayer.analysis.bytecode_extract import OpcodeMap
        assert OpcodeMap.add.__doc__

    def test_handler_for_has_docstring(self):
        from dragonslayer.analysis.bytecode_extract import OpcodeMap
        assert OpcodeMap.handler_for.__doc__

    def test_opcode_at_has_docstring(self):
        from dragonslayer.analysis.bytecode_extract import BytecodeStream
        assert BytecodeStream.opcode_at.__doc__


class TestContextLayoutProperties:
    """VMContextLayout property methods should work and have docstrings."""

    @pytest.fixture
    def layout(self):
        from dragonslayer.analysis.vm_discovery.context_registers import (
            VMContextLayout, VMContextRegister,
        )
        regs = [
            VMContextRegister(register="rsi", role="vIP"),
            VMContextRegister(register="rdi", role="vSP"),
            VMContextRegister(register="rbx", role="vHandlerTbl"),
            VMContextRegister(register="rcx", role="vKey"),
            VMContextRegister(register="rdx", role="vContext"),
            VMContextRegister(register="rax", role="scratch"),
        ]
        return VMContextLayout(vip_register="rsi", registers=regs)

    def test_vsp(self, layout):
        assert layout.vsp == "rdi"

    def test_table_base(self, layout):
        assert layout.table_base == "rbx"

    def test_key_register(self, layout):
        assert layout.key_register == "rcx"

    def test_context_base(self, layout):
        assert layout.context_base == "rdx"

    def test_scratch_registers(self, layout):
        assert "rax" in layout.scratch_registers

    def test_get_register_role(self, layout):
        assert layout.get_register_role("rsi") == "vIP"
        assert layout.get_register_role("r15") is None
        assert layout.get_register_role.__doc__


class TestVmEntryReportMethods:
    """VmEntryReport helper methods."""

    def test_top_returns_sorted(self):
        from dragonslayer.analysis.vm_discovery.vm_entry_locator import (
            VmEntryReport, VmEntryCandidate,
        )
        entries = [
            VmEntryCandidate(rva=0x100, va=0x400100, file_offset=0x100,
                             section_name=".text", confidence=0.5),
            VmEntryCandidate(rva=0x200, va=0x400200, file_offset=0x200,
                             section_name=".text", confidence=0.9),
        ]
        report = VmEntryReport(entries=entries)
        top = report.top(1)
        assert len(top) == 1
        assert top[0].rva == 0x200
        assert report.top.__doc__


class TestHookSetByCategory:
    """HookSet.by_category should filter correctly."""

    def test_by_category_filters(self):
        from dragonslayer.analysis.anti_evasion.runtime_hooks import (
            HookSet, HookDescriptor, HookCategory,
        )
        hooks = [
            HookDescriptor(name="a", category=HookCategory.TIMING, description="Hook A"),
            HookDescriptor(name="b", category=HookCategory.DEBUG, description="Hook B"),
        ]
        hs = HookSet(hooks=hooks, categories={HookCategory.TIMING, HookCategory.DEBUG})
        timing = hs.by_category(HookCategory.TIMING)
        assert len(timing) == 1 and timing[0].name == "a"
        assert hs.by_category.__doc__
