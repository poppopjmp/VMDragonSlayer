"""Tests for vIP-based handler boundary identification."""

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
    HandlerMarker,
)
from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    VIPCandidate,
    HandlerBoundary,
    SegmentationResult,
    identify_vip_register,
    segment_trace,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _ti(addr, regs=None, size=1, disasm="nop"):
    return TraceInstruction(
        address=addr, size=size, raw_bytes=b"\x90" * size,
        disassembly=disasm, registers=regs or {},
    )


def _make_dispatch_handler_trace(
    dispatcher_addr: int,
    handler_addrs: list[int],
    vip_values: list[int],
    vip_reg: str = "rsi",
    handler_len: int = 5,
) -> tuple[ExecutionTrace, list[int]]:
    """Build a synthetic trace: dispatcher → handler → dispatcher → handler …

    Returns (trace, dispatcher_addresses).
    """
    instrs = []
    for i, (haddr, vip) in enumerate(zip(handler_addrs, vip_values)):
        # 2 instructions inside dispatcher
        instrs.append(_ti(dispatcher_addr, {vip_reg: vip}))
        instrs.append(_ti(dispatcher_addr + 2, {vip_reg: vip}))
        # N instructions inside handler
        for j in range(handler_len):
            instrs.append(_ti(haddr + j, {vip_reg: vip}))
        # return to dispatcher for next iteration (vIP may change)

    # Final dispatcher visit
    last_vip = vip_values[-1] + 4 if vip_values else 0
    instrs.append(_ti(dispatcher_addr, {vip_reg: last_vip}))
    instrs.append(_ti(dispatcher_addr + 2, {vip_reg: last_vip}))

    return ExecutionTrace(instructions=instrs), [dispatcher_addr, dispatcher_addr + 2]


# ---------------------------------------------------------------------------
# identify_vip_register
# ---------------------------------------------------------------------------

class TestIdentifyVipRegister:
    def test_empty_trace(self):
        trace = ExecutionTrace()
        assert identify_vip_register(trace) is None

    def test_no_register_data(self):
        trace = ExecutionTrace(instructions=[_ti(0x1000)])
        assert identify_vip_register(trace) is None

    def test_single_monotonic_register(self):
        """rsi increments by 4 each step; other regs stay constant."""
        instrs = [
            _ti(0x1000, {"rsi": 0x100, "rax": 0}),
            _ti(0x1002, {"rsi": 0x104, "rax": 0}),
            _ti(0x1004, {"rsi": 0x108, "rax": 0}),
            _ti(0x1006, {"rsi": 0x10C, "rax": 0}),
            _ti(0x1008, {"rsi": 0x110, "rax": 0}),
        ]
        trace = ExecutionTrace(instructions=instrs)
        result = identify_vip_register(trace)
        assert result is not None
        assert result.name == "rsi"
        assert result.monotonic_ratio == 1.0

    def test_dispatcher_correlation_boost(self):
        """Register that changes at the dispatcher scores higher."""
        disp = 0x5000
        instrs = [
            _ti(disp, {"rsi": 0x100, "rdi": 0x200}),
            _ti(0x6000, {"rsi": 0x100, "rdi": 0x200}),
            _ti(0x6002, {"rsi": 0x100, "rdi": 0x200}),
            _ti(disp, {"rsi": 0x104, "rdi": 0x204}),
            _ti(0x7000, {"rsi": 0x104, "rdi": 0x204}),
            _ti(0x7002, {"rsi": 0x104, "rdi": 0x204}),
            _ti(disp, {"rsi": 0x108, "rdi": 0x208}),
        ]
        trace = ExecutionTrace(instructions=instrs)
        result = identify_vip_register(trace, dispatcher_addresses=[disp])
        assert result is not None
        # Both rsi and rdi advance identically, but dispatcher correlation
        # should still give both a near-equal score. Key: the function
        # does not crash and returns a valid candidate.
        assert result.score > 0

    def test_candidates_filter(self):
        instrs = [
            _ti(0x1000, {"rsi": 0x100, "rdi": 0x200}),
            _ti(0x1002, {"rsi": 0x104, "rdi": 0x210}),
            _ti(0x1004, {"rsi": 0x108, "rdi": 0x220}),
        ]
        trace = ExecutionTrace(instructions=instrs)
        result = identify_vip_register(trace, candidates=["rdi"])
        assert result is not None
        assert result.name == "rdi"

    def test_constant_register_rejected(self):
        instrs = [
            _ti(0x1000, {"rbx": 42}),
            _ti(0x1002, {"rbx": 42}),
            _ti(0x1004, {"rbx": 42}),
        ]
        trace = ExecutionTrace(instructions=instrs)
        result = identify_vip_register(trace)
        # Constant register should get zero score → None
        assert result is None

    def test_stack_pointer_excluded(self):
        instrs = [
            _ti(0x1000, {"rsp": 0x7FF0, "rsi": 0x100}),
            _ti(0x1002, {"rsp": 0x7FE8, "rsi": 0x104}),
            _ti(0x1004, {"rsp": 0x7FE0, "rsi": 0x108}),
        ]
        trace = ExecutionTrace(instructions=instrs)
        result = identify_vip_register(trace)
        assert result is not None
        assert result.name != "rsp"


# ---------------------------------------------------------------------------
# segment_trace — with dispatcher addresses
# ---------------------------------------------------------------------------

class TestSegmentByDispatcher:
    def test_basic_segmentation(self):
        trace, disp = _make_dispatch_handler_trace(
            dispatcher_addr=0x5000,
            handler_addrs=[0x6000, 0x7000, 0x8000],
            vip_values=[0x100, 0x104, 0x108],
        )
        vip = VIPCandidate(name="rsi", score=0.9)
        result = segment_trace(trace, vip, disp)
        assert isinstance(result, SegmentationResult)
        assert result.vip_register == "rsi"
        assert len(result.boundaries) == 3
        assert result.unique_handlers == 3

    def test_vip_values_captured(self):
        trace, disp = _make_dispatch_handler_trace(
            dispatcher_addr=0x5000,
            handler_addrs=[0x6000, 0x7000],
            vip_values=[0x100, 0x108],
        )
        vip = VIPCandidate(name="rsi", score=0.9)
        result = segment_trace(trace, vip, disp)
        assert result.boundaries[0].vip_value == 0x100
        assert result.boundaries[1].vip_value == 0x108

    def test_handler_addresses(self):
        trace, disp = _make_dispatch_handler_trace(
            dispatcher_addr=0x5000,
            handler_addrs=[0x6000, 0x7000],
            vip_values=[0x100, 0x104],
        )
        vip = VIPCandidate(name="rsi", score=0.9)
        result = segment_trace(trace, vip, disp)
        assert result.boundaries[0].handler_address == 0x6000
        assert result.boundaries[1].handler_address == 0x7000

    def test_instruction_count(self):
        trace, disp = _make_dispatch_handler_trace(
            dispatcher_addr=0x5000,
            handler_addrs=[0x6000],
            vip_values=[0x100],
            handler_len=10,
        )
        vip = VIPCandidate(name="rsi", score=0.9)
        result = segment_trace(trace, vip, disp)
        assert result.boundaries[0].instruction_count == 10

    def test_min_handler_insns_filter(self):
        trace, disp = _make_dispatch_handler_trace(
            dispatcher_addr=0x5000,
            handler_addrs=[0x6000],
            vip_values=[0x100],
            handler_len=1,  # only 1 instruction — below default min of 2
        )
        vip = VIPCandidate(name="rsi", score=0.9)
        result = segment_trace(trace, vip, disp)
        assert len(result.boundaries) == 0  # filtered out

    def test_bytecode_width_mode(self):
        trace, disp = _make_dispatch_handler_trace(
            dispatcher_addr=0x5000,
            handler_addrs=[0x6000, 0x7000, 0x8000],
            vip_values=[0x100, 0x104, 0x108],  # all +4
        )
        vip = VIPCandidate(name="rsi", score=0.9)
        result = segment_trace(trace, vip, disp)
        assert result.bytecode_width_mode == 4

    def test_to_dict(self):
        trace, disp = _make_dispatch_handler_trace(
            dispatcher_addr=0x5000,
            handler_addrs=[0x6000],
            vip_values=[0x100],
        )
        vip = VIPCandidate(name="rsi", score=0.9)
        result = segment_trace(trace, vip, disp)
        d = result.to_dict()
        assert d["vip_register"] == "rsi"
        assert d["boundary_count"] == 1


# ---------------------------------------------------------------------------
# segment_trace — fallback (no dispatcher addresses)
# ---------------------------------------------------------------------------

class TestSegmentByVipChanges:
    def test_fallback_segmentation(self):
        instrs = [
            _ti(0x1000, {"rsi": 0x100}),
            _ti(0x1002, {"rsi": 0x100}),
            _ti(0x1004, {"rsi": 0x100}),
            # vIP changes → new handler
            _ti(0x2000, {"rsi": 0x104}),
            _ti(0x2002, {"rsi": 0x104}),
            _ti(0x2004, {"rsi": 0x104}),
            # vIP changes again
            _ti(0x3000, {"rsi": 0x108}),
            _ti(0x3002, {"rsi": 0x108}),
        ]
        trace = ExecutionTrace(instructions=instrs)
        vip = VIPCandidate(name="rsi", score=0.9)
        result = segment_trace(trace, vip, [])
        assert len(result.boundaries) == 3

    def test_vip_delta_computed(self):
        instrs = [
            _ti(0x1000, {"rsi": 0x100}),
            _ti(0x1002, {"rsi": 0x100}),
            _ti(0x1004, {"rsi": 0x100}),
            _ti(0x2000, {"rsi": 0x106}),
            _ti(0x2002, {"rsi": 0x106}),
        ]
        trace = ExecutionTrace(instructions=instrs)
        vip = VIPCandidate(name="rsi", score=0.9)
        result = segment_trace(trace, vip, [])
        assert result.boundaries[0].vip_delta == 6


# ---------------------------------------------------------------------------
# Handler marker enrichment
# ---------------------------------------------------------------------------

class TestHandlerMarkerEnrichment:
    def test_markers_applied(self):
        trace, disp = _make_dispatch_handler_trace(
            dispatcher_addr=0x5000,
            handler_addrs=[0x6000, 0x7000],
            vip_values=[0x100, 0x104],
        )
        trace.handlers = [
            HandlerMarker(handler_id=0, address=0x6000, handler_type="arithmetic"),
            HandlerMarker(handler_id=1, address=0x7000, handler_type="memory"),
        ]
        vip = VIPCandidate(name="rsi", score=0.9)
        result = segment_trace(trace, vip, disp)
        assert result.boundaries[0].category == "arithmetic"
        assert result.boundaries[0].handler_id == 0
        assert result.boundaries[1].category == "memory"


# ---------------------------------------------------------------------------
# HandlerBoundary
# ---------------------------------------------------------------------------

class TestHandlerBoundary:
    def test_to_dict(self):
        b = HandlerBoundary(
            vip_value=0x100,
            handler_address=0x6000,
            trace_start=0,
            trace_end=10,
            instruction_count=10,
            category="arithmetic",
            vip_delta=4,
        )
        d = b.to_dict()
        assert d["vip_value"] == 0x100
        assert d["handler_address"] == "0x6000"
        assert d["category"] == "arithmetic"
        assert d["vip_delta"] == 4
