"""Batch 22 — Symbolic Depth integration tests.

Tests for extract_symbolic_summaries, run_handler_symbolic_execution,
and collect_symbolic_summaries.
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from dragonslayer.analysis.symbolic_depth import (
    extract_symbolic_summaries,
    run_handler_symbolic_execution,
    collect_symbolic_summaries,
    _handler_info_to_summary,
    _snapshot_to_summary,
    _extraction_to_summary,
)


# ═══════════════════════════════════════════════════════════════════════
# _handler_info_to_summary
# ═══════════════════════════════════════════════════════════════════════

class TestHandlerInfoToSummary:
    def test_basic(self):
        h = {
            "address": 0x1000,
            "instruction_count": 5,
            "register_effects": {"rax": "init_rax + init_rbx"},
        }
        s = _handler_info_to_summary(h)
        assert s["address"] == 0x1000
        assert s["final_registers"]["rax"] == "init_rax + init_rbx"

    def test_empty(self):
        s = _handler_info_to_summary({})
        assert s["address"] == 0
        assert s["final_registers"] == {}


# ═══════════════════════════════════════════════════════════════════════
# _snapshot_to_summary
# ═══════════════════════════════════════════════════════════════════════

class TestSnapshotToSummary:
    def test_with_registers_key(self):
        snap = {
            "registers": {"rax": 42, "rbx": 99},
            "instruction_count": 3,
        }
        s = _snapshot_to_summary(0x2000, snap)
        assert s["address"] == 0x2000
        assert s["final_registers"]["rax"] == "42"
        assert s["final_registers"]["rbx"] == "99"

    def test_filters_pc_registers(self):
        snap = {"registers": {"rax": 1, "rip": 0x4000, "pc": 0x4000}}
        s = _snapshot_to_summary(0x1000, snap)
        assert "rip" not in s["final_registers"]
        assert "pc" not in s["final_registers"]


# ═══════════════════════════════════════════════════════════════════════
# _extraction_to_summary
# ═══════════════════════════════════════════════════════════════════════

class TestExtractionToSummary:
    def test_positive_delta(self):
        h = {
            "address": 0x3000,
            "register_delta": {
                "rsp": {"before": 100, "after": 108},
            },
        }
        s = _extraction_to_summary(h)
        assert "init_rsp" in s["final_registers"]["rsp"]
        assert "+ 0x8" in s["final_registers"]["rsp"]
        assert s["input_symbols"]["rsp"] == "init_rsp"

    def test_negative_delta(self):
        h = {
            "address": 0x3000,
            "register_delta": {
                "rsp": {"before": 200, "after": 192},
            },
        }
        s = _extraction_to_summary(h)
        assert "- 0x8" in s["final_registers"]["rsp"]

    def test_zero_delta(self):
        h = {
            "address": 0x3000,
            "register_delta": {"rax": {"before": 5, "after": 5}},
        }
        s = _extraction_to_summary(h)
        assert s["final_registers"]["rax"] == "init_rax"

    def test_scalar_delta(self):
        h = {
            "address": 0x3000,
            "register_delta": {"rax": 8},
        }
        s = _extraction_to_summary(h)
        assert "0x8" in s["final_registers"]["rax"]

    def test_no_deltas(self):
        s = _extraction_to_summary({"address": 0x3000})
        assert s["final_registers"] == {}


# ═══════════════════════════════════════════════════════════════════════
# extract_symbolic_summaries
# ═══════════════════════════════════════════════════════════════════════

class TestExtractSymbolicSummaries:
    def test_empty_shared_data(self):
        summaries = extract_symbolic_summaries({})
        assert summaries == {}

    def test_source1_handler_summaries(self):
        shared = {
            "symbolic_execution": {
                "handler_summaries": {
                    0x1000: {
                        "address": 0x1000,
                        "final_registers": {"rax": "init_rbx"},
                    },
                    0x2000: {
                        "address": 0x2000,
                        "final_registers": {"rax": "init_rcx"},
                    },
                },
            },
        }
        summaries = extract_symbolic_summaries(shared)
        assert len(summaries) == 2
        assert summaries[0x1000]["final_registers"]["rax"] == "init_rbx"

    def test_source2_handlers_list(self):
        shared = {
            "symbolic_execution": {
                "handlers": [
                    {"address": 0x1000, "instruction_count": 5,
                     "register_effects": {"rax": "42"}},
                    {"address": 0x2000, "instruction_count": 3},
                ],
            },
        }
        summaries = extract_symbolic_summaries(shared)
        assert 0x1000 in summaries
        assert 0x2000 in summaries

    def test_source3_angr_snapshots(self):
        shared = {
            "symbolic_execution": {},
            "angr": {
                "register_snapshots": {
                    0x3000: {"registers": {"rax": 10, "rbx": 20}},
                },
            },
        }
        summaries = extract_symbolic_summaries(shared)
        assert 0x3000 in summaries
        assert summaries[0x3000]["final_registers"]["rax"] == "10"

    def test_source3_triton_snapshots_list(self):
        shared = {
            "symbolic_execution": {},
            "triton": {
                "snapshots": [
                    {"address": 0x4000, "registers": {"rax": 5}},
                ],
            },
        }
        summaries = extract_symbolic_summaries(shared)
        assert 0x4000 in summaries

    def test_source4_handler_extraction(self):
        shared = {
            "handler_extraction": {
                "handlers": [
                    {
                        "address": 0x5000,
                        "register_delta": {"rsp": {"before": 100, "after": 92}},
                    },
                ],
            },
        }
        summaries = extract_symbolic_summaries(shared)
        assert 0x5000 in summaries
        assert "init_rsp" in summaries[0x5000]["final_registers"]["rsp"]

    def test_priority_no_overwrite(self):
        """Source 2 should not overwrite source 1 when handler_summaries exist."""
        shared = {
            "symbolic_execution": {
                "handler_summaries": {
                    0x1000: {
                        "address": 0x1000,
                        "final_registers": {"rax": "from_summaries"},
                    },
                },
                "handlers": [
                    {"address": 0x1000, "instruction_count": 5,
                     "register_effects": {"rax": "from_handlers"}},
                ],
            },
        }
        summaries = extract_symbolic_summaries(shared)
        assert summaries[0x1000]["final_registers"]["rax"] == "from_summaries"


# ═══════════════════════════════════════════════════════════════════════
# run_handler_symbolic_execution
# ═══════════════════════════════════════════════════════════════════════

class TestRunHandlerSymbolicExecution:
    def test_empty_inputs(self):
        result = run_handler_symbolic_execution([])
        assert result == {}

    def test_dict_form(self):
        """Dict-form handler bodies should be accepted."""
        # NOP sled — valid x86 but trivial
        bodies = [
            {"address": 0x1000, "raw_bytes": "90" * 3 + "c3"},  # nop;nop;nop;ret
        ]
        result = run_handler_symbolic_execution(bodies, bit_width=64)
        assert 0x1000 in result
        assert "error" not in result[0x1000] or result[0x1000]["error"] is None

    def test_no_raw_bytes_skipped(self):
        bodies = [{"address": 0x2000, "raw_bytes": ""}]
        result = run_handler_symbolic_execution(bodies, bit_width=64)
        assert 0x2000 not in result

    def test_max_handlers_cap(self):
        bodies = [
            {"address": 0x1000 + i * 0x100, "raw_bytes": "90c3"}
            for i in range(10)
        ]
        result = run_handler_symbolic_execution(bodies, bit_width=64, max_handlers=3)
        assert len(result) <= 3


# ═══════════════════════════════════════════════════════════════════════
# collect_symbolic_summaries
# ═══════════════════════════════════════════════════════════════════════

class TestCollectSymbolicSummaries:
    def test_empty(self):
        result = collect_symbolic_summaries({})
        assert result == {}

    def test_prefers_existing_summaries(self):
        shared = {
            "symbolic_execution": {
                "handler_summaries": {
                    0x1000: {"address": 0x1000, "final_registers": {}},
                },
            },
        }
        result = collect_symbolic_summaries(shared, run_fresh=False)
        assert 0x1000 in result

    def test_supplements_with_fresh_se(self):
        """When coverage is low and handler_bodies are provided, fresh SE runs."""
        from dragonslayer.analysis.vm_discovery.handler_boundaries import HandlerBoundary
        boundaries = [
            HandlerBoundary(vip_value=0, handler_address=0x1000,
                            vip_delta=1, instruction_count=3,
                            trace_start=0, trace_end=3),
            HandlerBoundary(vip_value=1, handler_address=0x2000,
                            vip_delta=1, instruction_count=3,
                            trace_start=3, trace_end=6),
        ]
        bodies = [
            {"address": 0x1000, "raw_bytes": "90" * 3 + "c3"},
            {"address": 0x2000, "raw_bytes": "90c3"},
        ]
        result = collect_symbolic_summaries(
            {},
            boundaries=boundaries,
            handler_bodies=bodies,
            run_fresh=True,
        )
        # Should have run fresh SE for both
        assert len(result) >= 2
        assert 0x1000 in result
        assert 0x2000 in result

    def test_run_fresh_false_skips(self):
        from dragonslayer.analysis.vm_discovery.handler_boundaries import HandlerBoundary
        boundaries = [
            HandlerBoundary(vip_value=0, handler_address=0x1000,
                            vip_delta=1, instruction_count=3,
                            trace_start=0, trace_end=3),
        ]
        bodies = [{"address": 0x1000, "raw_bytes": "90c3"}]
        result = collect_symbolic_summaries(
            {},
            boundaries=boundaries,
            handler_bodies=bodies,
            run_fresh=False,
        )
        # Without existing data and run_fresh=False, nothing from fresh SE
        assert len(result) == 0
