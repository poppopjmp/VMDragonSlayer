"""
B68 — Dispatcher confidence, structured logging, streaming decryption, async ctx
=====================================================================================

Tests covering the B68 batch of improvements:

1. ``_find_dispatcher`` returns ``(address, confidence)`` tuple.
2. ``_JSONFormatter`` emits valid JSON log records.
3. ``_configure_logging`` respects ``VMDS_LOG_FORMAT`` env-var.
4. ``Z3Solver.solve_xor_key_schedule`` recovers XOR keys.
5. ``Z3Solver.solve_chained_decryption`` handles CBC-like chains.
6. ``Orchestrator`` supports async context manager protocol.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# 1. Dispatcher confidence
# ---------------------------------------------------------------------------

from dragonslayer.analysis.symbolic_execution.executor import (
    ExecutionResult,
    SymbolicExecutor,
)
from dragonslayer.analysis.symbolic_execution.lifter import (
    InstructionCategory,
    LiftedInstruction,
)


def _make_insn(addr, cat, target=None, mnemonic="jmp"):
    """Shorthand to build a ``LiftedInstruction``."""
    return LiftedInstruction(
        address=addr,
        size=2,
        mnemonic=mnemonic,
        operands="rax",
        raw_bytes=b"\xff\xe0",
        category=cat,
        branch_target=target,
    )


class TestDispatcherConfidence:
    """Confidence values from ``_find_dispatcher``."""

    def test_no_candidates_returns_none_and_zero(self):
        insns = [_make_insn(0x100, InstructionCategory.BRANCH_COND, target=0x200)]
        addr, conf = SymbolicExecutor._find_dispatcher(insns)
        assert addr is None
        assert conf == 0.0

    def test_single_candidate_moderate_confidence(self):
        insns = [_make_insn(0x100, InstructionCategory.BRANCH_UNCOND, target=None)]
        addr, conf = SymbolicExecutor._find_dispatcher(insns)
        assert addr == 0x100
        assert conf == 0.5

    def test_two_candidates_winner_has_higher_confidence(self):
        # Indirect jump A at 0x200 — no back-edges
        ij_a = _make_insn(0x200, InstructionCategory.BRANCH_UNCOND, target=None)
        # Indirect jump B at 0x400 — two back-edges
        ij_b = _make_insn(0x400, InstructionCategory.BRANCH_UNCOND, target=None)
        br1 = _make_insn(0x350, InstructionCategory.BRANCH_COND, target=0x3F0, mnemonic="jne")
        br2 = _make_insn(0x360, InstructionCategory.BRANCH_UNCOND, target=0x3E0, mnemonic="jmp")

        addr, conf = SymbolicExecutor._find_dispatcher([ij_a, br1, br2, ij_b])
        assert addr == 0x400
        assert 0.0 < conf <= 1.0

    def test_no_back_edge_evidence_low_confidence(self):
        """Two candidates, no branch targets near either → low confidence."""
        ij_a = _make_insn(0x1000, InstructionCategory.BRANCH_UNCOND, target=None)
        ij_b = _make_insn(0x2000, InstructionCategory.BRANCH_UNCOND, target=None)
        # Only a branch far away from both
        br = _make_insn(0x5000, InstructionCategory.BRANCH_COND, target=0x9000, mnemonic="jne")
        addr, conf = SymbolicExecutor._find_dispatcher([ij_a, ij_b, br])
        assert conf <= 0.2  # fallback low confidence

    def test_confidence_clamped_01(self):
        """Confidence is always in [0, 1]."""
        for _ in range(5):
            insns = [
                _make_insn(0x100, InstructionCategory.BRANCH_UNCOND, target=None),
                _make_insn(0x150, InstructionCategory.BRANCH_COND, target=0x100, mnemonic="jne"),
                _make_insn(0x160, InstructionCategory.BRANCH_COND, target=0x100, mnemonic="je"),
                _make_insn(0x170, InstructionCategory.BRANCH_COND, target=0x100, mnemonic="jle"),
            ]
            _, conf = SymbolicExecutor._find_dispatcher(insns)
            assert 0.0 <= conf <= 1.0


class TestExecutionResultDispatcherConfidence:
    """``ExecutionResult`` exposes ``dispatcher_confidence``."""

    def test_default_zero(self):
        r = ExecutionResult(success=True)
        assert r.dispatcher_confidence == 0.0

    def test_survives_to_dict_round_trip(self):
        r = ExecutionResult(success=True, dispatcher_confidence=0.85)
        d = r.to_dict()
        assert d["dispatcher_confidence"] == 0.85


# ---------------------------------------------------------------------------
# 2. Structured JSON logging
# ---------------------------------------------------------------------------

from dragonslayer.api.server import _JSONFormatter, _configure_logging


class TestJSONFormatter:
    """``_JSONFormatter`` produces valid JSON lines."""

    def test_basic_record_is_valid_json(self):
        fmt = _JSONFormatter()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Hello %s",
            args=("world",),
            exc_info=None,
        )
        line = fmt.format(record)
        obj = json.loads(line)
        assert obj["level"] == "INFO"
        assert obj["msg"] == "Hello world"
        assert "ts" in obj
        assert obj["logger"] == "test.logger"

    def test_exception_included(self):
        fmt = _JSONFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys
            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test", level=logging.ERROR, pathname="t.py",
            lineno=1, msg="fail", args=(), exc_info=exc_info,
        )
        line = fmt.format(record)
        obj = json.loads(line)
        assert "exception" in obj
        assert "boom" in obj["exception"]

    def test_request_id_propagated(self):
        fmt = _JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="t.py",
            lineno=1, msg="req", args=(), exc_info=None,
        )
        record.request_id = "abc-123"  # type: ignore[attr-defined]
        obj = json.loads(fmt.format(record))
        assert obj["request_id"] == "abc-123"


class TestConfigureLogging:
    """``_configure_logging`` respects ``VMDS_LOG_FORMAT`` env-var."""

    def test_json_format_uses_json_formatter(self):
        with patch.dict(os.environ, {"VMDS_LOG_FORMAT": "json"}):
            _configure_logging()
        root = logging.getLogger()
        stream_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler)]
        assert any(isinstance(h.formatter, _JSONFormatter) for h in stream_handlers)

    def test_text_format_is_default(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VMDS_LOG_FORMAT", None)
            _configure_logging()
        root = logging.getLogger()
        stream_handlers = [h for h in root.handlers if isinstance(h, logging.StreamHandler)]
        assert not any(isinstance(h.formatter, _JSONFormatter) for h in stream_handlers)


# ---------------------------------------------------------------------------
# 3. Streaming / chained decryption solver
# ---------------------------------------------------------------------------

from dragonslayer.analysis.symbolic_execution.solver import Z3Solver


class TestXORKeySchedule:
    """``Z3Solver.solve_xor_key_schedule`` recovers XOR keys."""

    def test_simple_xor_recovery(self):
        solver = Z3Solver()
        ct = [0xAA, 0xBB, 0xCC]
        pt = [0x11, 0x22, 0x33]
        expected_keys = [c ^ p for c, p in zip(ct, pt)]

        result = solver.solve_xor_key_schedule(ct, pt, bits=8)
        assert result.satisfiable
        for i, ek in enumerate(expected_keys):
            assert result.model[f"key_{i}"] == ek

    def test_64bit_chunks(self):
        solver = Z3Solver()
        ct = [0xDEADBEEF, 0xCAFEBABE]
        pt = [0x12345678, 0x87654321]
        result = solver.solve_xor_key_schedule(ct, pt, bits=64)
        assert result.satisfiable
        for i in range(2):
            assert result.model[f"key_{i}"] == (ct[i] ^ pt[i])

    def test_empty_input_returns_unsat(self):
        solver = Z3Solver()
        result = solver.solve_xor_key_schedule([], [], bits=8)
        assert not result.satisfiable
        assert "mismatch" in (result.error or "")

    def test_length_mismatch_returns_unsat(self):
        solver = Z3Solver()
        result = solver.solve_xor_key_schedule([1, 2], [3], bits=8)
        assert not result.satisfiable


class TestChainedDecryption:
    """``Z3Solver.solve_chained_decryption`` handles CBC-like chains."""

    def test_basic_chain(self):
        solver = Z3Solver()
        key_val = 0x42
        init = 0x00
        plains = [0x10, 0x20, 0x30]
        # Encrypt: cipher[i] = plain[i] ^ key ^ prev_plain
        chain = []
        prev = init
        for p in plains:
            c = p ^ key_val ^ prev
            chain.append(c)
            prev = p

        # Pin first plaintext so the key is uniquely determined
        result = solver.solve_chained_decryption(
            chain, init, bits=8, known_plaintexts={0: plains[0]},
        )
        assert result.satisfiable
        assert result.model["key"] == key_val
        for i, p in enumerate(plains):
            assert result.model[f"plain_{i}"] == p

    def test_empty_chain_unsat(self):
        solver = Z3Solver()
        result = solver.solve_chained_decryption([], 0, bits=8)
        assert not result.satisfiable

    def test_32bit_chain(self):
        solver = Z3Solver()
        key_val = 0xABCD1234
        init = 0x00000000
        plains = [0x11111111, 0x22222222]
        chain = []
        prev = init
        for p in plains:
            chain.append(p ^ key_val ^ prev)
            prev = p

        result = solver.solve_chained_decryption(
            chain, init, bits=32, known_plaintexts={0: plains[0]},
        )
        assert result.satisfiable
        assert result.model["key"] == key_val


# ---------------------------------------------------------------------------
# 4. Orchestrator async context manager
# ---------------------------------------------------------------------------

from dragonslayer.core.orchestrator import Orchestrator


class TestOrchestratorAsyncContextManager:
    """``Orchestrator`` supports ``async with``."""

    def test_sync_context_manager(self):
        with Orchestrator() as o:
            assert o is not None

    def test_async_context_manager(self):
        async def _go():
            async with Orchestrator() as o:
                assert o is not None
                return True
        assert asyncio.run(_go())

    def test_async_exit_calls_shutdown(self):
        calls = []
        orig_shutdown = Orchestrator.shutdown

        def mock_shutdown(self):
            calls.append("shutdown")
            orig_shutdown(self)

        async def _go():
            with patch.object(Orchestrator, "shutdown", mock_shutdown):
                async with Orchestrator():
                    pass
            return calls

        result = asyncio.run(_go())
        assert "shutdown" in result
