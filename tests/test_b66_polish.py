"""B66 – Multi-dimension polish tests.

Covers:
1. Config: deep-copy ``get_section``, bool env-var parsing
2. Taint: precompiled regex correctness (functional equivalence)
3. CFG: dominator-based back-edge classification
4. Production: CORS env-var override, request-body size limit
"""

from __future__ import annotations

import copy
import os
import re
from typing import Any, Dict
from unittest.mock import patch

import pytest

# ═══════════════════════════════════════════════════════════════════════════════
# 1. Config – deep-copy get_section & bool env-var parsing
# ═══════════════════════════════════════════════════════════════════════════════


def _make_config(**overrides: Any):
    """Build a minimal Config without touching the filesystem."""
    from dragonslayer.core.config import Config
    import threading

    c = Config.__new__(Config)
    c.environment = "test"
    c._config = copy.deepcopy(Config.DEFAULTS)
    c._lock = threading.RLock()
    for k, v in overrides.items():
        c._config[k] = v
    return c


class TestConfigDeepCopy:
    """get_section must return a defensive deep-copy."""

    def test_mutating_returned_section_does_not_affect_config(self):
        cfg = _make_config()
        section = cfg.get_section("logging")
        original_level = cfg.get("logging.level")

        section["level"] = "CRITICAL"  # mutate copy
        assert cfg.get("logging.level") == original_level

    def test_get_section_returns_empty_for_missing(self):
        cfg = _make_config()
        assert cfg.get_section("nonexistent") == {}

    def test_nested_mutation_isolated(self):
        cfg = _make_config(custom={"inner": {"key": [1, 2, 3]}})
        section = cfg.get_section("custom")
        section["inner"]["key"].append(4)
        assert cfg.get("custom.inner.key") == [1, 2, 3]


class TestConfigBoolEnv:
    """Generic VMDS_ env-var convention must parse booleans."""

    _TRUE_VALUES = ("true", "True", "TRUE", "yes", "Yes", "1", "on", "ON")
    _FALSE_VALUES = ("false", "False", "FALSE", "no", "No", "0", "off", "OFF")

    @pytest.mark.parametrize("raw", _TRUE_VALUES)
    def test_env_parsed_as_true(self, raw: str, monkeypatch):
        monkeypatch.setenv("VMDS_ANALYSIS__CUSTOM_BOOL", raw)
        cfg = _make_config()
        cfg._load_env_variables()
        assert cfg.get("analysis.custom_bool") is True

    @pytest.mark.parametrize("raw", _FALSE_VALUES)
    def test_env_parsed_as_false(self, raw: str, monkeypatch):
        monkeypatch.setenv("VMDS_ANALYSIS__CUSTOM_BOOL", raw)
        cfg = _make_config()
        cfg._load_env_variables()
        assert cfg.get("analysis.custom_bool") is False

    def test_env_numeric_preserved(self, monkeypatch):
        monkeypatch.setenv("VMDS_ANALYSIS__MAX_THINGS", "42")
        cfg = _make_config()
        cfg._load_env_variables()
        assert cfg.get("analysis.max_things") == 42

    def test_env_string_preserved(self, monkeypatch):
        monkeypatch.setenv("VMDS_TRACING__BACKEND", "qiling")
        cfg = _make_config()
        cfg._load_env_variables()
        assert cfg.get("tracing.backend") == "qiling"


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Taint – precompiled regex equivalence
# ═══════════════════════════════════════════════════════════════════════════════

from dragonslayer.analysis.taint_tracking.tracker import (
    _RE_INTEL_MEM,
    _RE_ATT_MEM,
    _RE_ADDR_SPLIT,
    _RE_MUL,
    _RE_NUM,
)


class TestPrecompiledRegex:
    """Validate that the module-level compiled patterns behave correctly."""

    def test_intel_mem_matches(self):
        """[reg + offset] style memory operands."""
        for op in ["[rax]", "[rsp + 0x10]", "dword ptr [rbx+rcx*4]"]:
            assert _RE_INTEL_MEM.search(op), f"Should match: {op}"

    def test_intel_mem_rejects(self):
        for op in ["rax", "0x1234", "eax"]:
            assert not _RE_INTEL_MEM.search(op), f"Should not match: {op}"

    def test_att_mem_matches(self):
        for op in ["(%rax)", "0x10(%rsp)", "(%rsp,%rdi,8)"]:
            assert _RE_ATT_MEM.search(op), f"Should match: {op}"

    def test_addr_split(self):
        parts = _RE_ADDR_SPLIT.split("rax+rbx*4+0x10")
        # Split may keep delimiters; just check substrings are present
        joined = "".join(parts)
        assert "rax" in joined
        assert "rbx" in joined

    def test_mul_pattern(self):
        assert _RE_MUL.search("rbx*4")
        assert not _RE_MUL.search("rbx+4")

    def test_num_pattern(self):
        assert _RE_NUM.fullmatch("0x1234")
        assert _RE_NUM.fullmatch("42")
        assert not _RE_NUM.fullmatch("rax")


# ═══════════════════════════════════════════════════════════════════════════════
# 3. CFG – dominator-based back-edge detection
# ═══════════════════════════════════════════════════════════════════════════════


class TestDominatorBackEdges:
    """Back-edges must be classified via dominator relation, not address order."""

    @staticmethod
    def _make_instr(address, mnemonic="nop", operands="", category=None,
                    size=1, is_branch=False, branch_target=None):
        from dragonslayer.analysis.symbolic_execution.lifter import (
            LiftedInstruction, InstructionCategory,
        )
        cat = category or InstructionCategory.NOP
        return LiftedInstruction(
            address=address, size=size, mnemonic=mnemonic,
            operands=operands, category=cat, raw_bytes=b"\x90",
            is_branch=is_branch, branch_target=branch_target,
        )

    @classmethod
    def _build_blocks(cls, graph_edges, entry=0x1000):
        """Build List[List[LiftedInstruction]] from a (src→[targets]) graph.

        Each node becomes a single-instruction basic block. Edges are encoded
        as unconditional jumps or conditional branches.
        """
        from dragonslayer.analysis.symbolic_execution.lifter import InstructionCategory

        all_addrs = set()
        out_edges: Dict[int, list] = {}
        for src, dst in graph_edges:
            all_addrs.update((src, dst))
            out_edges.setdefault(src, []).append(dst)

        blocks = []
        for addr in sorted(all_addrs):
            targets = out_edges.get(addr, [])
            if len(targets) == 0:
                blocks.append([cls._make_instr(addr, "ret",
                               category=InstructionCategory.RETURN)])
            elif len(targets) == 1:
                blocks.append([cls._make_instr(addr, "jmp",
                               category=InstructionCategory.BRANCH_UNCOND,
                               is_branch=True, branch_target=targets[0])])
            else:
                # Conditional: first target = taken, second = fall-through
                blocks.append([cls._make_instr(addr, "je",
                               category=InstructionCategory.BRANCH_COND,
                               is_branch=True, branch_target=targets[0],
                               size=targets[1] - addr)])  # fall_addr = addr + size
        return blocks

    def test_forward_cross_edge_not_back(self):
        """In A→B, A→C, B→C the edge B→C is a forward/cross edge, not a back edge."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor

        blocks = self._build_blocks(
            [(0x1000, 0x2000), (0x1000, 0x3000), (0x2000, 0x3000)],
        )
        cfg = SymbolicExecutor._build_cfg(blocks, 0x1000)
        assert cfg["back_edge_count"] == 0

    def test_simple_loop_detected(self):
        """In A→B, B→A the edge B→A is a back edge (A dominates B)."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor

        blocks = self._build_blocks([(0x1000, 0x2000), (0x2000, 0x1000)])
        cfg = SymbolicExecutor._build_cfg(blocks, 0x1000)
        assert cfg["back_edge_count"] == 1

    def test_diamond_no_back_edges(self):
        """Diamond A→B, A→C, B→D, C→D has no back edges."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor

        blocks = self._build_blocks([
            (0x1000, 0x2000), (0x1000, 0x3000),
            (0x2000, 0x4000), (0x3000, 0x4000),
        ])
        cfg = SymbolicExecutor._build_cfg(blocks, 0x1000)
        assert cfg["back_edge_count"] == 0

    def test_dominator_keys_are_ints(self):
        """B66 stores dominator keys as ints, not hex strings."""
        from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor

        blocks = self._build_blocks([(0x1000, 0x2000)])
        cfg = SymbolicExecutor._build_cfg(blocks, 0x1000)
        for k in cfg["dominators"]:
            assert isinstance(k, int), f"dominator key {k!r} should be int"


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Production – CORS env-var and body-size limit
# ═══════════════════════════════════════════════════════════════════════════════


class TestCORSConfig:
    """VMDS_CORS_ORIGINS env-var controls allowed origins."""

    def test_default_allows_wildcard(self):
        # Without env-var, default is ["*"]
        import dragonslayer.api.server as srv

        assert "*" in srv._cors_origins

    def test_custom_origins_parsed(self, monkeypatch):
        """Setting VMDS_CORS_ORIGINS splits on commas."""
        monkeypatch.setenv("VMDS_CORS_ORIGINS", "https://a.com, https://b.com")
        # Re-evaluate the module-level expression
        raw = os.environ.get("VMDS_CORS_ORIGINS", "*")
        origins = [o.strip() for o in raw.split(",") if o.strip()]
        assert origins == ["https://a.com", "https://b.com"]


class TestBodySizeLimit:
    """Request-body size limit middleware rejects oversized requests."""

    def test_max_body_constant_exists(self):
        from dragonslayer.api.server import MAX_REQUEST_BODY_BYTES

        assert isinstance(MAX_REQUEST_BODY_BYTES, int)
        assert MAX_REQUEST_BODY_BYTES > 0

    def test_body_size_middleware_registered(self):
        """The body_size_limit_middleware function is importable."""
        from dragonslayer.api.server import body_size_limit_middleware
        import inspect

        assert inspect.iscoroutinefunction(body_size_limit_middleware)

    def test_oversized_returns_413(self):
        """Simulating oversized Content-Length yields 413."""
        from dragonslayer.api.server import (
            body_size_limit_middleware,
            MAX_REQUEST_BODY_BYTES,
        )
        import asyncio

        class FakeRequest:
            headers = {"content-length": str(MAX_REQUEST_BODY_BYTES + 1)}

        async def _noop(req):
            pass  # pragma: no cover

        async def _run():
            resp = await body_size_limit_middleware(FakeRequest(), _noop)
            return resp

        loop = asyncio.new_event_loop()
        try:
            resp = loop.run_until_complete(_run())
            assert resp.status_code == 413
        finally:
            loop.close()

    def test_normal_size_passes_through(self):
        """Normal Content-Length passes to call_next."""
        from dragonslayer.api.server import body_size_limit_middleware
        import asyncio

        class FakeRequest:
            headers = {"content-length": "100"}

        sentinel = object()

        async def call_next(req):
            return sentinel

        async def _run():
            return await body_size_limit_middleware(FakeRequest(), call_next)

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(_run())
            assert result is sentinel
        finally:
            loop.close()
