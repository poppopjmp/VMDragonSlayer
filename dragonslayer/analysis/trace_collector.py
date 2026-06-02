"""
Trace Collector Facade
======================

High-level entry point for collecting execution traces.  Orchestrates
engine selection (Unicorn built-in vs. external plugin adapters),
configuration, error handling, and post-collection filtering.

Usage::

    from dragonslayer.analysis.trace_collector import collect_trace, TraceConfig

    # From raw binary bytes
    cfg = TraceConfig(arch="x86_64", max_instructions=5000)
    trace = collect_trace(binary_data, entry=0x401000, config=cfg)

    # From plugin shared_data
    trace = collect_trace_from_plugin(shared_data, plugin="triton")

    # Filter an existing trace
    filtered = filter_trace(trace, address_range=(0x401000, 0x402000))
"""

from __future__ import annotations

import logging
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    TraceInstruction,
    from_shared_data,
    parse_trace_text,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# Engine selection
# ═══════════════════════════════════════════════════════════════════════════

class TraceBackend(Enum):
    """Supported trace collection backends."""
    UNICORN = "unicorn"
    TRITON = "triton"
    ANGR = "angr"
    QILING = "qiling"
    FILE = "file"
    AUTO = "auto"


# ═══════════════════════════════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class TraceConfig:
    """Configuration for trace collection.

    Parameters
    ----------
    arch : str
        Target architecture (``"x86_64"``, ``"x86"``).
    max_instructions : int
        Maximum instructions to trace before stopping.
    capture_registers : bool
        Record register snapshots at each instruction.
    capture_memory : bool
        Record memory reads/writes.
    timeout_seconds : float
        Wall-clock timeout for the trace engine.
    entry_point : int or None
        Override entry point; if *None*, use the binary's entry.
    memory_map : dict
        Additional memory regions to map: ``{address: size}``.
    """
    arch: str = "x86_64"
    max_instructions: int = 10_000
    capture_registers: bool = True
    capture_memory: bool = True
    timeout_seconds: float = 60.0
    entry_point: int | None = None
    memory_map: dict[int, int] = field(default_factory=dict)

    def validate(self) -> list[str]:
        """Return a list of validation errors (empty = valid)."""
        errors: list[str] = []
        if self.arch not in ("x86", "x86_64", "x64"):
            errors.append(f"Unsupported architecture: {self.arch!r}")
        if self.max_instructions < 1:
            errors.append("max_instructions must be >= 1")
        if self.timeout_seconds <= 0:
            errors.append("timeout_seconds must be > 0")
        return errors


# ═══════════════════════════════════════════════════════════════════════════
# Collection result
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class CollectionResult:
    """Result of a trace collection operation.

    Wraps the :class:`ExecutionTrace` with collection metadata.
    """
    trace: ExecutionTrace
    backend: str
    elapsed_seconds: float
    truncated: bool = False
    error: str | None = None
    config: TraceConfig | None = None

    @property
    def success(self) -> bool:
        return self.error is None and len(self.trace.instructions) > 0

    def summary(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary."""
        return {
            "backend": self.backend,
            "success": self.success,
            "instruction_count": len(self.trace.instructions),
            "memory_access_count": len(self.trace.memory_accesses),
            "control_flow_edges": len(self.trace.control_flow),
            "elapsed_seconds": round(self.elapsed_seconds, 4),
            "truncated": self.truncated,
            "error": self.error,
        }


# ═══════════════════════════════════════════════════════════════════════════
# Core collection functions
# ═══════════════════════════════════════════════════════════════════════════

def _select_backend(backend: TraceBackend) -> TraceBackend:
    """Resolve ``AUTO`` to the best available backend."""
    if backend is not TraceBackend.AUTO:
        return backend

    try:
        from dragonslayer.analysis.trace_engine import UNICORN_AVAILABLE
        if UNICORN_AVAILABLE:
            return TraceBackend.UNICORN
    except ImportError:
        pass

    # Fallback: try Triton, angr, Qiling in order
    for candidate in (TraceBackend.TRITON, TraceBackend.ANGR, TraceBackend.QILING):
        try:
            __import__(candidate.value)
            return candidate
        except ImportError:
            continue

    logger.warning("No trace backend available; falling back to UNICORN stub")
    return TraceBackend.UNICORN


def collect_trace(
    binary_data: bytes,
    entry: int,
    *,
    config: TraceConfig | None = None,
    backend: TraceBackend = TraceBackend.AUTO,
) -> CollectionResult:
    """Collect an execution trace from raw binary data.

    Parameters
    ----------
    binary_data : bytes
        Raw machine code or PE/ELF binary data.
    entry : int
        Virtual address to start execution.
    config : TraceConfig or None
        Collection configuration.  Defaults are used if *None*.
    backend : TraceBackend
        Which engine to use.  ``AUTO`` picks the best available.

    Returns
    -------
    CollectionResult
        The collected trace plus metadata.
    """
    if config is None:
        config = TraceConfig()

    errors = config.validate()
    if errors:
        return CollectionResult(
            trace=ExecutionTrace(source="error"),
            backend="none",
            elapsed_seconds=0.0,
            error=f"Config validation failed: {'; '.join(errors)}",
            config=config,
        )

    resolved = _select_backend(backend)
    logger.info(
        "Collecting trace: backend=%s, entry=0x%x, max_insns=%d",
        resolved.value, entry, config.max_instructions,
    )

    t0 = time.monotonic()

    try:
        if resolved == TraceBackend.UNICORN:
            trace = _collect_unicorn(binary_data, entry, config)
        elif resolved == TraceBackend.FILE:
            # binary_data is treated as trace text
            trace = parse_trace_text(binary_data.decode("utf-8", errors="replace"))
        elif resolved in (
            TraceBackend.TRITON, TraceBackend.ANGR, TraceBackend.QILING,
        ):
            trace = _collect_via_plugin(binary_data, entry, config, resolved)
        else:
            trace = _collect_external_stub(binary_data, entry, config, resolved)

        elapsed = time.monotonic() - t0
        truncated = len(trace.instructions) >= config.max_instructions

        return CollectionResult(
            trace=trace,
            backend=resolved.value,
            elapsed_seconds=elapsed,
            truncated=truncated,
            config=config,
        )

    except Exception as exc:
        elapsed = time.monotonic() - t0
        logger.error("Trace collection failed: %s", exc)
        return CollectionResult(
            trace=ExecutionTrace(source="error"),
            backend=resolved.value,
            elapsed_seconds=elapsed,
            error=str(exc),
            config=config,
        )


def _collect_unicorn(
    binary_data: bytes,
    entry: int,
    config: TraceConfig,
) -> ExecutionTrace:
    """Collect trace using the built-in Unicorn engine."""
    from dragonslayer.analysis.trace_engine import TraceEngine

    engine = TraceEngine(
        arch=config.arch,
        capture_registers=config.capture_registers,
        capture_memory=config.capture_memory,
    )
    trace = engine.trace(
        binary_data,
        entry_va=entry,
        max_insns=config.max_instructions,
    )
    return trace


def _collect_external_stub(
    binary_data: bytes,
    entry: int,
    config: TraceConfig,
    backend: TraceBackend,
) -> ExecutionTrace:
    """Placeholder for unknown/future backends.

    Known backends (Triton, angr, Qiling) are routed through
    :func:`_collect_via_plugin` instead.
    """
    logger.warning(
        "External backend %r not yet directly integrated — "
        "use collect_trace_from_plugin() with pre-collected shared_data",
        backend.value,
    )
    return ExecutionTrace(
        source=backend.value,
        metadata={"entry": entry, "arch": config.arch, "stub": True},
    )


def _collect_via_plugin(
    binary_data: bytes,
    entry: int,
    config: TraceConfig,
    backend: TraceBackend,
) -> ExecutionTrace:
    """Collect a trace by invoking the corresponding dynamic plugin.

    Instead of returning a stub, this function instantiates the real
    ``TritonAnalyzer`` / ``QilingAnalyzer`` / ``AngrExplorer`` plugin,
    executes it with a temporary :class:`PluginContext`, and converts
    the deposited ``shared_data`` to an :class:`ExecutionTrace`.

    Falls back to :func:`_collect_external_stub` when the plugin is
    unavailable (dependency not installed).
    """
    from dragonslayer.plugins import PluginContext, Stage, get_all_plugins

    # Map backend → plugin name
    _backend_name = {
        TraceBackend.TRITON: "triton",
        TraceBackend.ANGR: "angr",
        TraceBackend.QILING: "qiling",
    }
    target_name = _backend_name.get(backend)

    # Find the plugin by name and check availability
    plugin = None
    for p in get_all_plugins(stage=Stage.DYNAMIC, available_only=True):
        if p.name == target_name:
            plugin = p
            break

    if plugin is None:
        logger.warning(
            "%s plugin not available (dependency not installed) — "
            "returning stub trace",
            backend.value,
        )
        return _collect_external_stub(binary_data, entry, config, backend)

    # Build a lightweight plugin context
    ctx = PluginContext(
        binary_data=binary_data,
        shared_data={
            "vm_discovery": {"dispatcher_addresses": [entry] if entry else []},
        },
    )

    # Execute the plugin
    pr = plugin.safe_execute("", binary_data, ctx)
    if not pr.success:
        logger.warning(
            "%s plugin execution failed: %s — returning stub trace",
            backend.value, pr.error,
        )
        return _collect_external_stub(binary_data, entry, config, backend)

    # Convert deposited shared_data → ExecutionTrace
    plugin_data = ctx.shared_data.get(target_name, {})
    if not plugin_data:
        return _collect_external_stub(binary_data, entry, config, backend)

    from dragonslayer.analysis.trace_ingestion import from_shared_data
    trace = from_shared_data(ctx.shared_data)
    logger.info(
        "Collected %d instructions via %s plugin",
        len(trace.instructions) if trace else 0, backend.value,
    )
    return trace


# ═══════════════════════════════════════════════════════════════════════════
# Plugin-based collection (pre-collected data)
# ═══════════════════════════════════════════════════════════════════════════

def collect_trace_from_plugin(
    shared_data: dict[str, Any],
    plugin: str = "auto",
) -> CollectionResult:
    """Build an :class:`ExecutionTrace` from plugin-provided shared_data.

    Reuses the adapter functions in
    :mod:`dragonslayer.analysis.trace_ingestion`.

    Parameters
    ----------
    shared_data : dict
        Dynamic analysis output (Triton, angr, Qiling, or generic).
    plugin : str
        Plugin name hint (``"triton"``, ``"angr"``, ``"qiling"``,
        ``"auto"``).  ``"auto"`` infers the source from *shared_data* keys.

    Returns
    -------
    CollectionResult
    """
    from dragonslayer.analysis.trace_ingestion import (
        from_angr_result,
        from_qiling_result,
        from_triton_result,
    )

    t0 = time.monotonic()

    try:
        plugin_lower = plugin.lower()

        if plugin_lower == "auto":
            plugin_lower = _infer_plugin(shared_data)

        if plugin_lower == "triton":
            trace = from_triton_result(shared_data)
        elif plugin_lower == "angr":
            trace = from_angr_result(shared_data)
        elif plugin_lower == "qiling":
            trace = from_qiling_result(shared_data)
        else:
            trace = from_shared_data(shared_data)

        elapsed = time.monotonic() - t0
        return CollectionResult(
            trace=trace,
            backend=plugin_lower,
            elapsed_seconds=elapsed,
        )

    except Exception as exc:
        elapsed = time.monotonic() - t0
        logger.error("Plugin trace conversion failed: %s", exc)
        return CollectionResult(
            trace=ExecutionTrace(source="error"),
            backend=plugin,
            elapsed_seconds=elapsed,
            error=str(exc),
        )


def _infer_plugin(shared_data: dict[str, Any]) -> str:
    """Infer the plugin source from shared_data keys."""
    if "triton" in shared_data or "taint_flow" in shared_data:
        return "triton"
    if "angr" in shared_data or "cfg" in shared_data:
        return "angr"
    if "qiling" in shared_data or "rootfs" in shared_data:
        return "qiling"
    return "generic"


# ═══════════════════════════════════════════════════════════════════════════
# File-based collection (parse trace files)
# ═══════════════════════════════════════════════════════════════════════════

def collect_trace_from_file(
    path: str,
    *,
    encoding: str = "utf-8",
) -> CollectionResult:
    """Load a trace from a FORMAT.md text file.

    Parameters
    ----------
    path : str
        Path to the trace file.

    Returns
    -------
    CollectionResult
    """
    from pathlib import Path as _Path

    t0 = time.monotonic()
    try:
        text = _Path(path).read_text(encoding=encoding)
        trace = parse_trace_text(text)
        elapsed = time.monotonic() - t0
        return CollectionResult(
            trace=trace,
            backend="file",
            elapsed_seconds=elapsed,
        )
    except Exception as exc:
        elapsed = time.monotonic() - t0
        return CollectionResult(
            trace=ExecutionTrace(source="error"),
            backend="file",
            elapsed_seconds=elapsed,
            error=str(exc),
        )


# ═══════════════════════════════════════════════════════════════════════════
# Trace filtering & transformation
# ═══════════════════════════════════════════════════════════════════════════

def filter_trace(
    trace: ExecutionTrace,
    *,
    address_range: tuple[int, int] | None = None,
    max_instructions: int | None = None,
    include_mnemonics: Sequence[str] | None = None,
    exclude_mnemonics: Sequence[str] | None = None,
) -> ExecutionTrace:
    """Return a new :class:`ExecutionTrace` with filtered instructions.

    Parameters
    ----------
    address_range : (start, end) or None
        Keep only instructions within ``[start, end)``.
    max_instructions : int or None
        Truncate to at most this many instructions.
    include_mnemonics : sequence of str or None
        Whitelist — keep only these mnemonic prefixes.
    exclude_mnemonics : sequence of str or None
        Blacklist — drop these mnemonic prefixes.

    Returns
    -------
    ExecutionTrace
        New filtered trace (original is not mutated).
    """
    instrs: list[TraceInstruction] = list(trace.instructions)

    if address_range is not None:
        lo, hi = address_range
        instrs = [i for i in instrs if lo <= i.address < hi]

    if include_mnemonics is not None:
        prefixes = tuple(m.lower() for m in include_mnemonics)
        instrs = [
            i for i in instrs
            if i.disassembly.split()[0].lower().startswith(prefixes) if i.disassembly
        ]

    if exclude_mnemonics is not None:
        prefixes = tuple(m.lower() for m in exclude_mnemonics)
        instrs = [
            i for i in instrs
            if not (i.disassembly and i.disassembly.split()[0].lower().startswith(prefixes))
        ]

    if max_instructions is not None:
        instrs = instrs[:max_instructions]

    mem = list(trace.memory_accesses)
    cf = list(trace.control_flow)
    if address_range is not None:
        lo, hi = address_range
        cf = [c for c in cf if lo <= c.source < hi or lo <= c.target < hi]

    return ExecutionTrace(
        instructions=instrs,
        memory_accesses=mem if address_range is None else list(trace.memory_accesses),
        control_flow=cf,
        handlers=list(trace.handlers),
        metadata={**trace.metadata, "filtered": True},
        source=trace.source,
    )


def merge_traces(*traces: ExecutionTrace) -> ExecutionTrace:
    """Merge multiple traces into a single :class:`ExecutionTrace`.

    Instructions are concatenated in order (no deduplication).
    Metadata is merged with later traces overriding earlier keys.
    """
    merged = ExecutionTrace(source="merged")

    for t in traces:
        merged.instructions.extend(t.instructions)
        merged.memory_accesses.extend(t.memory_accesses)
        merged.control_flow.extend(t.control_flow)
        merged.handlers.extend(t.handlers)
        merged.metadata.update(t.metadata)

    merged.metadata["merge_count"] = len(traces)
    return merged


def trace_statistics(trace: ExecutionTrace) -> dict[str, Any]:
    """Compute summary statistics for a trace.

    Returns a JSON-serialisable dict with instruction distribution,
    memory access breakdown, and control flow summary.
    """
    from collections import Counter

    mnemonic_counts: Counter[str] = Counter()
    for instr in trace.instructions:
        parts = instr.disassembly.split()
        if parts:
            mnemonic_counts[parts[0].lower()] += 1

    mem_reads = sum(1 for m in trace.memory_accesses if m.type == "R")
    mem_writes = sum(1 for m in trace.memory_accesses if m.type == "W")

    cf_types: Counter[str] = Counter(c.type for c in trace.control_flow)

    unique_addrs = len({i.address for i in trace.instructions})

    return {
        "instruction_count": len(trace.instructions),
        "unique_addresses": unique_addrs,
        "top_mnemonics": mnemonic_counts.most_common(20),
        "memory_reads": mem_reads,
        "memory_writes": mem_writes,
        "control_flow_edges": len(trace.control_flow),
        "control_flow_types": dict(cf_types),
        "handler_count": len(trace.handlers),
        "source": trace.source,
    }
