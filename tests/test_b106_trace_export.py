"""B106 – Trace collector facade + output export system.

Tests cover:
- ``TraceConfig`` validation
- ``TraceBackend`` enum and auto-selection
- ``CollectionResult`` properties and summary
- ``collect_trace`` (error paths, file backend)
- ``collect_trace_from_plugin`` with synthetic shared_data
- ``collect_trace_from_file`` with FORMAT.md traces
- ``filter_trace`` (address range, mnemonic filter, max_instructions)
- ``merge_traces``
- ``trace_statistics``
- ``OutputFormat`` and ``list_formats()``
- ``render_trace_json`` (full-fidelity JSON with round-trip validation)
- ``render_trace_text`` (FORMAT.md writer as inverse of parse_trace_text)
- ``render_trace_csv``
- ``render_ida_annotations``
- ``render_ghidra_script``
- ``export_trace`` file writing
- ``validate_roundtrip``
- analysis __init__ exports
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from dragonslayer.analysis.trace_ingestion import (
    ExecutionTrace,
    HandlerMarker,
    TraceControlFlow,
    TraceInstruction,
    TraceMemoryAccess,
    parse_trace_text,
)
from dragonslayer.analysis.trace_collector import (
    CollectionResult,
    TraceBackend,
    TraceConfig,
    collect_trace,
    collect_trace_from_file,
    collect_trace_from_plugin,
    filter_trace,
    merge_traces,
    trace_statistics,
)
from dragonslayer.analysis.trace_export import (
    OutputFormat,
    export_trace,
    list_formats,
    render_ghidra_script,
    render_ida_annotations,
    render_trace,
    render_trace_csv,
    render_trace_json,
    render_trace_text,
    validate_roundtrip,
)


# ── Test fixtures ────────────────────────────────────────────────────────

def _sample_trace() -> ExecutionTrace:
    """Build a small but representative ExecutionTrace for testing."""
    return ExecutionTrace(
        instructions=[
            TraceInstruction(address=0x401000, size=3, raw_bytes=b"\x48\x89\xc1", disassembly="mov rcx, rax", registers={"rax": 0x42, "rcx": 0}),
            TraceInstruction(address=0x401003, size=2, raw_bytes=b"\x48\x01", disassembly="add rax, rcx", registers={"rax": 0x42, "rcx": 0x42}),
            TraceInstruction(address=0x401005, size=1, raw_bytes=b"\xc3", disassembly="ret", registers={"rax": 0x84}),
            TraceInstruction(address=0x402000, size=1, raw_bytes=b"\x90", disassembly="nop", registers={}),
        ],
        memory_accesses=[
            TraceMemoryAccess(type="R", address=0x7FFF0000, size=8, value=0x42),
            TraceMemoryAccess(type="W", address=0x7FFF0008, size=8, value=0x84),
        ],
        control_flow=[
            TraceControlFlow(type="ret", source=0x401005, target=0x401100),
        ],
        handlers=[
            HandlerMarker(handler_id=1, address=0x401000, handler_type="arithmetic"),
        ],
        metadata={"arch": "x86_64", "test": True},
        source="test",
    )


# ═══════════════════════════════════════════════════════════════════════════
# TraceConfig
# ═══════════════════════════════════════════════════════════════════════════

class TestTraceConfig:
    def test_defaults(self) -> None:
        cfg = TraceConfig()
        assert cfg.arch == "x86_64"
        assert cfg.max_instructions == 10_000
        assert cfg.capture_registers is True

    def test_valid_config_no_errors(self) -> None:
        cfg = TraceConfig(arch="x86", max_instructions=100)
        assert cfg.validate() == []

    def test_invalid_arch(self) -> None:
        cfg = TraceConfig(arch="arm64")
        errs = cfg.validate()
        assert any("arch" in e.lower() for e in errs)

    def test_invalid_max_instructions(self) -> None:
        cfg = TraceConfig(max_instructions=0)
        errs = cfg.validate()
        assert len(errs) >= 1

    def test_invalid_timeout(self) -> None:
        cfg = TraceConfig(timeout_seconds=-1)
        errs = cfg.validate()
        assert any("timeout" in e.lower() for e in errs)


# ═══════════════════════════════════════════════════════════════════════════
# TraceBackend
# ═══════════════════════════════════════════════════════════════════════════

class TestTraceBackend:
    def test_enum_values(self) -> None:
        assert TraceBackend.UNICORN.value == "unicorn"
        assert TraceBackend.AUTO.value == "auto"
        assert TraceBackend.FILE.value == "file"

    def test_all_backends(self) -> None:
        names = {b.value for b in TraceBackend}
        assert names == {"unicorn", "triton", "angr", "qiling", "file", "auto"}


# ═══════════════════════════════════════════════════════════════════════════
# CollectionResult
# ═══════════════════════════════════════════════════════════════════════════

class TestCollectionResult:
    def test_success_property(self) -> None:
        r = CollectionResult(
            trace=_sample_trace(), backend="test", elapsed_seconds=0.1,
        )
        assert r.success is True

    def test_failure_on_error(self) -> None:
        r = CollectionResult(
            trace=ExecutionTrace(), backend="test", elapsed_seconds=0.0,
            error="something broke",
        )
        assert r.success is False

    def test_failure_on_empty_trace(self) -> None:
        r = CollectionResult(
            trace=ExecutionTrace(), backend="test", elapsed_seconds=0.0,
        )
        assert r.success is False

    def test_summary(self) -> None:
        r = CollectionResult(
            trace=_sample_trace(), backend="test", elapsed_seconds=0.5, truncated=True,
        )
        s = r.summary()
        assert s["backend"] == "test"
        assert s["success"] is True
        assert s["instruction_count"] == 4
        assert s["truncated"] is True


# ═══════════════════════════════════════════════════════════════════════════
# collect_trace
# ═══════════════════════════════════════════════════════════════════════════

class TestCollectTrace:
    def test_invalid_config_returns_error(self) -> None:
        cfg = TraceConfig(arch="mips", max_instructions=-1)
        result = collect_trace(b"\x90", 0x1000, config=cfg)
        assert result.success is False
        assert "validation" in result.error.lower()

    def test_file_backend(self) -> None:
        trace_text = "i: 0x1000 | 1 | 90 | nop |\n"
        result = collect_trace(
            trace_text.encode(), 0x1000, backend=TraceBackend.FILE,
        )
        assert result.success is True
        assert result.backend == "file"
        assert len(result.trace.instructions) == 1

    def test_external_stub_backend(self) -> None:
        result = collect_trace(
            b"\x90", 0x1000, backend=TraceBackend.TRITON,
        )
        # Should return a stub trace (Triton not directly integrated)
        assert result.backend == "triton"


# ═══════════════════════════════════════════════════════════════════════════
# collect_trace_from_plugin
# ═══════════════════════════════════════════════════════════════════════════

class TestCollectTraceFromPlugin:
    def test_generic_shared_data(self) -> None:
        shared = {
            "instructions": [
                {"address": 0x1000, "size": 1, "bytes": "90", "disassembly": "nop"},
            ],
        }
        result = collect_trace_from_plugin(shared, plugin="auto")
        assert result.backend == "generic"

    def test_triton_hint(self) -> None:
        shared = {"taint_flow": [], "instructions": []}
        result = collect_trace_from_plugin(shared, plugin="triton")
        assert result.backend == "triton"


# ═══════════════════════════════════════════════════════════════════════════
# collect_trace_from_file
# ═══════════════════════════════════════════════════════════════════════════

class TestCollectTraceFromFile:
    def test_valid_trace_file(self, tmp_path: Path) -> None:
        trace_file = tmp_path / "test.trace"
        trace_file.write_text("i: 0x1000 | 1 | 90 | nop |\n", encoding="utf-8")
        result = collect_trace_from_file(str(trace_file))
        assert result.success is True
        assert len(result.trace.instructions) == 1

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        result = collect_trace_from_file(str(tmp_path / "nope.trace"))
        assert result.success is False
        assert result.error is not None

    def test_real_sample_trace(self) -> None:
        path = Path(__file__).resolve().parents[1] / "data" / "samples" / "traces" / "vmprotect_vadd_handler.trace"
        if not path.exists():
            pytest.skip("Sample trace not found")
        result = collect_trace_from_file(str(path))
        assert result.success is True
        assert len(result.trace.instructions) > 0


# ═══════════════════════════════════════════════════════════════════════════
# filter_trace
# ═══════════════════════════════════════════════════════════════════════════

class TestFilterTrace:
    def test_address_range(self) -> None:
        trace = _sample_trace()
        filtered = filter_trace(trace, address_range=(0x401000, 0x402000))
        assert all(0x401000 <= i.address < 0x402000 for i in filtered.instructions)
        assert len(filtered.instructions) == 3  # address 0x402000 excluded

    def test_max_instructions(self) -> None:
        trace = _sample_trace()
        filtered = filter_trace(trace, max_instructions=2)
        assert len(filtered.instructions) == 2

    def test_include_mnemonics(self) -> None:
        trace = _sample_trace()
        filtered = filter_trace(trace, include_mnemonics=["mov", "add"])
        assert all(
            i.disassembly.split()[0] in ("mov", "add")
            for i in filtered.instructions
        )

    def test_exclude_mnemonics(self) -> None:
        trace = _sample_trace()
        filtered = filter_trace(trace, exclude_mnemonics=["nop", "ret"])
        assert all(
            i.disassembly.split()[0] not in ("nop", "ret")
            for i in filtered.instructions
        )

    def test_does_not_mutate_original(self) -> None:
        trace = _sample_trace()
        original_count = len(trace.instructions)
        filter_trace(trace, max_instructions=1)
        assert len(trace.instructions) == original_count

    def test_filtered_metadata_flag(self) -> None:
        trace = _sample_trace()
        filtered = filter_trace(trace, max_instructions=2)
        assert filtered.metadata.get("filtered") is True


# ═══════════════════════════════════════════════════════════════════════════
# merge_traces
# ═══════════════════════════════════════════════════════════════════════════

class TestMergeTraces:
    def test_merge_two_traces(self) -> None:
        t1 = _sample_trace()
        t2 = ExecutionTrace(
            instructions=[
                TraceInstruction(address=0x500000, size=1, raw_bytes=b"\x90", disassembly="nop"),
            ],
            source="test2",
        )
        merged = merge_traces(t1, t2)
        assert len(merged.instructions) == 5
        assert merged.source == "merged"
        assert merged.metadata["merge_count"] == 2

    def test_merge_preserves_handlers(self) -> None:
        t1 = _sample_trace()
        t2 = ExecutionTrace(
            handlers=[HandlerMarker(handler_id=99, address=0xBEEF, handler_type="crypto")],
        )
        merged = merge_traces(t1, t2)
        assert len(merged.handlers) == 2


# ═══════════════════════════════════════════════════════════════════════════
# trace_statistics
# ═══════════════════════════════════════════════════════════════════════════

class TestTraceStatistics:
    def test_basic_stats(self) -> None:
        stats = trace_statistics(_sample_trace())
        assert stats["instruction_count"] == 4
        assert stats["unique_addresses"] == 4
        assert stats["memory_reads"] == 1
        assert stats["memory_writes"] == 1
        assert stats["handler_count"] == 1
        assert stats["source"] == "test"

    def test_top_mnemonics(self) -> None:
        stats = trace_statistics(_sample_trace())
        mnems = dict(stats["top_mnemonics"])
        assert "mov" in mnems
        assert "nop" in mnems

    def test_empty_trace(self) -> None:
        stats = trace_statistics(ExecutionTrace())
        assert stats["instruction_count"] == 0


# ═══════════════════════════════════════════════════════════════════════════
# OutputFormat & list_formats
# ═══════════════════════════════════════════════════════════════════════════

class TestOutputFormat:
    def test_enum_values(self) -> None:
        assert OutputFormat.JSON.value == "json"
        assert OutputFormat.TEXT.value == "text"
        assert OutputFormat.CSV.value == "csv"
        assert OutputFormat.IDA.value == "ida"
        assert OutputFormat.GHIDRA.value == "ghidra"

    def test_list_formats(self) -> None:
        fmts = list_formats()
        assert "json" in fmts
        assert "text" in fmts
        assert "csv" in fmts
        assert "ida" in fmts
        assert "ghidra" in fmts
        assert len(fmts) == 5


# ═══════════════════════════════════════════════════════════════════════════
# JSON export
# ═══════════════════════════════════════════════════════════════════════════

class TestRenderJSON:
    def test_structure(self) -> None:
        text = render_trace_json(_sample_trace())
        data = json.loads(text)
        assert data["version"] == "1.0"
        assert data["source"] == "test"
        assert len(data["instructions"]) == 4
        assert len(data["memory_accesses"]) == 2
        assert len(data["control_flow"]) == 1
        assert len(data["handlers"]) == 1

    def test_instruction_fields(self) -> None:
        text = render_trace_json(_sample_trace())
        instr = json.loads(text)["instructions"][0]
        assert instr["address"] == 0x401000
        assert instr["size"] == 3
        assert instr["disassembly"] == "mov rcx, rax"
        assert instr["raw_bytes"] == "4889C1"

    def test_roundtrip_count(self) -> None:
        assert validate_roundtrip(_sample_trace()) is True

    def test_empty_trace(self) -> None:
        text = render_trace_json(ExecutionTrace())
        data = json.loads(text)
        assert data["instructions"] == []


# ═══════════════════════════════════════════════════════════════════════════
# FORMAT.md text export
# ═══════════════════════════════════════════════════════════════════════════

class TestRenderText:
    def test_header(self) -> None:
        text = render_trace_text(_sample_trace())
        assert "DragonSlayer Trace v1.0" in text
        assert "source: test" in text

    def test_instruction_lines(self) -> None:
        text = render_trace_text(_sample_trace())
        lines = [l for l in text.splitlines() if l.startswith("i:")]
        assert len(lines) == 4
        # First instruction
        assert "0x401000" in lines[0]
        assert "mov rcx, rax" in lines[0]

    def test_memory_lines(self) -> None:
        text = render_trace_text(_sample_trace())
        mem_lines = [l for l in text.splitlines() if l.startswith("m:")]
        assert len(mem_lines) == 2

    def test_control_flow_lines(self) -> None:
        text = render_trace_text(_sample_trace())
        cf_lines = [l for l in text.splitlines() if l.startswith("c:")]
        assert len(cf_lines) == 1

    def test_handler_lines(self) -> None:
        text = render_trace_text(_sample_trace())
        h_lines = [l for l in text.splitlines() if l.startswith("h:")]
        assert len(h_lines) == 1
        assert "arithmetic" in h_lines[0]

    def test_roundtrip_with_parser(self) -> None:
        """Export to text, re-parse, check instruction count matches."""
        original = _sample_trace()
        text = render_trace_text(original)
        reconstructed = parse_trace_text(text)
        assert len(reconstructed.instructions) == len(original.instructions)


# ═══════════════════════════════════════════════════════════════════════════
# CSV export
# ═══════════════════════════════════════════════════════════════════════════

class TestRenderCSV:
    def test_row_count(self) -> None:
        text = render_trace_csv(_sample_trace())
        reader = csv.reader(io.StringIO(text))
        rows = list(reader)
        assert len(rows) == 5  # 1 header + 4 data rows

    def test_header_row(self) -> None:
        text = render_trace_csv(_sample_trace())
        reader = csv.reader(io.StringIO(text))
        header = next(reader)
        assert "address" in header
        assert "mnemonic" in header
        assert "disassembly" in header

    def test_data_values(self) -> None:
        text = render_trace_csv(_sample_trace())
        reader = csv.reader(io.StringIO(text))
        next(reader)  # skip header
        row = next(reader)
        assert "0x401000" in row[0]
        assert "mov" in row[4]  # mnemonic column


# ═══════════════════════════════════════════════════════════════════════════
# IDA annotations
# ═══════════════════════════════════════════════════════════════════════════

class TestRenderIDA:
    def test_structure(self) -> None:
        text = render_ida_annotations(_sample_trace())
        data = json.loads(text)
        assert data["version"] == "1.0"
        assert "annotations" in data
        assert "functions" in data

    def test_handler_annotations(self) -> None:
        text = render_ida_annotations(_sample_trace())
        data = json.loads(text)
        # Should have at least handler annotation
        handler_annots = [
            a for a in data["annotations"] if "VM Handler" in a.get("comment", "")
        ]
        assert len(handler_annots) >= 1

    def test_handler_functions(self) -> None:
        text = render_ida_annotations(_sample_trace())
        data = json.loads(text)
        assert any("vm_handler" in f["name"] for f in data["functions"])


# ═══════════════════════════════════════════════════════════════════════════
# Ghidra script
# ═══════════════════════════════════════════════════════════════════════════

class TestRenderGhidra:
    def test_is_python_script(self) -> None:
        text = render_ghidra_script(_sample_trace())
        assert "Auto-generated by DragonSlayer" in text
        assert "currentProgram" in text

    def test_handler_comments(self) -> None:
        text = render_ghidra_script(_sample_trace())
        assert "VM Handler #1" in text
        assert "arithmetic" in text

    def test_bookmark_call(self) -> None:
        text = render_ghidra_script(_sample_trace())
        assert "setBookmark" in text


# ═══════════════════════════════════════════════════════════════════════════
# export_trace (file writing)
# ═══════════════════════════════════════════════════════════════════════════

class TestExportTrace:
    @pytest.mark.parametrize("fmt", list(OutputFormat))
    def test_export_all_formats(self, tmp_path: Path, fmt: OutputFormat) -> None:
        out = tmp_path / f"trace.{fmt.value}"
        result = export_trace(_sample_trace(), str(out), format=fmt)
        assert out.exists()
        assert len(result) > 0

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        out = tmp_path / "sub" / "dir" / "trace.json"
        export_trace(_sample_trace(), str(out), format=OutputFormat.JSON)
        assert out.exists()

    def test_invalid_format_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown format"):
            render_trace(_sample_trace(), format="not_a_format")  # type: ignore[arg-type]


# ═══════════════════════════════════════════════════════════════════════════
# render_trace convenience function
# ═══════════════════════════════════════════════════════════════════════════

class TestRenderTrace:
    @pytest.mark.parametrize("fmt", list(OutputFormat))
    def test_all_formats_return_string(self, fmt: OutputFormat) -> None:
        result = render_trace(_sample_trace(), format=fmt)
        assert isinstance(result, str)
        assert len(result) > 0


# ═══════════════════════════════════════════════════════════════════════════
# analysis __init__ exports
# ═══════════════════════════════════════════════════════════════════════════

class TestAnalysisExports:
    _COLLECTOR_NAMES = [
        "TraceBackend", "TraceConfig", "CollectionResult",
        "collect_trace", "collect_trace_from_plugin", "collect_trace_from_file",
        "filter_trace", "merge_traces", "trace_statistics",
    ]
    _EXPORT_NAMES = [
        "OutputFormat", "export_trace", "render_trace",
        "render_trace_json", "render_trace_text", "render_trace_csv",
        "render_ida_annotations", "render_ghidra_script",
        "list_formats", "validate_roundtrip",
    ]

    @pytest.mark.parametrize("name", _COLLECTOR_NAMES + _EXPORT_NAMES)
    def test_in_analysis_all(self, name: str) -> None:
        import dragonslayer.analysis as analysis
        assert name in analysis.__all__, f"{name} not in analysis.__all__"

    @pytest.mark.parametrize("name", _COLLECTOR_NAMES + _EXPORT_NAMES)
    def test_importable(self, name: str) -> None:
        import dragonslayer.analysis as analysis
        obj = getattr(analysis, name, None)
        assert obj is not None, f"analysis.{name} is None"
