"""
VMDragonSlayer — Command-Line Interface
========================================

Entry point declared in ``pyproject.toml``::

    [project.scripts]
    vmdragonslayer = "dragonslayer.cli:main"
    vmdslayer      = "dragonslayer.cli:main"

Usage::

    vmdragonslayer scan   sample.exe
    vmdragonslayer analyze sample.exe --type full_analysis
    vmdragonslayer info
    vmdragonslayer patterns list
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

import click

from dragonslayer.core.exceptions import VMDragonSlayerError

# ---------------------------------------------------------------------------
# Exit codes (CI-friendly)
# ---------------------------------------------------------------------------

EX_OK = 0          # No issues
EX_ERROR = 1       # Runtime / analysis error
EX_DETECTED = 2    # VM protection detected

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Enable debug logging.")
@click.version_option(package_name="vmdragonslayer")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """VMDragonSlayer — Automated VM-based binary protection analysis."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _configure_logging(verbose)


# ---------------------------------------------------------------------------
# scan — quick VM detection triage
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-output", "-j", is_flag=True, help="Output raw JSON.")
@click.pass_context
def scan(ctx: click.Context, file: str, json_output: bool) -> None:
    """Quick scan for VM protection presence."""
    from dragonslayer.core.pipeline import create_quick_scan_pipeline

    binary_data = Path(file).read_bytes()
    click.echo(f"[*] Scanning {file} ({len(binary_data):,} bytes)...\n")

    t0 = time.perf_counter()
    try:
        pipe, cfg = create_quick_scan_pipeline()
        pipeline_result = pipe.run(binary_data=binary_data, pipeline_config=cfg)
    except (VMDragonSlayerError, OSError) as exc:
        click.secho(f"Scan failed: {exc}", fg="red", err=True)
        raise SystemExit(EX_ERROR) from exc
    elapsed = time.perf_counter() - t0

    result = pipeline_result.to_dict()

    if json_output:
        click.echo(json.dumps(result, indent=2, default=str))
    else:
        _print_scan_summary(pipeline_result.shared_data, elapsed)

    # Non-zero exit when VM protection is detected (useful in CI).
    vm_detected = pipeline_result.shared_data.get("vm_discovery", {}).get(
        "vm_detected", False,
    )
    if vm_detected:
        raise SystemExit(EX_DETECTED)


def _print_scan_summary(result: dict, elapsed: float) -> None:
    """Pretty-print scan results."""
    vm = result.get("vm_discovery", {})
    ae = result.get("anti_evasion", {})
    pat = result.get("pattern_analysis", {})

    vm_detected = vm.get("vm_detected", False)
    protector = vm.get("protector", "unknown")
    score = vm.get("confidence", 0.0)

    click.secho(
        f"  VM Detected : {'YES' if vm_detected else 'no'}",
        fg="red" if vm_detected else "green",
        bold=True,
    )
    click.echo(f"  Protector   : {protector}")
    click.echo(f"  Confidence  : {score:.2%}")

    indicators = ae.get("indicators", [])
    if indicators:
        click.echo(f"\n  Anti-analysis indicators ({len(indicators)}):")
        for ind in indicators[:10]:
            name = ind.get("name", ind) if isinstance(ind, dict) else str(ind)
            click.echo(f"    - {name}")

    matches = pat.get("matches", [])
    if matches:
        click.echo(f"\n  Pattern matches ({len(matches)}):")
        for m in matches[:10]:
            if isinstance(m, dict):
                click.echo(f"    - {m.get('name', m.get('pattern', '?'))} "
                           f"(confidence={m.get('confidence', 0):.2f})")

    click.echo(f"\n  Elapsed: {elapsed:.2f}s")


# ---------------------------------------------------------------------------
# analyze — full or typed analysis
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--type", "-t", "analysis_type",
    default="hybrid",
    help="Analysis type (hybrid, full_analysis, vm_discovery, vmprotect_devirt, …).",
)
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Write JSON results to file.")
@click.option("--json-output", "-j", is_flag=True, help="Print raw JSON to stdout.")
@click.pass_context
def analyze(
    ctx: click.Context,
    file: str,
    analysis_type: str,
    output: Optional[str],
    json_output: bool,
) -> None:
    """Run a full analysis pipeline on a binary."""
    from dragonslayer.core.orchestrator import Orchestrator, AnalysisType

    binary_data = Path(file).read_bytes()
    click.echo(f"[*] Analyzing {file} ({len(binary_data):,} bytes) "
               f"type={analysis_type}...\n")

    t0 = time.perf_counter()
    orch = Orchestrator()
    try:
        result = orch.analyze_binary(
            binary_data,
            analysis_type=analysis_type,
        )
    except (VMDragonSlayerError, OSError) as exc:
        click.secho(f"Analysis failed: {exc}", fg="red", err=True)
        raise SystemExit(EX_ERROR) from exc
    elapsed = time.perf_counter() - t0

    result_dict = result.to_dict()

    if output:
        Path(output).write_text(json.dumps(result_dict, indent=2, default=str))
        click.echo(f"[+] Results written to {output}")

    if json_output:
        click.echo(json.dumps(result_dict, indent=2, default=str))
    else:
        _print_analysis_summary(result_dict, elapsed)

    # Non-zero exit when VM protection is detected (useful in CI).
    vm_info = result_dict.get("results", {}).get("vm_discovery", {})
    if vm_info.get("vm_detected", False):
        raise SystemExit(EX_DETECTED)


def _print_analysis_summary(result: dict, elapsed: float) -> None:
    """Pretty-print analysis summary."""
    success = result.get("success", False)
    click.secho(
        f"  Success     : {'YES' if success else 'FAILED'}",
        fg="green" if success else "red",
        bold=True,
    )
    click.echo(f"  Analysis ID : {result.get('analysis_id', 'n/a')}")

    results = result.get("results", {})
    for stage, data in results.items():
        if not isinstance(data, dict):
            continue
        click.echo(f"\n  [{stage}]")
        for k, v in list(data.items())[:8]:
            val = v if not isinstance(v, (list, dict)) else f"({type(v).__name__}, len={len(v)})"
            click.echo(f"    {k}: {val}")

    click.echo(f"\n  Elapsed: {elapsed:.2f}s")


# ---------------------------------------------------------------------------
# info — show framework information
# ---------------------------------------------------------------------------

@cli.command()
def info() -> None:
    """Show framework version and available analysis types."""
    from dragonslayer.core.orchestrator import Orchestrator

    click.echo("VMDragonSlayer — VM-based Binary Protection Analysis\n")

    types = Orchestrator.get_supported_analysis_types()
    click.echo(f"Supported analysis types ({len(types)}):")
    for t in sorted(types):
        click.echo(f"  - {t}")

    # Optional dependency check
    click.echo("\nOptional dependencies:")
    _check_dep("z3", "z3-solver (symbolic execution)")
    _check_dep("capstone", "capstone (disassembly)")
    _check_dep("lief", "LIEF (binary parsing)")
    _check_dep("angr", "angr (dynamic analysis)")
    _check_dep("triton", "triton (symbolic + taint)")
    _check_dep("yara", "yara-python (pattern matching)")
    _check_dep("litellm", "litellm (LLM analysis)")
    _check_dep("sklearn", "scikit-learn (ML)")
    _check_dep("networkx", "networkx (CFG)")


def _check_dep(module: str, label: str) -> None:
    try:
        __import__(module)
        click.secho(f"  [+] {label}", fg="green")
    except ImportError:
        click.secho(f"  [-] {label}", fg="yellow")


# ---------------------------------------------------------------------------
# patterns — pattern database operations
# ---------------------------------------------------------------------------

@cli.group()
def patterns() -> None:
    """Pattern database operations."""


@patterns.command("list")
@click.option("--arch", default=None, help="Filter by architecture.")
@click.option("--type", "handler_type", default=None, help="Filter by handler type.")
def patterns_list(arch: Optional[str], handler_type: Optional[str]) -> None:
    """List patterns in the database."""
    from dragonslayer.analysis.pattern_analysis.database import PatternDatabase

    db = PatternDatabase()
    all_patterns = db.search(architecture=arch, handler_type=handler_type)

    if not all_patterns:
        click.echo("No patterns found.")
        return

    click.echo(f"Patterns ({len(all_patterns)}):\n")
    for p in all_patterns:
        click.echo(f"  {p.name:<40s}  arch={p.architecture or 'any':<8s}  "
                    f"type={p.handler_type or 'any':<12s}  "
                    f"conf={p.confidence:.2f}")


# ---------------------------------------------------------------------------
# export — export trace or analysis results
# ---------------------------------------------------------------------------

@cli.command("export")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--format", "-f", "fmt",
    type=click.Choice(["json", "text", "csv", "ida", "ghidra"], case_sensitive=False),
    default="json",
    help="Output format.",
)
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Output file path (default: <file>.<format>).")
@click.option("--type", "-t", "analysis_type", default="hybrid",
              help="Analysis type to run before export.")
@click.pass_context
def export_cmd(
    ctx: click.Context,
    file: str,
    fmt: str,
    output: Optional[str],
    analysis_type: str,
) -> None:
    """Analyze a binary and export results in the specified format.

    Supported formats: json, text (FORMAT.md), csv, ida (IDA annotations),
    ghidra (Ghidra Jython script).
    """
    from dragonslayer.core.orchestrator import Orchestrator
    from dragonslayer.analysis.trace_export import (
        OutputFormat,
        export_trace as do_export,
    )
    from dragonslayer.analysis.trace_ingestion import (
        ExecutionTrace,
        HandlerMarker,
    )

    binary_data = Path(file).read_bytes()
    click.echo(f"[*] Analyzing {file} ({len(binary_data):,} bytes) "
               f"type={analysis_type}...\n")

    t0 = time.perf_counter()
    orch = Orchestrator()
    try:
        result = orch.analyze_binary(binary_data, analysis_type=analysis_type)
    except (VMDragonSlayerError, OSError) as exc:
        click.secho(f"Analysis failed: {exc}", fg="red", err=True)
        raise SystemExit(EX_ERROR) from exc
    elapsed = time.perf_counter() - t0

    # Build an ExecutionTrace from analysis results for export
    result_dict = result.to_dict()
    results = result_dict.get("results", {})
    vm_info = results.get("vm_discovery", {})

    handlers_list: list = []
    for i, h in enumerate(vm_info.get("handlers", [])):
        addr = h.get("address", 0) if isinstance(h, dict) else 0
        htype = h.get("type", "unknown") if isinstance(h, dict) else "unknown"
        handlers_list.append(HandlerMarker(
            handler_id=i, address=addr, handler_type=htype,
        ))

    trace = ExecutionTrace(
        handlers=handlers_list,
        metadata={
            **result_dict.get("metadata", {}),
            "analysis_type": analysis_type,
            "source_file": file,
        },
        source="cli_export",
    )

    # Resolve output format
    fmt_map = {
        "json": OutputFormat.JSON, "text": OutputFormat.TEXT,
        "csv": OutputFormat.CSV, "ida": OutputFormat.IDA,
        "ghidra": OutputFormat.GHIDRA,
    }
    output_format = fmt_map[fmt.lower()]

    # Resolve output path
    if output is None:
        ext_map = {
            "json": ".json", "text": ".trace", "csv": ".csv",
            "ida": ".ida.json", "ghidra": ".ghidra.py",
        }
        output = file + ext_map.get(fmt.lower(), ".json")

    do_export(trace, output, format=output_format)
    click.echo(f"[+] Exported to {output} (format={fmt}, elapsed={elapsed:.2f}s)")


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point referenced by pyproject.toml ``[project.scripts]``."""
    cli(auto_envvar_prefix="VMDS")


if __name__ == "__main__":
    main()
