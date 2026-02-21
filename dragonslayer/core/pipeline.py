"""
Analysis Pipeline
=================

Sequential multi-stage pipeline that chains plugin execution with a
**single shared** :class:`PluginContext`, so data flows naturally from
static → dynamic → enrichment → reporting.  This is the core
architectural piece that connects plugins to the VM deobfuscation goal.

The pipeline also integrates the :class:`LLMAnalyzer` at key decision
points:

* After **static analysis** — classify detected patterns and handlers.
* After **dynamic analysis** — suggest deobfuscation strategies.
* After **enrichment** — summarise combined findings.
* As a standalone **LLM analysis** step that can be inserted anywhere.

Usage::

    from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig

    pipe = AnalysisPipeline()
    result = pipe.run(binary_data, PipelineConfig(
        stages=["static", "dynamic", "enrichment", "llm_analysis", "reporting"],
    ))
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import logging
import tempfile
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, TypedDict

import shutil as _shutil

logger = logging.getLogger(__name__)

# B88: Named exception tuple for stage-level fault tolerance.
_STAGE_ERRORS = (
    ValueError, TypeError, KeyError, IndexError, RuntimeError,
    OSError, ImportError, AttributeError, ArithmeticError,
)


# ---------------------------------------------------------------------------
# Pipeline configuration
# ---------------------------------------------------------------------------

@dataclass
class PipelineConfig:
    """
    Controls which stages to run and how.

    Attributes
    ----------
    stages : list[str]
        Ordered list of stage keys to execute.  Valid keys:
        ``"pattern_analysis"``, ``"vm_discovery"``, ``"static"``,
        ``"dynamic"``, ``"dispatcher_analysis"``, ``"devirtualize"``,
        ``"enrichment"``, ``"llm_analysis"``, ``"reporting"``,
        ``"llm_summary"``.
    storage_backend : str
        Backend name for :func:`create_storage`.
    storage_options : dict
        Keyword args forwarded to the storage backend constructor.
    llm_enabled : bool
        Whether to run LLM-assisted analysis steps.
    max_workers : int
        Thread count for *intra-stage* parallelism (plugins within
        a single stage run concurrently).
    timeout : float
        Per-stage timeout in seconds.
    """

    stages: List[str] = field(default_factory=lambda: [
        "pattern_analysis",
        "vm_discovery",
        "anti_evasion",
        "classify",
        "static",
        "dynamic",
        "taint_analysis",
        "symbolic_execution",
        "dispatcher_analysis",
        "devirtualize",
        "enrichment",
        "llm_analysis",
        "reporting",
        "llm_summary",
    ])
    storage_backend: str = "memory"
    storage_options: Dict[str, Any] = field(default_factory=dict)
    llm_enabled: bool = True
    max_workers: int = 4
    timeout: float = 600
    extra: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Pipeline stage result
# ---------------------------------------------------------------------------

class StageResultDict(TypedDict):
    """Serialised shape of :meth:`StageResult.to_dict`."""

    stage: str
    success: bool
    data: Dict[str, Any]
    error: Optional[str]
    duration: float
    plugins_run: int
    plugins_succeeded: int


class PipelineResultDict(TypedDict):
    """Serialised shape of :meth:`PipelineResult.to_dict`."""

    success: bool
    stages: List[StageResultDict]
    shared_data: Dict[str, Any]
    llm_insights: Dict[str, Any]
    total_duration: float
    errors: List[str]


@dataclass
class StageResult:
    """Output from a single pipeline stage.

    Attributes:
        stage: Name of the pipeline stage (e.g. ``"static"``).
        success: Whether the stage completed without fatal errors.
        data: Arbitrary data produced by the stage's plugins.
        error: Error message if the stage failed, else ``None``.
        duration: Wall-clock seconds the stage took.
        plugins_run: Number of plugins invoked.
        plugins_succeeded: Number of plugins that returned success.
    """
    stage: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration: float = 0.0
    plugins_run: int = 0
    plugins_succeeded: int = 0

    def to_dict(self) -> StageResultDict:
        return asdict(self)


@dataclass
class PipelineResult:
    """Complete pipeline output.

    Attributes:
        success: ``True`` if every stage succeeded.
        stages: Per-stage results in execution order.
        shared_data: Merged scratchpad data from all stages.
        llm_insights: LLM-generated analysis notes (if enabled).
        total_duration: Wall-clock seconds for the entire pipeline.
        errors: Collected error messages from any failed stages.
    """
    success: bool
    stages: List[StageResult] = field(default_factory=list)
    shared_data: Dict[str, Any] = field(default_factory=dict)
    llm_insights: Dict[str, Any] = field(default_factory=dict)
    total_duration: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> PipelineResultDict:
        d = asdict(self)
        d["stages"] = [s.to_dict() for s in self.stages]
        return d


# ---------------------------------------------------------------------------
# Analysis Pipeline
# ---------------------------------------------------------------------------

class AnalysisPipeline:
    """
    Orchestrates sequential stage execution with a shared context.

    Unlike the flat-parallel dispatch in :class:`Orchestrator`, the pipeline
    ensures that data produced by early stages (e.g. static analysis extracts
    sections, imports, strings) is available to later stages (e.g. dynamic
    analysis uses extracted entry points, enrichment uses function hashes).
    """

    def __init__(self, config: Optional[Any] = None) -> None:
        try:
            from ..core.config import get_config
            self._cfg = config or get_config()
        except (ImportError, AttributeError, KeyError):
            self._cfg = config

    # -- public API ---------------------------------------------------------

    def run(
        self,
        binary_data: bytes,
        pipeline_config: PipelineConfig | None = None,
        *,
        metadata: Dict[str, Any] | None = None,
    ) -> PipelineResult:
        """
        Execute the full analysis pipeline on *binary_data*.

        Parameters
        ----------
        binary_data : bytes
            Raw binary to analyse.
        pipeline_config : PipelineConfig | None
            Override defaults.
        metadata : dict | None
            Caller-provided metadata (filename, tags, …).

        Returns
        -------
        PipelineResult
            Combined output from all stages.
        """
        from ..plugins import PluginContext, Stage, get_all_plugins
        from ..plugins._storage import create_storage

        t0 = time.monotonic()
        cfg = pipeline_config or PipelineConfig()
        metadata = metadata or {}
        self._current_max_workers = cfg.max_workers

        # --- build shared context (ONE context for the entire pipeline) ----
        storage = create_storage(cfg.storage_backend, **cfg.storage_options)
        work_dir = tempfile.mkdtemp(prefix="vmds_pipeline_")

        sha256 = hashlib.sha256(binary_data).hexdigest()

        ctx = PluginContext(
            storage=storage,
            config=dict(self._cfg._config) if hasattr(self._cfg, "_config") else {},
            shared_data={
                "binary_size": len(binary_data),
                "sha256": sha256,
                "metadata": metadata,
                "pipeline_stages_completed": [],
            },
            sample_hash=sha256,
            work_dir=work_dir,
        )

        file_path = metadata.get("filename", "")

        # --- stage dispatch map -------------------------------------------
        stage_handlers: Dict[str, Callable] = {
            "binary_parse": lambda: self._run_binary_parse(binary_data, ctx),
            "pattern_analysis": lambda: self._run_pattern_analysis(binary_data, ctx),
            "vm_discovery": lambda: self._run_vm_discovery(binary_data, ctx),
            "anti_evasion": lambda: self._run_anti_evasion(binary_data, ctx),
            "classify": lambda: self._run_classify(ctx),
            "taint_analysis": lambda: self._run_taint_analysis(binary_data, ctx),
            "symbolic_execution": lambda: self._run_symbolic_execution(binary_data, ctx),
            "dispatcher_analysis": lambda: self._run_dispatcher_analysis(binary_data, ctx),
            "devirtualize": lambda: self._run_devirtualize(binary_data, ctx),
            "static": lambda: self._run_plugin_stage(binary_data, file_path, ctx, Stage.STATIC, "static"),
            "dynamic": lambda: self._run_plugin_stage(binary_data, file_path, ctx, Stage.DYNAMIC, "dynamic"),
            "enrichment": lambda: self._run_plugin_stage(binary_data, file_path, ctx, Stage.ENRICHMENT, "enrichment"),
            "reporting": lambda: self._run_plugin_stage(binary_data, file_path, ctx, Stage.REPORTING, "reporting"),
            "llm_analysis": lambda: self._run_llm_analysis(binary_data, ctx),
            "llm_summary": lambda: self._run_llm_summary(ctx),
        }

        # --- execute stages sequentially -----------------------------------
        stage_results: List[StageResult] = []
        errors: List[str] = []
        llm_insights: Dict[str, Any] = {}

        try:
          for stage_name in cfg.stages:
            handler = stage_handlers.get(stage_name)
            if handler is None:
                logger.warning("Unknown pipeline stage '%s' — skipping", stage_name)
                continue

            # Skip LLM stages if disabled
            if stage_name.startswith("llm_") and not cfg.llm_enabled:
                continue

            try:
                # Enforce per-stage timeout via a thread-pool future.
                stage_timeout = cfg.timeout if cfg.timeout > 0 else None
                pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                future = pool.submit(handler)
                try:
                    sr = future.result(timeout=stage_timeout)
                except concurrent.futures.TimeoutError:
                    logger.warning(
                        "Stage %s exceeded timeout of %.1fs", stage_name, cfg.timeout,
                    )
                    sr = StageResult(
                        stage=stage_name,
                        success=False,
                        error=f"timeout after {cfg.timeout}s",
                    )
                finally:
                    # Shut down without waiting for the hung thread.
                    pool.shutdown(wait=False, cancel_futures=True)
                stage_results.append(sr)
                ctx.shared_data["pipeline_stages_completed"].append(stage_name)

                if not sr.success and sr.error:
                    errors.append(f"[{stage_name}] {sr.error}")

                # Collect LLM insights separately
                if stage_name.startswith("llm_") and sr.data:
                    llm_insights[stage_name] = sr.data

            except _STAGE_ERRORS as exc:
                logger.exception("Pipeline stage %s failed", stage_name)
                stage_results.append(StageResult(
                    stage=stage_name,
                    success=False,
                    error=str(exc),
                ))
                errors.append(f"[{stage_name}] {exc}")

        finally:
            # Always clean up the temp directory
            _shutil.rmtree(work_dir, ignore_errors=True)

        elapsed = time.monotonic() - t0
        any_success = any(sr.success for sr in stage_results) if stage_results else False

        return PipelineResult(
            success=any_success,
            stages=stage_results,
            shared_data=ctx.shared_data,
            llm_insights=llm_insights,
            total_duration=elapsed,
            errors=errors,
        )

    # -- stage runner helper ------------------------------------------------

    def _run_stage(
        self,
        stage_name: str,
        fn: Callable[[], Dict[str, Any]],
        ctx: Any | None = None,
    ) -> StageResult:
        """Execute *fn* and wrap its return value in a :class:`StageResult`.

        This eliminates the repetitive try/except + timing boilerplate that
        every ``_run_*`` method previously duplicated.

        Parameters
        ----------
        stage_name : str
            Key for the stage (used in ``StageResult.stage``).
        fn : callable
            Zero-argument callable that performs the work and returns a
            ``dict`` of result data.  It may also return a :class:`StageResult`
            directly for full control.
        ctx : PluginContext | None
            If provided, result data are stored into ``ctx.shared_data[stage_name]``.

        Returns
        -------
        StageResult
        """
        t0 = time.monotonic()
        try:
            out = fn()
            elapsed = time.monotonic() - t0
            if isinstance(out, StageResult):
                out.duration = elapsed
                return out
            data = out if isinstance(out, dict) else {}
            if ctx is not None:
                ctx.shared_data[stage_name] = data
            return StageResult(stage=stage_name, success=True, data=data, duration=elapsed)
        except _STAGE_ERRORS as exc:
            logger.exception("%s stage failed", stage_name)
            return StageResult(
                stage=stage_name, success=False, error=str(exc),
                duration=time.monotonic() - t0,
            )

    # -- built-in engine stages --------------------------------------------

    def _run_binary_parse(
        self,
        binary_data: bytes,
        ctx: Any,
    ) -> StageResult:
        """Parse binary format and populate shared_data with PE/ELF info.

        Stores ``image_base``, ``entry_point``, ``architecture``,
        and ``sections`` so downstream stages can access them
        without redoing PE parsing.
        """
        t0 = time.monotonic()
        try:
            from ..analysis.binary_format import parse_binary
            parsed = parse_binary(binary_data)
            ctx.shared_data["parsed_binary"] = parsed
            ctx.shared_data["image_base"] = parsed.image_base
            ctx.shared_data["entry_point"] = parsed.entry_point
            arch_val = getattr(parsed.architecture, "value", str(parsed.architecture))
            ctx.shared_data["architecture"] = arch_val
            ctx.shared_data["binary_format"] = getattr(
                parsed.format, "value", str(parsed.format)
            )
            ctx.shared_data["sections"] = [
                {
                    "name": s.name,
                    "virtual_address": s.virtual_address,
                    "virtual_size": s.virtual_size,
                    "raw_size": s.raw_size,
                    "characteristics": s.characteristics,
                    "entropy": getattr(s, "entropy", 0.0),
                }
                for s in parsed.sections
            ]
            data = {
                "image_base": parsed.image_base,
                "entry_point": parsed.entry_point,
                "architecture": arch_val,
                "section_count": len(parsed.sections),
            }
            return StageResult(
                stage="binary_parse", success=True, data=data,
                duration=time.monotonic() - t0,
            )
        except _STAGE_ERRORS as exc:
            logger.debug("Binary parse stage failed: %s", exc)
            return StageResult(
                stage="binary_parse", success=False, error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _run_pattern_analysis(
        self,
        binary_data: bytes,
        ctx: Any,
    ) -> StageResult:
        """Run the local pattern recogniser and store results in shared_data."""
        t0 = time.monotonic()
        try:
            from ..analysis.pattern_analysis.database import PatternDatabase
            from ..analysis.pattern_analysis.recognizer import PatternRecognizer

            # Load pattern database
            # parents[2] reaches the project root (pipeline.py → core/ → dragonslayer/ → root)
            db = PatternDatabase()
            project_root = Path(__file__).resolve().parents[2]
            for candidate in [
                project_root / "data" / "patterns" / "vmprotect_handlers.json",
                project_root / "data" / "patterns" / "themida_patterns.json",
            ]:
                if candidate.exists():
                    db = PatternDatabase(candidate)
                    break

            recognizer = PatternRecognizer(db)
            hex_str = binary_data.hex().upper()
            matches = recognizer.recognize(hex_str)

            matches_data = []
            for m in matches:
                md = {
                    "pattern_id": m.pattern.pattern_id,
                    "name": m.pattern.name,
                    "operation": m.pattern.operation,
                    "handler_type": m.pattern.handler_type,
                    "architecture": m.pattern.architecture,
                    "start_offset": m.start_offset,
                    "end_offset": m.end_offset,
                    "matched_bytes": m.matched_bytes,
                    "confidence": m.confidence,
                }
                matches_data.append(md)

            avg_confidence = (
                sum(m.confidence for m in matches) / len(matches) if matches else 0.0
            )

            result_data = {
                "matches": matches_data,
                "total_matches": len(matches),
                "patterns_checked": len(recognizer.database),
                "avg_confidence": round(avg_confidence, 4),
            }

            # Store in shared_data for downstream stages
            ctx.shared_data["pattern_analysis"] = result_data
            ctx.shared_data["pattern_matches"] = matches_data

            return StageResult(
                stage="pattern_analysis",
                success=True,
                data=result_data,
                duration=time.monotonic() - t0,
            )

        except _STAGE_ERRORS as exc:
            logger.exception("Pattern analysis stage failed")
            return StageResult(
                stage="pattern_analysis",
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _run_vm_discovery(
        self,
        binary_data: bytes,
        ctx: Any,
    ) -> StageResult:
        """Run VM discovery heuristics and store results in shared_data."""
        t0 = time.monotonic()
        try:
            from ..analysis.vm_discovery.detector import VMDetector
            from ..analysis.vm_discovery.database import VMSignatureDatabase

            detector = VMDetector()
            result = detector.detect(binary_data)

            # Add binary hex for entry-point pattern matching in signature DB
            result["binary_hex"] = binary_data[:0x2000].hex().upper()

            # Match against known protector signatures
            sig_db = VMSignatureDatabase()
            sig_matches = sig_db.match(result)
            result["signature_matches"] = sig_matches

            # Extract dispatcher addresses (offsets → ints) for downstream
            dispatcher_addrs = [
                d["offset"] for d in result.get("dispatchers", [])
                if isinstance(d, dict) and "offset" in d
            ]
            result["dispatcher_addresses"] = dispatcher_addrs

            ctx.shared_data["vm_discovery"] = result
            ctx.shared_data["vm_detected"] = result.get("vm_detected", False)
            ctx.shared_data["vm_confidence"] = result.get("confidence", 0.0)

            return StageResult(
                stage="vm_discovery",
                success=True,
                data=result,
                duration=time.monotonic() - t0,
            )

        except _STAGE_ERRORS as exc:
            logger.exception("VM discovery stage failed")
            return StageResult(
                stage="vm_discovery",
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    # -- plugin stage runner -----------------------------------------------

    def _run_plugin_stage(
        self,
        binary_data: bytes,
        file_path: str,
        ctx: Any,
        stage: Any,
        label: str,
    ) -> StageResult:
        """
        Execute all available plugins for *stage* using the shared context.

        This is the critical difference from the old orchestrator: the SAME
        ``ctx`` is passed to every stage, so plugins can read data deposited
        by previous stages via ``ctx.shared_data``.
        """
        from ..plugins import get_all_plugins

        t0 = time.monotonic()
        try:
            plugins = get_all_plugins(stage=stage, available_only=True)
            if not plugins:
                return StageResult(
                    stage=label,
                    success=True,
                    data={"plugins_run": 0, "note": f"No plugins available for {label}"},
                    duration=time.monotonic() - t0,
                )

            plugin_results: Dict[str, Any] = {}
            successes = 0
            total_confidence = 0.0

            max_w = getattr(self, "_current_max_workers", 4)

            def _exec_one(plugin):
                return plugin.name, plugin.safe_execute(file_path, binary_data, ctx)

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_w) as pool:
                futures = {pool.submit(_exec_one, p): p for p in plugins}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        name, pr = future.result()
                    except _STAGE_ERRORS as exc:
                        plugin = futures[future]
                        name = plugin.name
                        logger.warning("Plugin %s raised: %s", name, exc)
                        continue
                    plugin_results[name] = pr.to_dict()
                    if pr.success:
                        successes += 1
                        total_confidence += pr.confidence
                        if pr.data:
                            ctx.set_shared("plugin_results",
                                           {**ctx.get_shared("plugin_results", {}), name: pr.data})

            elapsed = time.monotonic() - t0
            avg_confidence = total_confidence / successes if successes else 0.0

            stage_data = {
                "plugins_run": len(plugins),
                "successful": successes,
                "failed": len(plugins) - successes,
                "results": plugin_results,
                "avg_confidence": round(avg_confidence, 4),
            }

            # Store aggregated stage results in shared_data
            ctx.set_shared(label, stage_data)

            return StageResult(
                stage=label,
                success=successes > 0,
                data=stage_data,
                duration=elapsed,
                plugins_run=len(plugins),
                plugins_succeeded=successes,
            )

        except _STAGE_ERRORS as exc:
            logger.exception("Plugin stage %s failed", label)
            return StageResult(
                stage=label,
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    # -- analysis engine stages --------------------------------------------

    def _run_anti_evasion(
        self,
        binary_data: bytes,
        ctx: Any,
    ) -> StageResult:
        """Detect and catalogue anti-analysis / anti-debug techniques.

        Also builds the runtime hook-set (Batch 17) so downstream
        stages can install hooks into Qiling / angr / Triton.
        """
        t0 = time.monotonic()
        try:
            from ..analysis.anti_evasion.environment_normalizer import EnvironmentNormalizer

            normalizer = EnvironmentNormalizer()
            report = normalizer.analyze(binary_data)
            result_data = report.to_dict()

            ctx.shared_data["anti_evasion"] = result_data
            ctx.shared_data["evasion_risk"] = report.risk_score

            # Build runtime hook-set from the report (Batch 17).
            try:
                from ..analysis.anti_evasion.runtime_hooks import (
                    build_hook_set_from_report,
                )
                hook_set = build_hook_set_from_report(result_data)
                result_data["runtime_hooks"] = {
                    "hook_count": len(hook_set.hooks),
                    "categories": list({h.category.value for h in hook_set.hooks}),
                    "hook_names": [h.name for h in hook_set.hooks],
                }
                ctx.shared_data["runtime_hook_set"] = hook_set
            except _STAGE_ERRORS as exc:
                logger.debug("Runtime hook-set generation skipped: %s", exc)

            return StageResult(
                stage="anti_evasion",
                success=True,
                data=result_data,
                duration=time.monotonic() - t0,
            )
        except _STAGE_ERRORS as exc:
            logger.exception("Anti-evasion stage failed")
            return StageResult(
                stage="anti_evasion",
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _run_classify(self, ctx: Any) -> StageResult:
        """Classify pattern matches into handler categories."""
        t0 = time.monotonic()
        try:
            from ..analysis.pattern_analysis.classifier import PatternClassifier

            matches = ctx.shared_data.get("pattern_matches", [])
            if not matches:
                return StageResult(
                    stage="classify",
                    success=True,
                    data={"skipped": True, "reason": "No pattern matches to classify"},
                    duration=time.monotonic() - t0,
                )

            classifier = PatternClassifier(use_llm=False)
            report = classifier.classify_matches(matches)
            result_data = report.to_dict()

            ctx.shared_data["classification"] = result_data
            ctx.shared_data["dominant_handler_type"] = (
                report.dominant_type.value if report.dominant_type else None
            )
            ctx.shared_data["vm_complexity"] = report.complexity_score

            return StageResult(
                stage="classify",
                success=True,
                data=result_data,
                duration=time.monotonic() - t0,
            )
        except _STAGE_ERRORS as exc:
            logger.exception("Classification stage failed")
            return StageResult(
                stage="classify",
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _run_taint_analysis(
        self,
        binary_data: bytes,
        ctx: Any,
    ) -> StageResult:
        """Run taint tracking over the binary using VM discovery results.

        When dynamic plugin output is available (Qiling / angr / Triton),
        the trace is ingested via :func:`trace_ingestion.from_shared_data`
        and its :meth:`to_lifted_instructions` is used — this preserves
        concrete register snapshots and Triton taint flags.

        Falls back to raw-binary lifting when no dynamic data is present.

        When a VM protector is detected, uses :class:`VMTaintTracker` which
        provides virtual register mapping and handler boundary detection.
        Otherwise falls back to the generic :class:`TaintAnalyzer`.
        """
        t0 = time.monotonic()
        try:
            from ..analysis.taint_tracking.analyzer import TaintAnalyzer
            from ..analysis.taint_tracking.vm_taint_tracker import VMTaintTracker
            from ..analysis.symbolic_execution.lifter import InstructionLifter
            from ..analysis.trace_ingestion import from_shared_data

            # Determine entry point from vm_discovery
            vm_info = ctx.shared_data.get("vm_discovery", {})
            dispatcher_addrs = vm_info.get("dispatcher_addresses", [])
            entry = dispatcher_addrs[0] if dispatcher_addrs else 0

            # ----------------------------------------------------------
            # Prefer dynamic plugin traces (Qiling → taint, Triton → taint)
            # over raw-binary lifting.  This carries register snapshots
            # and per-instruction taint from the plugin engines.
            # ----------------------------------------------------------
            instructions = None
            trace_source = "binary"

            has_dynamic = any(
                ctx.shared_data.get(k)
                for k in ("qiling", "triton", "angr")
            )
            if has_dynamic:
                try:
                    trace = from_shared_data(ctx.shared_data)
                    if trace and trace.instructions:
                        instructions = trace.to_lifted_instructions()
                        trace_source = trace.source
                        logger.info(
                            "Taint stage: using %d instructions from %s",
                            len(instructions), trace_source,
                        )
                except _STAGE_ERRORS:
                    logger.debug(
                        "Taint stage: plugin trace ingestion failed, "
                        "falling back to binary lift",
                        exc_info=True,
                    )

            # Fallback: lift directly from binary
            if not instructions:
                lifter = InstructionLifter()
                instructions = lifter.lift(binary_data, base_address=entry)
                trace_source = "binary"

            if not instructions:
                return StageResult(
                    stage="taint_analysis",
                    success=True,
                    data={"skipped": True, "reason": "No instructions lifted from binary"},
                    duration=time.monotonic() - t0,
                )

            vm_detected = vm_info.get("vm_detected", False)

            if vm_detected:
                # Use VM-aware tracker with virtual register mapping
                vm_type = vm_info.get("vm_type", "").lower()
                # Pick preset based on detected VM type
                if "vmprotect" in vm_type:
                    preset = "vmprotect_x64"
                elif "themida" in vm_type:
                    preset = "themida_x64"
                else:
                    preset = None

                vtt = VMTaintTracker()
                result = vtt.analyze_vm_trace(
                    instructions,
                    vm_preset=preset,
                )
                ctx.shared_data["taint_results"] = result
            else:
                # Generic taint analysis (no VM-specific enrichment)
                taint_sources: dict[str, str] = {}
                analyzer = TaintAnalyzer()
                result = analyzer.analyze(
                    instructions,
                    taint_sources=taint_sources,
                    shared_data=ctx.shared_data,
                )
                ctx.shared_data["taint_results"] = result

            # Annotate result with trace provenance.
            if isinstance(result, dict):
                result["trace_source"] = trace_source
            elif hasattr(result, "to_dict"):
                pass  # provenance added by caller if needed

            return StageResult(
                stage="taint_analysis",
                success=True,
                data=result,
                duration=time.monotonic() - t0,
            )
        except _STAGE_ERRORS as exc:
            logger.exception("Taint analysis stage failed")
            return StageResult(
                stage="taint_analysis",
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _run_symbolic_execution(
        self,
        binary_data: bytes,
        ctx: Any,
    ) -> StageResult:
        """Run symbolic execution to analyse VM handlers.

        When dynamic plugin output is available (angr / Triton), the
        trace is ingested and its code regions are extracted so the
        symbolic executor operates on *executing* code rather than the
        whole binary blob.  If the Triton plugin provided path
        constraints they are forwarded to the Z3 solver as seed
        constraints, giving the explorer a head start.
        """
        t0 = time.monotonic()
        try:
            from ..analysis.symbolic_execution.executor import SymbolicExecutor
            from ..analysis.trace_ingestion import from_shared_data

            # Use dispatcher address from vm_discovery if available
            vm_info = ctx.shared_data.get("vm_discovery", {})
            dispatcher_addrs = vm_info.get("dispatcher_addresses", [])
            entry = dispatcher_addrs[0] if dispatcher_addrs else 0

            executor = SymbolicExecutor()

            # ----------------------------------------------------------
            # Try to extract code regions from dynamic plugin traces so
            # the symbolic executor works on real handler code rather
            # than the entire binary.
            # ----------------------------------------------------------
            code_to_analyze = binary_data
            trace_regions = None
            has_dynamic = any(
                ctx.shared_data.get(k)
                for k in ("angr", "triton")
            )
            if has_dynamic:
                try:
                    trace = from_shared_data(ctx.shared_data)
                    if trace and trace.instructions:
                        regions = trace.extract_code_regions()
                        if regions:
                            trace_regions = regions
                            # Build a single code blob aligned to the
                            # lowest address, suitable for the lifter.
                            base_addr = min(regions.keys())
                            end_addr = max(
                                addr + len(data)
                                for addr, data in regions.items()
                            )
                            buf = bytearray(end_addr - base_addr)
                            for addr, data in regions.items():
                                offset = addr - base_addr
                                buf[offset:offset + len(data)] = data
                            code_to_analyze = bytes(buf)
                            if entry == 0:
                                entry = base_addr
                            logger.info(
                                "Symbolic stage: using %d code regions "
                                "(%d bytes) from plugin traces",
                                len(regions), len(code_to_analyze),
                            )

                        # Forward Triton path constraints as seed
                        # constraints for the Z3 solver.
                        path_constraints = trace.metadata.get(
                            "path_constraints", [],
                        )
                        if path_constraints:
                            ctx.shared_data.setdefault(
                                "_triton_path_constraints",
                                path_constraints,
                            )
                except _STAGE_ERRORS:
                    logger.debug(
                        "Symbolic stage: plugin trace ingestion failed, "
                        "falling back to raw binary",
                        exc_info=True,
                    )

            result = executor.analyze(code_to_analyze, entry_point=entry)

            result_data = result.to_dict() if hasattr(result, "to_dict") else {
                "handlers": [
                    h.to_dict() if hasattr(h, "to_dict") else {
                        "address": getattr(h, "address", 0),
                        "category": getattr(h, "category", "unknown"),
                        "instruction_count": getattr(h, "instruction_count", 0),
                        "confidence": getattr(h, "confidence", 0),
                    }
                    for h in getattr(result, "handlers", [])
                ],
                "paths_explored": getattr(result, "paths_explored", 0),
                "dispatcher_address": getattr(result, "dispatcher_address", 0),
                "opaque_predicates": getattr(result, "opaque_predicates", []),
            }

            # Annotate with trace provenance when plugin data was used.
            if trace_regions is not None:
                result_data["trace_source"] = "plugin"
                result_data["trace_region_count"] = len(trace_regions)

            ctx.shared_data["symbolic_execution"] = result_data

            return StageResult(
                stage="symbolic_execution",
                success=True,
                data=result_data,
                duration=time.monotonic() - t0,
            )
        except _STAGE_ERRORS as exc:
            logger.exception("Symbolic execution stage failed")
            return StageResult(
                stage="symbolic_execution",
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _run_dispatcher_analysis(
        self,
        binary_data: bytes,
        ctx: Any,
    ) -> StageResult:
        """
        Identify VM dispatchers and reconstruct the handler dispatch table.

        Runs after symbolic_execution so it can incorporate handler
        classifications.  Stores the dispatch table in shared_data for
        the LLM analyzer and reporter.
        """
        t0 = time.monotonic()
        try:
            from ..analysis.vm_discovery.dispatcher import DispatcherAnalyzer

            analyzer = DispatcherAnalyzer()
            result = analyzer.analyze(binary_data, shared_data=ctx.shared_data)
            result_data = result.to_dict()

            ctx.shared_data["dispatcher_analysis"] = result_data
            ctx.shared_data["handler_table"] = result_data.get("handler_table", [])

            return StageResult(
                stage="dispatcher_analysis",
                success=result.success,
                data=result_data,
                duration=time.monotonic() - t0,
            )
        except _STAGE_ERRORS as exc:
            logger.exception("Dispatcher analysis stage failed")
            return StageResult(
                stage="dispatcher_analysis",
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    # -- LLM stages --------------------------------------------------------

    def _run_devirtualize(
        self,
        binary_data: bytes,
        ctx: Any,
    ) -> StageResult:
        """End-to-end devirtualisation pipeline stage.

        Chains eight sub-steps:

        1. **Trace ingestion** — convert dynamic-plugin output to a
           unified :class:`ExecutionTrace`.
        2. **Anti-evasion hooks** — if an ``anti_evasion`` report is
           available, build the hook-set and store it (Batch 17).
        3. **VMProtect dispatcher identification** — locate the fetch →
           decode → dispatch loop and reconstruct the handler table
           (Batch 13).
        4. **vIP identification + segmentation** — locate the virtual IP
           register and slice the trace into per-handler segments.
        5. **Handler extraction** — extract concrete handler bodies,
           register deltas, and fingerprints from the trace segments
           (Batch 14).
        6. **VM context register identification** — identify virtual
           stack pointer, table-base, decode-key, and context-base
           registers from the trace (Batch 15).
        7. **Semantic analysis + clustering** — classify each handler's
           VM-level operation, then cluster semantically-equivalent
           handler variants (Batch 16).
        8. **Pseudocode emission** — emit human-readable output, passing
           the handler-level CFG when available.

        Results (including pseudocode) are stored in
        ``ctx.shared_data["devirtualize"]``.
        """
        def _do_devirt() -> Dict[str, Any]:
            from ..analysis.trace_ingestion import from_shared_data, ExecutionTrace
            from ..analysis.vm_discovery.handler_boundaries import (
                identify_vip_register,
                segment_trace,
            )
            from ..analysis.handler_semantics import analyse_handler_semantics
            from ..analysis.pseudocode import emit_pseudocode
            from ..analysis.devirtualisation_result import DevirtualisationResult

            # ── 1. Obtain an ExecutionTrace ──────────────────────────────
            trace: ExecutionTrace | None = None
            try:
                trace = from_shared_data(ctx.shared_data)
            except _STAGE_ERRORS:
                pass

            if trace is None or not trace.instructions:
                return DevirtualisationResult.skipped_result(
                    "No execution trace available — run dynamic analysis first",
                ).to_dict()

            # Derive base address from PE analysis or shared_data.
            base_address: int = ctx.shared_data.get("image_base", 0)
            if not base_address:
                pe_info = ctx.shared_data.get("pe_analyzer", {})
                if isinstance(pe_info, dict):
                    base_address = pe_info.get("image_base", 0) or pe_info.get("base_address", 0)
            if not base_address:
                base_address = ctx.shared_data.get("base_address", 0)

            # ── 2. Anti-evasion hook-set (Batch 17) ──────────────────────
            hook_set_data: Optional[Dict[str, Any]] = None
            try:
                from ..analysis.anti_evasion.runtime_hooks import (
                    build_hook_set_from_report,
                )
                ae_report = ctx.shared_data.get("anti_evasion")
                if ae_report is not None:
                    hook_set = build_hook_set_from_report(ae_report)
                    hook_set_data = {
                        "hook_count": len(hook_set.hooks),
                        "categories": list({h.category.value for h in hook_set.hooks}),
                        "hook_names": [h.name for h in hook_set.hooks],
                    }
            except _STAGE_ERRORS as exc:
                logger.debug("Anti-evasion hook-set skipped: %s", exc)

            # ── 2b. VM entry point locator (Batch 21) ────────────────────
            vm_entry_data: Optional[Dict[str, Any]] = None
            try:
                from ..analysis.vm_discovery.vm_entry_locator import (
                    locate_entries_from_pe_result,
                    locate_vm_entries,
                )
                pe_result = ctx.shared_data.get("pe_analyzer")
                if pe_result and isinstance(pe_result, dict):
                    entry_report = locate_entries_from_pe_result(
                        binary_data, pe_result)
                elif len(binary_data) > 64 and binary_data[:2] == b"MZ":
                    entry_report = locate_vm_entries(binary_data)
                else:
                    entry_report = None

                if entry_report is not None and entry_report.count > 0:
                    vm_entry_data = entry_report.to_dict()
                    ctx.shared_data["vm_entry_points"] = vm_entry_data
            except _STAGE_ERRORS as exc:
                logger.debug("VM entry locator skipped: %s", exc)

            # ── 3. VMProtect dispatcher identification (Batch 13) ────────
            vmprotect_match: Optional[Dict[str, Any]] = None
            try:
                from ..analysis.vm_discovery.dispatcher import (
                    find_vmprotect_dispatcher,
                    find_dispatcher_in_trace,
                )

                # Try trace-based first (more reliable), fall back to binary
                disp_match = find_dispatcher_in_trace(trace)
                if disp_match is None:
                    disp_match = find_vmprotect_dispatcher(binary_data)

                if disp_match is not None:
                    vmprotect_match = disp_match.to_dict()
                    # Inject handler addresses into dispatcher_addrs pool
                    ctx.shared_data.setdefault("vmprotect_dispatcher", vmprotect_match)
            except _STAGE_ERRORS as exc:
                logger.debug("VMProtect dispatcher identification skipped: %s", exc)

            # ── 3b. Rolling-key decryptor + handler table decrypt (B24/25) ─
            bytecode_decryptor = None
            try:
                from ..analysis.bytecode_decrypt import (
                    make_decryptor_from_dispatcher,
                    decrypt_handler_table,
                )
                if vmprotect_match is not None:
                    bytecode_decryptor = make_decryptor_from_dispatcher(
                        vmprotect_match, trace,
                    )
                    if bytecode_decryptor is not None:
                        ctx.shared_data["bytecode_decryptor"] = {
                            "initial_key": bytecode_decryptor.initial_key,
                            "key_width": bytecode_decryptor.key_width,
                            "transform_count": len(bytecode_decryptor.transforms),
                        }

                    # Decrypt handler table if table_base is available
                    tbl_base = vmprotect_match.get("table_base", 0)
                    if tbl_base and binary_data and len(binary_data) > 64:
                        known_addrs = vmprotect_match.get(
                            "handler_addresses", [],
                        )
                        dec_table = decrypt_handler_table(
                            binary_data, tbl_base, base_address,
                            bit_width=64,
                            known_handler_addresses=known_addrs or None,
                        )
                        if dec_table.count > 0:
                            ctx.shared_data["decrypted_handler_table"] = (
                                dec_table.to_dict()
                            )
            except _STAGE_ERRORS as exc:
                logger.debug("Bytecode decryptor / table decrypt skipped: %s", exc)

            # ── 4. Identify vIP and segment into handler boundaries ──────
            dispatcher_addrs: list = list(
                ctx.shared_data.get("vm_discovery", {}).get(
                    "dispatcher_addresses", [],
                )
            )

            # Supplement from DispatcherAnalyzer handler_table (Batch 4).
            handler_table = ctx.shared_data.get("handler_table", [])
            if handler_table:
                ht_addrs = set(dispatcher_addrs)
                for entry in handler_table:
                    addr = entry.get("handler_address") if isinstance(entry, dict) else getattr(entry, "handler_address", None)
                    if addr and addr not in ht_addrs:
                        dispatcher_addrs.append(addr)
                        ht_addrs.add(addr)

            # Also supplement from the VMProtect dispatcher match.
            if vmprotect_match is not None:
                ht_addrs = set(dispatcher_addrs)
                for ht_entry in vmprotect_match.get("handler_table", []):
                    addr = ht_entry.get("handler_address") if isinstance(ht_entry, dict) else getattr(ht_entry, "handler_address", None)
                    if addr and addr not in ht_addrs:
                        dispatcher_addrs.append(addr)
                        ht_addrs.add(addr)

            vip_candidate = identify_vip_register(trace, dispatcher_addrs)

            if vip_candidate is None:
                return DevirtualisationResult.skipped_result(
                    "Could not identify virtual instruction pointer register",
                ).to_dict()

            seg = segment_trace(trace, vip_candidate, dispatcher_addrs)
            boundaries = seg.boundaries

            if not boundaries:
                return DevirtualisationResult.skipped_result(
                    "Trace segmentation produced no handler boundaries",
                ).to_dict()

            # ── 5. Handler extraction (Batch 14) ─────────────────────────
            extraction_data: Optional[Dict[str, Any]] = None
            try:
                from ..analysis.vm_discovery.handler_extraction import (
                    extract_handler_bodies,
                )
                extraction = extract_handler_bodies(trace, boundaries)
                extraction_data = extraction.to_dict()
                ctx.shared_data["handler_extraction"] = extraction_data
            except _STAGE_ERRORS as exc:
                logger.debug("Handler extraction skipped: %s", exc)

            # ── 6. VM context register identification (Batch 15) ─────────
            context_layout_data: Optional[Dict[str, Any]] = None
            try:
                from ..analysis.vm_discovery.context_registers import (
                    identify_vm_context,
                )
                context_layout = identify_vm_context(trace, boundaries)
                context_layout_data = context_layout.to_dict()
                ctx.shared_data["vm_context_layout"] = context_layout_data
            except _STAGE_ERRORS as exc:
                logger.debug("VM context register identification skipped: %s", exc)

            # ── 7. Semantic analysis + clustering (Batch 16 + 22) ────────
            # Use the symbolic depth bridge to extract per-handler summaries
            # from all available sources (SE results, plugin traces,
            # handler extraction deltas), running fresh SE when coverage
            # is low.
            sym_summaries: Optional[Dict[int, Any]] = None
            try:
                from ..analysis.symbolic_depth import collect_symbolic_summaries
                ext_handlers = None
                if extraction_data and isinstance(extraction_data, dict):
                    ext_handlers = extraction_data.get("handlers")
                sym_summaries = collect_symbolic_summaries(
                    ctx.shared_data,
                    boundaries=boundaries,
                    handler_bodies=ext_handlers,
                    bit_width=64,
                    run_fresh=True,
                ) or None
            except _STAGE_ERRORS as exc:
                logger.debug("Symbolic depth collection skipped: %s", exc)
                sym_summaries = ctx.shared_data.get(
                    "symbolic_execution", {},
                ).get("handler_summaries", None)

            opcode_table = analyse_handler_semantics(
                trace, boundaries,
                symbolic_summaries=sym_summaries,
            )

            # Cluster semantically-equivalent handler variants.
            clustering_data: Optional[Dict[str, Any]] = None
            try:
                from ..analysis.handler_clustering import (
                    cluster_handlers_by_semantics,
                    refine_opcode_table,
                )
                clustering_result = cluster_handlers_by_semantics(
                    opcode_table,
                    symbolic_summaries=sym_summaries,
                )
                clustering_data = clustering_result.to_dict()
                ctx.shared_data["handler_clustering"] = clustering_data

                # Refine the opcode table with cluster annotations.
                opcode_table = refine_opcode_table(
                    opcode_table, clustering_result,
                )
            except _STAGE_ERRORS as exc:
                logger.debug("Handler clustering skipped: %s", exc)

            # ── 7c. ML ensemble classification (Batch 39) ────────────────
            ml_labels: Optional[Dict[str, str]] = None
            try:
                from ..ml.model import SymbolicClassifierModel, VMHandlerModel
                from ..ml.ensemble import WeightedEnsemble

                sym_model = SymbolicClassifierModel()
                heur_model = VMHandlerModel()
                ensemble = WeightedEnsemble(
                    models=[heur_model, sym_model],
                    weights=[0.4, 0.6],
                )

                ml_labels = {}
                for entry in opcode_table.entries:
                    features: Dict[str, Any] = {}
                    # Attach symbolic summary if available
                    if sym_summaries and entry.handler_address in sym_summaries:
                        s = sym_summaries[entry.handler_address]
                        features["symbolic_summary"] = (
                            s.to_dict() if hasattr(s, "to_dict") else s
                        )
                    # Attach heuristic features from the semantic
                    sem = entry.semantic
                    if sem is not None:
                        hist = getattr(sem, "mnemonic_histogram", {}) or {}
                        total = max(sum(hist.values()), 1)
                        features["values"] = [
                            hist.get("add", 0) / total,
                            hist.get("and", 0) / total,
                            hist.get("mov", 0) / total,
                            hist.get("push", 0) / total,
                            0.0, 0.0, 0.0, 0.0, 0.0,
                            float(total), 0.0, 0.0, 0.0,
                        ]
                        features["names"] = [
                            "arith_ratio", "logic_ratio", "mem_ratio",
                            "stack_ratio", "branch_ratio", "vip_delta",
                            "nop_ratio", "junk_ratio", "reg_diversity",
                            "insn_count", "avg_operands", "push_ratio",
                            "pop_ratio",
                        ]

                    pred = ensemble.predict(features)
                    addr_hex = f"0x{entry.handler_address:x}"
                    ml_labels[addr_hex] = pred.label

                    # Confidence boost when ML agrees with symbolic
                    if (
                        sem is not None
                        and pred.label == sem.operation
                        and pred.confidence > 0.7
                    ):
                        sem.confidence = min(sem.confidence + 0.05, 1.0)
            except _STAGE_ERRORS as exc:
                logger.debug("ML ensemble classification skipped: %s", exc)

            # ── 7b. Handler-level CFG construction (Batch 19 + B24) ────
            handler_cfg = None
            handler_cfg_data: Optional[Dict[str, Any]] = None
            try:
                from ..analysis.bytecode_cfg import (
                    build_handler_cfg,
                    build_static_cfg,
                )
                handler_cfg_obj = build_handler_cfg(
                    opcode_table, boundaries, trace,
                )
                if handler_cfg_obj.blocks:
                    handler_cfg = handler_cfg_obj.graph  # networkx DiGraph
                    handler_cfg_data = handler_cfg_obj.to_dict()
                    ctx.shared_data["handler_cfg"] = handler_cfg_data

                # If we have a decryptor and raw bytecode, also build
                # a static CFG (covers paths not in the trace).
                if bytecode_decryptor is not None and binary_data:
                    vip_start = boundaries[0].vip_value if boundaries else 0
                    # Extract bytecode region from binary
                    bc_offset = vip_start - base_address
                    if 0 <= bc_offset < len(binary_data):
                        bc_end = min(len(binary_data), bc_offset + 0x10000)
                        bc_bytes = binary_data[bc_offset:bc_end]
                        static_cfg_obj = build_static_cfg(
                            bc_bytes, opcode_table, vip_start,
                            decryptor=bytecode_decryptor,
                        )
                        if static_cfg_obj.blocks:
                            ctx.shared_data["static_handler_cfg"] = (
                                static_cfg_obj.to_dict()
                            )
                            # If trace-based CFG was empty, use static
                            if handler_cfg is None:
                                handler_cfg = static_cfg_obj.graph
                                handler_cfg_data = static_cfg_obj.to_dict()
                                ctx.shared_data["handler_cfg"] = (
                                    handler_cfg_data
                                )
            except _STAGE_ERRORS as exc:
                logger.debug("Handler CFG construction skipped: %s", exc)

            # ── 8. Pseudocode emission ───────────────────────────────────
            pseudocode_result = emit_pseudocode(
                opcode_table, boundaries, handler_cfg,
                style="c_like",
                context_layout=ctx.shared_data.get("vm_context_layout"),
                clustering=ctx.shared_data.get("handler_clustering"),
            )

            # ── Assemble result ──────────────────────────────────────────
            result = DevirtualisationResult(
                success=True,
                vip_register=vip_candidate.name,
                handler_count=len(boundaries),
                unique_operations=opcode_table.unique_operations,
                opcode_table=opcode_table.to_dict(),
                pseudocode=pseudocode_result.to_dict(),
                pseudocode_text=pseudocode_result.text,
                anti_evasion_hooks=hook_set_data,
                vmprotect_dispatcher=vmprotect_match,
                handler_extraction=extraction_data,
                vm_context_layout=context_layout_data,
                handler_clustering=clustering_data,
                handler_cfg=handler_cfg_data,
                vm_entry_points=vm_entry_data,
                decrypted_handler_table=ctx.shared_data.get("decrypted_handler_table"),
                bytecode_decryptor=ctx.shared_data.get("bytecode_decryptor"),
                static_handler_cfg=ctx.shared_data.get("static_handler_cfg"),
                ml_classifications=ml_labels,
            )

            # Store boundaries for downstream stages.
            ctx.shared_data["devirt_boundaries"] = [
                {
                    "vip_value": b.vip_value,
                    "handler_address": b.handler_address,
                    "vip_delta": b.vip_delta,
                    "instruction_count": b.instruction_count,
                }
                for b in boundaries
            ]

            return result.to_dict()

        return self._run_stage("devirtualize", _do_devirt, ctx)

    def _run_llm_analysis(
        self,
        binary_data: bytes,
        ctx: Any,
    ) -> StageResult:
        """
        LLM-assisted analysis using accumulated shared_data.

        Performs:
        1. Handler classification for any matched patterns.
        2. Deobfuscation hints if VM is detected.
        3. Code recovery if instruction traces are available.
        """
        t0 = time.monotonic()
        try:
            from ..llm import get_llm_analyzer

            llm = get_llm_analyzer()
            if not llm.available:
                return StageResult(
                    stage="llm_analysis",
                    success=True,
                    data={"skipped": True, "reason": "LLM not available"},
                    duration=time.monotonic() - t0,
                )

            insights: Dict[str, Any] = {}

            # 1. Classify matched patterns
            pattern_matches = ctx.shared_data.get("pattern_matches", [])
            if pattern_matches:
                classifications = []
                # Classify up to 10 most confident matches to avoid token overuse
                top_matches = sorted(
                    pattern_matches,
                    key=lambda m: m.get("confidence", 0),
                    reverse=True,
                )[:10]
                for match in top_matches:
                    result = llm.classify_handler(
                        handler_data=json.dumps(match, indent=2),
                        context=f"VM detected: {ctx.shared_data.get('vm_detected', False)}, "
                                f"Confidence: {ctx.shared_data.get('vm_confidence', 0)}",
                    )
                    if "error" not in result:
                        classifications.append({
                            "pattern": match.get("name", "unknown"),
                            "classification": result,
                        })
                if classifications:
                    insights["handler_classifications"] = classifications

            # 2. Deobfuscation suggestions if VM detected
            vm_data = ctx.shared_data.get("vm_discovery", {})
            if vm_data.get("vm_detected"):
                deobf = llm.suggest_deobfuscation(
                    structure=json.dumps(vm_data.get("indicators", []), indent=2),
                    indicators=json.dumps({
                        "sections": vm_data.get("indicators", []),
                        "patterns": len(pattern_matches),
                        "confidence": vm_data.get("confidence", 0),
                    }, indent=2),
                )
                if "error" not in deobf:
                    insights["deobfuscation_hints"] = deobf

            # 3. Code recovery if we have instruction traces from dynamic plugins
            traces = ctx.shared_data.get("plugin_results", {})
            if traces:
                # Look for traces from angr, triton, qiling
                for plugin_name in ("angr", "triton", "qiling"):
                    trace_data = traces.get(plugin_name)
                    if trace_data:
                        recovered = llm.recover_code(
                            instructions=json.dumps(trace_data, indent=2)[:8000],
                            taint_info=json.dumps(
                                ctx.shared_data.get("taint_results", {}), indent=2
                            )[:4000],
                        )
                        if "error" not in recovered:
                            insights.setdefault("code_recovery", {})[plugin_name] = recovered

            ctx.shared_data["llm_analysis"] = insights

            return StageResult(
                stage="llm_analysis",
                success=True,
                data=insights,
                duration=time.monotonic() - t0,
            )

        except _STAGE_ERRORS as exc:
            logger.exception("LLM analysis stage failed")
            return StageResult(
                stage="llm_analysis",
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _run_llm_summary(self, ctx: Any) -> StageResult:
        """
        Generate an executive summary of all analysis results using LLM.
        """
        t0 = time.monotonic()
        try:
            from ..llm import get_llm_analyzer

            llm = get_llm_analyzer()
            if not llm.available:
                return StageResult(
                    stage="llm_summary",
                    success=True,
                    data={"skipped": True, "reason": "LLM not available"},
                    duration=time.monotonic() - t0,
                )

            # Build a summary of all accumulated data
            summary_input = {
                "vm_detected": ctx.shared_data.get("vm_detected", False),
                "vm_confidence": ctx.shared_data.get("vm_confidence", 0),
                "pattern_matches_count": len(ctx.shared_data.get("pattern_matches", [])),
                "vm_discovery": ctx.shared_data.get("vm_discovery", {}),
                "static_analysis": _summarise_stage(ctx.shared_data.get("static", {})),
                "dynamic_analysis": _summarise_stage(ctx.shared_data.get("dynamic", {})),
                "enrichment": _summarise_stage(ctx.shared_data.get("enrichment", {})),
                "llm_insights": ctx.shared_data.get("llm_analysis", {}),
                "stages_completed": ctx.shared_data.get("pipeline_stages_completed", []),
            }

            summary = llm.summarise_analysis(summary_input)
            ctx.shared_data["llm_summary"] = summary

            return StageResult(
                stage="llm_summary",
                success=True,
                data=summary,
                duration=time.monotonic() - t0,
            )

        except _STAGE_ERRORS as exc:
            logger.exception("LLM summary stage failed")
            return StageResult(
                stage="llm_summary",
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )


# ---------------------------------------------------------------------------
# Pre-configured pipeline profiles
# ---------------------------------------------------------------------------

def create_full_pipeline(**kwargs: Any) -> tuple[AnalysisPipeline, PipelineConfig]:
    """Full analysis: all stages including LLM."""
    pipe = AnalysisPipeline(**kwargs)
    cfg = PipelineConfig(stages=[
        "pattern_analysis",
        "vm_discovery",
        "anti_evasion",
        "classify",
        "static",
        "dynamic",
        "taint_analysis",
        "symbolic_execution",
        "dispatcher_analysis",
        "devirtualize",
        "enrichment",
        "llm_analysis",
        "reporting",
        "llm_summary",
    ])
    return pipe, cfg


def create_vmprotect_devirt_pipeline(**kwargs: Any) -> tuple[AnalysisPipeline, PipelineConfig]:
    """
    Focused VMProtect devirtualisation pipeline.

    Stages:
    1. Pattern analysis — find VMProtect handler patterns.
    2. VM discovery — confirm VM presence and identify dispatcher.
    3. Anti-evasion — detect anti-debug/anti-VM tricks.
    4. Classification — categorise matched patterns into handler types.
    5. Static analysis — PE structure, strings, signatures.
    6. Dynamic analysis — angr CFG, triton symbolic exec, qiling trace.
    7. Taint analysis — track VM operand/context data flow.
    8. Symbolic execution — analyse handlers, detect opaque predicates.
    9. LLM analysis — classify handlers, suggest devirt strategy.
    10. Enrichment — similarity hashing, function matching.
    11. Reporting — generate deobfuscation report.
    12. LLM summary — executive debrief.
    """
    pipe = AnalysisPipeline(**kwargs)
    cfg = PipelineConfig(stages=[
        "pattern_analysis",
        "vm_discovery",
        "anti_evasion",
        "classify",
        "static",
        "dynamic",
        "taint_analysis",
        "symbolic_execution",
        "dispatcher_analysis",
        "devirtualize",
        "llm_analysis",
        "enrichment",
        "reporting",
        "llm_summary",
    ])
    return pipe, cfg


def create_quick_scan_pipeline(**kwargs: Any) -> tuple[AnalysisPipeline, PipelineConfig]:
    """Quick scan: pattern + VM discovery + classify + static only."""
    pipe = AnalysisPipeline(**kwargs)
    cfg = PipelineConfig(
        stages=["pattern_analysis", "vm_discovery", "anti_evasion", "classify", "static"],
        llm_enabled=False,
    )
    return pipe, cfg


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _summarise_stage(stage_data: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a compact summary from a stage's results dict."""
    if not stage_data:
        return {}
    return {
        "plugins_run": stage_data.get("plugins_run", 0),
        "successful": stage_data.get("successful", 0),
        "failed": stage_data.get("failed", 0),
    }
