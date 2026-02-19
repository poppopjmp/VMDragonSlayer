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
from typing import Any, Callable, Dict, List, Optional, Sequence

logger = logging.getLogger(__name__)


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
        ``"dynamic"``, ``"enrichment"``, ``"llm_analysis"``,
        ``"reporting"``, ``"llm_summary"``.
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

@dataclass
class StageResult:
    """Output from a single pipeline stage."""
    stage: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration: float = 0.0
    plugins_run: int = 0
    plugins_succeeded: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PipelineResult:
    """Complete pipeline output."""
    success: bool
    stages: List[StageResult] = field(default_factory=list)
    shared_data: Dict[str, Any] = field(default_factory=dict)
    llm_insights: Dict[str, Any] = field(default_factory=dict)
    total_duration: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
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
        except Exception:
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
            "pattern_analysis": lambda: self._run_pattern_analysis(binary_data, ctx),
            "vm_discovery": lambda: self._run_vm_discovery(binary_data, ctx),
            "anti_evasion": lambda: self._run_anti_evasion(binary_data, ctx),
            "classify": lambda: self._run_classify(ctx),
            "taint_analysis": lambda: self._run_taint_analysis(binary_data, ctx),
            "symbolic_execution": lambda: self._run_symbolic_execution(binary_data, ctx),
            "dispatcher_analysis": lambda: self._run_dispatcher_analysis(binary_data, ctx),
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

        for stage_name in cfg.stages:
            handler = stage_handlers.get(stage_name)
            if handler is None:
                logger.warning("Unknown pipeline stage '%s' — skipping", stage_name)
                continue

            # Skip LLM stages if disabled
            if stage_name.startswith("llm_") and not cfg.llm_enabled:
                continue

            try:
                sr = handler()
                stage_results.append(sr)
                ctx.shared_data["pipeline_stages_completed"].append(stage_name)

                if not sr.success and sr.error:
                    errors.append(f"[{stage_name}] {sr.error}")

                # Collect LLM insights separately
                if stage_name.startswith("llm_") and sr.data:
                    llm_insights[stage_name] = sr.data

            except Exception as exc:
                logger.exception("Pipeline stage %s failed", stage_name)
                stage_results.append(StageResult(
                    stage=stage_name,
                    success=False,
                    error=str(exc),
                ))
                errors.append(f"[{stage_name}] {exc}")

        elapsed = time.monotonic() - t0
        any_success = any(sr.success for sr in stage_results) if stage_results else False

        # Cleanup temp directory
        import shutil
        try:
            shutil.rmtree(work_dir, ignore_errors=True)
        except Exception:
            pass

        return PipelineResult(
            success=any_success,
            stages=stage_results,
            shared_data=ctx.shared_data,
            llm_insights=llm_insights,
            total_duration=elapsed,
            errors=errors,
        )

    # -- built-in engine stages --------------------------------------------

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

        except Exception as exc:
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

        except Exception as exc:
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

            max_w = getattr(
                pipeline_config, "max_workers", 4
            ) if hasattr(self, "_pipeline_config") else 4
            # Access from the pipeline run context if stored
            max_w = getattr(self, "_current_max_workers", 4)

            def _exec_one(plugin):
                return plugin.name, plugin.safe_execute(file_path, binary_data, ctx)

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_w) as pool:
                futures = {pool.submit(_exec_one, p): p for p in plugins}
                for future in concurrent.futures.as_completed(futures):
                    try:
                        name, pr = future.result()
                    except Exception as exc:
                        plugin = futures[future]
                        name = plugin.name
                        logger.warning("Plugin %s raised: %s", name, exc)
                        continue
                    plugin_results[name] = pr.to_dict()
                    if pr.success:
                        successes += 1
                        total_confidence += pr.confidence
                        if pr.data:
                            ctx.shared_data.setdefault("plugin_results", {})[name] = pr.data

            elapsed = time.monotonic() - t0
            avg_confidence = total_confidence / successes if successes else 0.0

            stage_data = {
                "plugins_run": len(plugins),
                "successful": successes,
                "failed": len(plugins) - successes,
                "results": plugin_results,
            }

            # Store aggregated stage results in shared_data
            ctx.shared_data[label] = stage_data

            return StageResult(
                stage=label,
                success=successes > 0,
                data=stage_data,
                duration=elapsed,
                plugins_run=len(plugins),
                plugins_succeeded=successes,
            )

        except Exception as exc:
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
        """Detect and catalogue anti-analysis / anti-debug techniques."""
        t0 = time.monotonic()
        try:
            from ..analysis.anti_evasion.environment_normalizer import EnvironmentNormalizer

            normalizer = EnvironmentNormalizer()
            report = normalizer.analyze(binary_data)
            result_data = report.to_dict()

            ctx.shared_data["anti_evasion"] = result_data
            ctx.shared_data["evasion_risk"] = report.risk_score

            return StageResult(
                stage="anti_evasion",
                success=True,
                data=result_data,
                duration=time.monotonic() - t0,
            )
        except Exception as exc:
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
        except Exception as exc:
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

        When a VM protector is detected, uses :class:`VMTaintTracker` which
        provides virtual register mapping and handler boundary detection.
        Otherwise falls back to the generic :class:`TaintAnalyzer`.
        """
        t0 = time.monotonic()
        try:
            from ..analysis.taint_tracking.analyzer import TaintAnalyzer
            from ..analysis.taint_tracking.vm_taint_tracker import VMTaintTracker
            from ..analysis.symbolic_execution.lifter import InstructionLifter

            # Determine entry point from vm_discovery
            vm_info = ctx.shared_data.get("vm_discovery", {})
            dispatchers = vm_info.get("dispatchers", [])
            entry = dispatchers[0] if dispatchers else 0

            # Lift instructions from binary data
            lifter = InstructionLifter()
            instructions = lifter.lift(binary_data, base_address=entry)

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

            return StageResult(
                stage="taint_analysis",
                success=True,
                data=result,
                duration=time.monotonic() - t0,
            )
        except Exception as exc:
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
        """Run symbolic execution to analyse VM handlers."""
        t0 = time.monotonic()
        try:
            from ..analysis.symbolic_execution.executor import SymbolicExecutor

            # Use dispatcher address from vm_discovery if available
            vm_info = ctx.shared_data.get("vm_discovery", {})
            dispatcher_addrs = vm_info.get("dispatcher_addresses", [])
            entry = dispatcher_addrs[0] if dispatcher_addrs else 0

            executor = SymbolicExecutor()
            result = executor.analyze(binary_data, entry_point=entry)

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

            ctx.shared_data["symbolic_execution"] = result_data

            return StageResult(
                stage="symbolic_execution",
                success=True,
                data=result_data,
                duration=time.monotonic() - t0,
            )
        except Exception as exc:
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
        except Exception as exc:
            logger.exception("Dispatcher analysis stage failed")
            return StageResult(
                stage="dispatcher_analysis",
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    # -- LLM stages --------------------------------------------------------

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

        except Exception as exc:
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

        except Exception as exc:
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
