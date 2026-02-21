"""
VMDragonSlayer Orchestrator
===========================

Central coordination point that dispatches analysis requests to local engines
(pattern analysis, VM discovery) **and** to the Metroplex plugin gateway
(stage-4 dynamic analysis, stage-5 enrichment, AV scanners …).

The design mirrors the Metroplex gateway fan-out pattern
(``repos/gateway/main.go``): the orchestrator sends the sample to every
relevant plugin in parallel, waits for results with per-plugin timeouts,
then aggregates everything into a single ``AnalysisResult``.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from .config import get_config
from .exceptions import (
    AnalysisError,
    AnalysisTimeoutError,
    ConfigurationError,
    InvalidDataError,
)
from ..utils.metrics import AnalysisMetrics

logger = logging.getLogger(__name__)

# B87: Named exception tuple for engine fault-tolerance handlers.
_ENGINE_ERRORS = (
    AnalysisError, AnalysisTimeoutError, ConfigurationError, InvalidDataError,
    ValueError, TypeError, KeyError, IndexError, RuntimeError, OSError,
)

# ---------------------------------------------------------------------------
# Public enums & data classes (imported by core/__init__.py and api/server.py)
# ---------------------------------------------------------------------------


class AnalysisType(str, Enum):
    """Every analysis mode the framework supports."""

    # Primary engines
    VM_DISCOVERY = "vm_discovery"
    PATTERN_ANALYSIS = "pattern_analysis"
    TAINT_TRACKING = "taint_tracking"
    SYMBOLIC_EXECUTION = "symbolic_execution"

    # Composite / shortcut modes
    HYBRID = "hybrid"                       # vm_discovery + pattern_analysis
    FULL_ANALYSIS = "full_analysis"         # every available engine
    UNIFIED = "unified"                     # alias → full_analysis
    VMPROTECT_DEVIRT = "vmprotect_devirt"   # focused VMProtect devirtualisation

    # Metroplex gateway delegation
    GATEWAY_SCAN = "gateway_scan"           # fan-out through all gateway plugins
    STAGE4_DYNAMIC = "stage4_dynamic"       # angr / triton / qiling / …
    STAGE5_ENRICHMENT = "stage5_enrichment" # similarity / vector_share

    # Specialist
    ML_DETECTION = "ml_detection"
    ANTI_EVASION = "anti_evasion"
    MULTI_ARCH = "multi_arch"
    EXTENDED_PATTERNS = "extended_patterns"
    SECURITY_EXTENSIONS = "security_extensions"
    REALTIME = "realtime"

    # Local plugin stages (run plugins directly, no gateway)
    LOCAL_STATIC = "local_static"
    LOCAL_DYNAMIC = "local_dynamic"
    LOCAL_ENRICHMENT = "local_enrichment"
    LOCAL_REPORTING = "local_reporting"
    LOCAL_ALL = "local_all"

    # Aliases kept for backwards compat with server.py
    VM_DETECTION = "vm_detection"


@dataclass
class FileInfo:
    """Metadata about the binary under analysis."""
    path: Optional[str] = None
    size: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""

    @classmethod
    def from_bytes(cls, data: bytes, path: Optional[str] = None) -> "FileInfo":
        return cls(
            path=path,
            size=len(data),
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
        )


@dataclass
class AnalysisRequest:
    """Immutable description of *what* to analyse and *how*."""
    binary_data: bytes
    analysis_type: AnalysisType = AnalysisType.HYBRID
    options: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    file_info: Optional[FileInfo] = None

    def __post_init__(self) -> None:
        if not self.binary_data:
            raise InvalidDataError("binary_data must not be empty")
        if isinstance(self.analysis_type, str):
            self.analysis_type = AnalysisType(self.analysis_type)
        if self.file_info is None:
            self.file_info = FileInfo.from_bytes(
                self.binary_data,
                path=self.metadata.get("filename"),
            )


@dataclass
class EngineResult:
    """Output from one analysis engine or plugin."""
    engine: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration: float = 0.0
    confidence: float = 0.0


@dataclass
class AnalysisResult:
    """Aggregated result returned to callers."""
    success: bool
    analysis_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    file_info: Dict[str, Any] = field(default_factory=dict)
    analysis_type: str = ""
    results: Dict[str, Any] = field(default_factory=dict)
    engine_results: List[EngineResult] = field(default_factory=list)
    execution_time: float = 0.0
    errors: List[str] = field(default_factory=list)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # asdict() already recursively converted engine_results;
        # no need to re-convert.
        return d


# ---------------------------------------------------------------------------
# Engine registry
# ---------------------------------------------------------------------------

class _EngineRegistry:
    """Lazy-loads analysis engines so we only import what's actually used."""

    def __init__(self) -> None:
        self._pattern_db = None
        self._pattern_recognizer = None
        self._gateway_client = None

    # -- Pattern Analysis (local, always available) -------------------------

    @property
    def pattern_db(self) -> "PatternDatabase":
        """Return the lazily-loaded :class:`PatternDatabase` instance."""
        if self._pattern_db is None:
            from ..analysis.pattern_analysis.database import PatternDatabase
            cfg = get_config()
            db_path = cfg.get("data.patterns_db")
            if db_path and Path(db_path).exists():
                self._pattern_db = PatternDatabase(Path(db_path))
            else:
                # Try default locations relative to project root
                for candidate in [
                    Path(__file__).resolve().parents[2] / "data" / "patterns" / "vmprotect_handlers.json",
                    Path(__file__).resolve().parents[2] / "data" / "patterns" / "themida_patterns.json",
                ]:
                    if candidate.exists():
                        self._pattern_db = PatternDatabase(candidate)
                        break
                if self._pattern_db is None:
                    self._pattern_db = PatternDatabase()
        return self._pattern_db

    @property
    def pattern_recognizer(self) -> "PatternRecognizer":
        """Return the lazily-loaded :class:`PatternRecognizer` instance."""
        if self._pattern_recognizer is None:
            from ..analysis.pattern_analysis.recognizer import PatternRecognizer
            self._pattern_recognizer = PatternRecognizer(self.pattern_db)
        return self._pattern_recognizer

    # -- Metroplex Gateway client -------------------------------------------

    @property
    def gateway_client(self) -> "MetroplexGatewayClient":
        """Return the lazily-created :class:`MetroplexGatewayClient`."""
        if self._gateway_client is None:
            from ..api.client import MetroplexGatewayClient
            cfg = get_config()
            gateway_url = cfg.get(
                "metroplex.gateway_url",
                "https://gateway.plugins.localhost:8443",
            )
            timeout = cfg.get("metroplex.timeout", 120)
            self._gateway_client = MetroplexGatewayClient(
                gateway_url=gateway_url,
                timeout=timeout,
            )
        return self._gateway_client


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

# Maps composite analysis types → the individual engines they expand to.
_COMPOSITE_TYPES: Dict[AnalysisType, List[str]] = {
    AnalysisType.HYBRID: ["pattern_analysis", "vm_discovery"],
    AnalysisType.FULL_ANALYSIS: [
        "pattern_analysis",
        "vm_discovery",
        "local_static",
        "local_dynamic",
        "local_enrichment",
        "local_reporting",
    ],
    AnalysisType.UNIFIED: [
        "pattern_analysis",
        "vm_discovery",
        "local_static",
        "local_dynamic",
        "local_enrichment",
        "local_reporting",
    ],
    AnalysisType.GATEWAY_SCAN: ["gateway_all"],
    AnalysisType.STAGE4_DYNAMIC: ["gateway_stage4"],
    AnalysisType.STAGE5_ENRICHMENT: ["gateway_stage5"],
    AnalysisType.LOCAL_STATIC: ["local_static"],
    AnalysisType.LOCAL_DYNAMIC: ["local_dynamic"],
    AnalysisType.LOCAL_ENRICHMENT: ["local_enrichment"],
    AnalysisType.LOCAL_REPORTING: ["local_reporting"],
    AnalysisType.LOCAL_ALL: [
        "local_static",
        "local_dynamic",
        "local_enrichment",
        "local_reporting",
    ],
}

# Stage-4 plugin names (mirrors defaultPlugins() in gateway/main.go)
STAGE4_PLUGINS = [
    "angr", "assemblyline", "binexport", "blackfyre",
    "capev2", "qiling", "rizin", "strelka", "triton",
]

# Stage-5 plugin names
STAGE5_PLUGINS = ["similarity", "vector_share"]


class Orchestrator:
    """
    Central analysis dispatcher.

    Usage::

        orch = Orchestrator()
        result = orch.analyze_binary(binary_data, AnalysisType.HYBRID)
    """

    def __init__(self, config: Optional[Any] = None) -> None:
        self.config = config or get_config()
        self._engines = _EngineRegistry()
        self._executor = ThreadPoolExecutor(
            max_workers=self.config.get("analysis.max_threads", 4),
        )
        self.metrics = AnalysisMetrics()
        logger.info("Orchestrator initialised")

    # B64: Context-manager protocol ------------------------------------------

    def __enter__(self) -> "Orchestrator":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[override]
        self.shutdown()
        return None

    # B68: Async context manager ---------------------------------------------

    async def __aenter__(self) -> "Orchestrator":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[override]
        self.shutdown()
        return None

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------

    def analyze_binary(
        self,
        binary_data: bytes,
        analysis_type: AnalysisType | str = AnalysisType.HYBRID,
        *,
        options: Dict[str, Any] | None = None,
        metadata: Dict[str, Any] | None = None,
    ) -> AnalysisResult:
        """Synchronous analysis — the main entry point."""
        request = AnalysisRequest(
            binary_data=binary_data,
            analysis_type=AnalysisType(analysis_type) if isinstance(analysis_type, str) else analysis_type,
            options=options or {},
            metadata=metadata or {},
        )
        return self._dispatch(request)

    async def analyze_binary_async(
        self,
        binary_data: bytes,
        analysis_type: AnalysisType | str = AnalysisType.HYBRID,
        *,
        options: Dict[str, Any] | None = None,
        metadata: Dict[str, Any] | None = None,
    ) -> AnalysisResult:
        """Async wrapper that runs the synchronous dispatch in a thread."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self.analyze_binary(
                binary_data, analysis_type, options=options, metadata=metadata,
            ),
        )

    # ------------------------------------------------------------------
    # Dispatch logic
    # ------------------------------------------------------------------

    def _dispatch(self, request: AnalysisRequest) -> AnalysisResult:
        # ------------------------------------------------------------------
        # Pipeline-based analysis types run through AnalysisPipeline which
        # chains stages sequentially with a single shared PluginContext.
        # ------------------------------------------------------------------
        pipeline_types = {
            AnalysisType.FULL_ANALYSIS,
            AnalysisType.UNIFIED,
            AnalysisType.VMPROTECT_DEVIRT,
            AnalysisType.LOCAL_ALL,
        }
        if request.analysis_type in pipeline_types:
            return self._dispatch_pipeline(request)

        # ------------------------------------------------------------------
        # All other analysis types use flat parallel dispatch (fast path for
        # single-engine calls or gateway delegation).
        # ------------------------------------------------------------------
        self.metrics = AnalysisMetrics()  # fresh metrics per analysis
        t0 = time.monotonic()
        engine_names = self._resolve_engines(request.analysis_type)

        futures = {}
        for engine_name in engine_names:
            handler = self._get_engine_handler(engine_name)
            if handler is None:
                continue

            def _run_engine(h=handler, r=request, en=engine_name):
                with self.metrics.phase(en):
                    return h(r)

            fut = self._executor.submit(_run_engine)
            futures[fut] = engine_name

        engine_results: List[EngineResult] = []
        errors: List[str] = []
        timeout = self.config.get("analysis.timeout", 1800)

        try:
            for fut in as_completed(futures, timeout=timeout):
                engine_name = futures[fut]
                try:
                    er: EngineResult = fut.result()
                    engine_results.append(er)
                    if not er.success and er.error:
                        errors.append(f"[{engine_name}] {er.error}")
                except _ENGINE_ERRORS as exc:
                    logger.exception("Engine %s raised an exception", engine_name)
                    engine_results.append(EngineResult(
                        engine=engine_name,
                        success=False,
                        error=str(exc),
                    ))
                    errors.append(f"[{engine_name}] {exc}")
        except TimeoutError:
            # Some futures didn't complete within the timeout — record them.
            for fut, engine_name in futures.items():
                if not fut.done():
                    fut.cancel()
                    engine_results.append(EngineResult(
                        engine=engine_name,
                        success=False,
                        error=f"Engine timed out after {timeout}s",
                    ))
                    errors.append(f"[{engine_name}] timed out after {timeout}s")

        elapsed = time.monotonic() - t0

        # Aggregate
        combined_results: Dict[str, Any] = {}
        confidence_scores: Dict[str, float] = {}
        for er in engine_results:
            combined_results[er.engine] = er.data
            if er.confidence > 0:
                confidence_scores[er.engine] = er.confidence

        overall_success = any(er.success for er in engine_results) if engine_results else False
        self.metrics.finalise()

        return AnalysisResult(
            success=overall_success,
            file_info=asdict(request.file_info) if request.file_info else {},
            analysis_type=request.analysis_type.value,
            results=combined_results,
            engine_results=engine_results,
            execution_time=elapsed,
            errors=errors,
            confidence_scores=confidence_scores,
            metrics=self.metrics.to_dict(),
        )

    # ------------------------------------------------------------------
    # Pipeline-based dispatch (shared context across stages)
    # ------------------------------------------------------------------

    def _dispatch_pipeline(self, request: AnalysisRequest) -> AnalysisResult:
        """
        Route analysis to :class:`AnalysisPipeline` for sequential
        stage execution with a shared :class:`PluginContext`.

        B53: Wraps pipeline execution with a timeout guard derived
        from ``analysis.timeout`` to prevent unbounded runs.
        """
        from .pipeline import (
            AnalysisPipeline,
            PipelineConfig,
            create_full_pipeline,
            create_vmprotect_devirt_pipeline,
            create_quick_scan_pipeline,
        )

        self.metrics = AnalysisMetrics()  # fresh metrics per pipeline run
        t0 = time.monotonic()
        pipeline_timeout = self.config.get("analysis.timeout", 1800)

        # Select pipeline configuration based on analysis type
        llm_enabled = self.config.get("llm.enabled", True)
        if request.analysis_type == AnalysisType.VMPROTECT_DEVIRT:
            pipe, cfg = create_vmprotect_devirt_pipeline(config=self.config)
            cfg.llm_enabled = llm_enabled
        elif request.analysis_type == AnalysisType.LOCAL_ALL:
            pipe = AnalysisPipeline(config=self.config)
            cfg = PipelineConfig(
                stages=["pattern_analysis", "vm_discovery", "static", "dynamic", "enrichment", "reporting"],
                llm_enabled=False,
            )
        else:
            # FULL_ANALYSIS / UNIFIED
            pipe, cfg = create_full_pipeline(config=self.config)
            cfg.llm_enabled = llm_enabled

        # B53: Run the pipeline with timeout guard
        try:
            import concurrent.futures
            with self.metrics.phase("pipeline"):
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(
                        pipe.run,
                        binary_data=request.binary_data,
                        pipeline_config=cfg,
                        metadata=request.metadata,
                    )
                    pipe_result = future.result(timeout=pipeline_timeout)
        except (TimeoutError, concurrent.futures.TimeoutError):
            elapsed = time.monotonic() - t0
            logger.error(
                "Pipeline timed out after %.1fs (limit=%ds)",
                elapsed, pipeline_timeout,
            )
            # B57: Raise AnalysisTimeoutError so callers (API, tests) can
            # handle timeouts specifically instead of inspecting error strings.
            raise AnalysisTimeoutError(
                f"Pipeline timed out after {pipeline_timeout}s",
                error_code="PIPELINE_TIMEOUT",
                details={
                    "elapsed": round(elapsed, 2),
                    "limit_seconds": pipeline_timeout,
                    "analysis_type": request.analysis_type.value,
                },
            )
        except _ENGINE_ERRORS as exc:
            elapsed = time.monotonic() - t0
            logger.exception("Pipeline failed")
            return AnalysisResult(
                success=False,
                file_info=asdict(request.file_info) if request.file_info else {},
                analysis_type=request.analysis_type.value,
                results={},
                engine_results=[],
                execution_time=elapsed,
                errors=[str(exc)],
                confidence_scores={},
            )

        # Convert PipelineResult → AnalysisResult for API compatibility
        engine_results: List[EngineResult] = []
        combined_results: Dict[str, Any] = {}
        confidence_scores: Dict[str, float] = {}
        errors: List[str] = pipe_result.errors[:]

        for sr in pipe_result.stages:
            er = EngineResult(
                engine=sr.stage,
                success=sr.success,
                data=sr.data,
                error=sr.error,
                duration=sr.duration,
            )
            engine_results.append(er)
            combined_results[sr.stage] = sr.data

        # Include shared data and LLM insights in results
        combined_results["_shared_data"] = pipe_result.shared_data
        if pipe_result.llm_insights:
            combined_results["_llm_insights"] = pipe_result.llm_insights

        elapsed = time.monotonic() - t0
        self.metrics.finalise()

        return AnalysisResult(
            success=pipe_result.success,
            file_info=asdict(request.file_info) if request.file_info else {},
            analysis_type=request.analysis_type.value,
            results=combined_results,
            engine_results=engine_results,
            execution_time=elapsed,
            errors=errors,
            confidence_scores=confidence_scores,
            metrics=self.metrics.to_dict(),
        )

    # ------------------------------------------------------------------
    # Engine resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_engines(analysis_type: AnalysisType) -> List[str]:
        """Expand a composite analysis type into individual engine names."""
        if analysis_type in _COMPOSITE_TYPES:
            return list(_COMPOSITE_TYPES[analysis_type])
        # Single-engine types map 1-to-1
        return [analysis_type.value]

    def _get_engine_handler(self, engine_name: str) -> "Optional[Callable[[AnalysisRequest], EngineResult]]":
        """Return a callable ``(AnalysisRequest) → EngineResult`` or *None*."""
        handlers = {
            "pattern_analysis": self._run_pattern_analysis,
            "vm_discovery": self._run_vm_discovery,
            "extended_patterns": self._run_pattern_analysis,
            # Metroplex gateway delegation
            "gateway_all": self._run_gateway_all,
            "gateway_stage4": self._run_gateway_stage4,
            "gateway_stage5": self._run_gateway_stage5,
            # Direct plugin delegation
            "taint_tracking": self._run_gateway_stage4,   # Taint info comes from angr/triton
            "symbolic_execution": self._run_gateway_stage4,
            # Local plugin stages (no gateway required)
            "local_static": self._run_local_static,
            "local_dynamic": self._run_local_dynamic,
            "local_enrichment": self._run_local_enrichment,
            "local_reporting": self._run_local_reporting,
        }
        handler = handlers.get(engine_name)
        if handler is None:
            logger.warning("No handler registered for engine '%s' – skipping", engine_name)
        return handler

    # ------------------------------------------------------------------
    # Local engine runners
    # ------------------------------------------------------------------

    def _run_pattern_analysis(self, request: AnalysisRequest) -> EngineResult:
        """Run the local pattern recogniser against raw bytes.

        ``PatternRecognizer.recognize()`` expects a hex-encoded string, not
        raw ``bytes``.  We convert here so the caller doesn't need to know.
        """
        t0 = time.monotonic()
        try:
            recognizer = self._engines.pattern_recognizer

            # Convert raw bytes → uppercase hex string (e.g. "4D5A90…")
            hex_str = request.binary_data.hex().upper()

            matches = recognizer.recognize(hex_str)
            elapsed = time.monotonic() - t0

            matches_data = []
            total_confidence = 0.0
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
                total_confidence += m.confidence

            avg_confidence = (total_confidence / len(matches)) if matches else 0.0

            return EngineResult(
                engine="pattern_analysis",
                success=True,
                data={
                    "matches": matches_data,
                    "total_matches": len(matches),
                    "patterns_checked": len(recognizer.database),
                    "database_stats": recognizer.database.get_statistics(),
                },
                duration=elapsed,
                confidence=avg_confidence,
            )
        except _ENGINE_ERRORS as exc:
            logger.exception("Pattern analysis failed")
            return EngineResult(
                engine="pattern_analysis",
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _run_vm_discovery(self, request: AnalysisRequest) -> EngineResult:
        """
        VM-presence detection delegated to the canonical VMDetector.

        The detector provides full PE section parsing, entropy analysis,
        watermark scanning, and dispatcher heuristics — all in one place.
        Previously this method duplicated a simpler version inline.
        """
        t0 = time.monotonic()
        try:
            from ..analysis.vm_discovery.detector import VMDetector

            detector = VMDetector()
            result = detector.detect(request.binary_data)

            elapsed = time.monotonic() - t0
            return EngineResult(
                engine="vm_discovery",
                success=True,
                data=result,
                duration=elapsed,
                confidence=result.get("confidence", 0.0),
            )
        except _ENGINE_ERRORS as exc:
            logger.exception("VM discovery failed")
            return EngineResult(
                engine="vm_discovery",
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    # ------------------------------------------------------------------
    # Local plugin runners
    # ------------------------------------------------------------------

    def _run_local_plugins(
        self,
        request: AnalysisRequest,
        stage: int,
        label: str,
    ) -> EngineResult:
        """
        Execute all available local plugins for *stage* against the sample.

        Each plugin runs through ``safe_execute()`` — exceptions are caught so
        one failing plugin doesn't take down the rest.  Results are aggregated
        into a single :class:`EngineResult` whose ``data`` dict maps plugin
        names to their individual ``PluginResult.to_dict()`` output.
        """
        from ..plugins import Stage, PluginContext, get_all_plugins
        from ..plugins._storage import create_storage

        t0 = time.monotonic()
        try:
            plugins = get_all_plugins(stage=stage, available_only=True)
            if not plugins:
                return EngineResult(
                    engine=label,
                    success=True,
                    data={"plugins_run": 0, "note": f"No plugins available for {stage.name}"},
                    duration=time.monotonic() - t0,
                )

            # Build shared context
            storage_type = self.config.get("plugins.storage", "memory")
            storage = create_storage(storage_type, **self.config.get("plugins.storage_options", {}))
            work_dir = tempfile.mkdtemp(prefix="vmds_")
            try:
                ctx = PluginContext(
                    storage=storage,
                    config=dict(self.config._config) if hasattr(self.config, "_config") else {},
                    shared_data={
                        "fileinfo": request.file_info.__dict__ if request.file_info else {},
                    },
                    sample_hash=request.file_info.sha256 if request.file_info else "",
                    work_dir=work_dir,
                )

                file_path = request.metadata.get("filename", "")
                plugin_results: Dict[str, Any] = {}
                total_confidence = 0.0
                successes = 0

                for plugin in plugins:
                    pr = plugin.safe_execute(file_path, request.binary_data, ctx)
                    plugin_results[plugin.name] = pr.to_dict()
                    if pr.success:
                        successes += 1
                        total_confidence += pr.confidence

                elapsed = time.monotonic() - t0
                avg_confidence = total_confidence / successes if successes else 0.0

                return EngineResult(
                    engine=label,
                    success=successes > 0,
                    data={
                        "plugins_run": len(plugins),
                        "successful": successes,
                        "failed": len(plugins) - successes,
                        "results": plugin_results,
                        "shared_data": ctx.shared_data,
                    },
                    duration=elapsed,
                    confidence=round(avg_confidence, 4),
                )
            finally:
                import shutil
                shutil.rmtree(work_dir, ignore_errors=True)
        except _ENGINE_ERRORS as exc:
            logger.exception("Local plugin stage %s failed", label)
            return EngineResult(
                engine=label,
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _run_local_static(self, request: AnalysisRequest) -> EngineResult:
        """Run all Stage-3 (static) local plugins."""
        from ..plugins import Stage
        return self._run_local_plugins(request, Stage.STATIC, "local_static")

    def _run_local_dynamic(self, request: AnalysisRequest) -> EngineResult:
        """Run all Stage-4 (dynamic) local plugins."""
        from ..plugins import Stage
        return self._run_local_plugins(request, Stage.DYNAMIC, "local_dynamic")

    def _run_local_enrichment(self, request: AnalysisRequest) -> EngineResult:
        """Run all Stage-5 (enrichment) local plugins."""
        from ..plugins import Stage
        return self._run_local_plugins(request, Stage.ENRICHMENT, "local_enrichment")

    def _run_local_reporting(self, request: AnalysisRequest) -> EngineResult:
        """Run all Stage-6 (reporting) local plugins."""
        from ..plugins import Stage
        return self._run_local_plugins(request, Stage.REPORTING, "local_reporting")

    # ------------------------------------------------------------------
    # Metroplex Gateway delegation
    # ------------------------------------------------------------------

    def _run_gateway_all(self, request: AnalysisRequest) -> EngineResult:
        """Send sample to the Metroplex gateway for a full fan-out scan."""
        return self._call_gateway(request, plugins=None, stage=None, label="gateway_all")

    def _run_gateway_stage4(self, request: AnalysisRequest) -> EngineResult:
        """Send sample to Stage-4 dynamic-analysis plugins."""
        return self._call_gateway(request, plugins=STAGE4_PLUGINS, stage=4, label="gateway_stage4")

    def _run_gateway_stage5(self, request: AnalysisRequest) -> EngineResult:
        """Send sample to Stage-5 enrichment plugins (similarity, vector_share)."""
        return self._call_gateway(request, plugins=STAGE5_PLUGINS, stage=5, label="gateway_stage5")

    def _call_gateway(
        self,
        request: AnalysisRequest,
        *,
        plugins: Optional[List[str]],
        stage: Optional[int],
        label: str,
    ) -> EngineResult:
        t0 = time.monotonic()
        try:
            client = self._engines.gateway_client
            gw_response = client.scan(
                file_bytes=request.binary_data,
                filename=request.file_info.path or request.file_info.sha256 or "sample.bin",
                plugins=plugins,
                stage=stage,
                timeout=self.config.get("metroplex.timeout", 120),
            )
            elapsed = time.monotonic() - t0

            # ``gw_response`` follows the GatewayResponse JSON contract from
            # gateway/main.go: {id, total_time, plugins_queried, successful,
            # failed, results: [{plugin, status, duration, data, error}]}
            successful = gw_response.get("successful", 0)
            total = gw_response.get("plugins_queried", 0)
            confidence = successful / total if total else 0.0

            return EngineResult(
                engine=label,
                success=successful > 0,
                data=gw_response,
                duration=elapsed,
                confidence=round(confidence, 4),
            )
        except _ENGINE_ERRORS as exc:
            logger.warning("Gateway call (%s) failed: %s", label, exc)
            return EngineResult(
                engine=label,
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    # ------------------------------------------------------------------
    # Introspection helpers (used by server.py StatusResponse)
    # ------------------------------------------------------------------

    @staticmethod
    def get_supported_analysis_types() -> List[str]:
        return [t.value for t in AnalysisType]

    def shutdown(self) -> None:
        self._executor.shutdown(wait=True)
        logger.info("Orchestrator shut down")


# ---------------------------------------------------------------------------
# VMDragonSlayerAPI shim
# ---------------------------------------------------------------------------
# ``server.py`` imports ``from ..core.api import VMDragonSlayerAPI``.
# We keep it as a thin adapter in this module so that ``core/`` has no
# circular-import issues.  The import in server.py can be satisfied by a
# small ``core/api.py`` that re-exports from here — or we can simply
# provide the class here and have ``core/api.py`` re-export it.
# ---------------------------------------------------------------------------

class VMDragonSlayerAPI:
    """
    High-level API façade consumed by the FastAPI server.

    Translates between the HTTP request model and the ``Orchestrator``.
    """

    def __init__(self) -> None:
        self._orchestrator = Orchestrator()

    def shutdown(self) -> None:
        """Release resources held by the orchestrator."""
        self._orchestrator.shutdown()

    def analyze_binary_data(
        self,
        binary_data: bytes,
        analysis_type: str = "hybrid",
        metadata: Dict[str, Any] | None = None,
        **options: Any,
    ) -> Dict[str, Any]:
        result = self._orchestrator.analyze_binary(
            binary_data,
            analysis_type=analysis_type,
            options=options,
            metadata=metadata or {},
        )
        return result.to_dict()

    @staticmethod
    def get_supported_analysis_types() -> List[str]:
        return Orchestrator.get_supported_analysis_types()
