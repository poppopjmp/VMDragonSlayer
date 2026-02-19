"""
VMDragonSlayer Plugin Framework
===============================

Self-contained plugin system ported from the Metroplex containerised
pipeline.  Each plugin implements the :class:`Plugin` ABC and is
registered via :func:`register_plugin` / discovered with
:func:`get_plugin` and :func:`list_plugins`.

Key concepts
------------
* **PluginContext** — carries storage backends, config, and cross-plugin
  data so plugins can share results without hard-coding Elasticsearch.
* **PluginResult** — uniform output envelope (success, data, errors,
  duration, confidence).
* **StorageBackend** — swappable persistence (Elasticsearch,
  local-file, in-memory) injected through the context.

Stages mirror the Metroplex pipeline:

    1  Identification  (fileinfo, packer-detector)
    3  Static analysis (PE/ELF/Mach-O analysers, strelka, strings)
    4  Dynamic analysis (angr, triton, qiling, blackfyre, binexport)
    5  Enrichment      (similarity, function similarity, vector share)
    6  Reporting       (markdown reporter, network graph)
"""

from __future__ import annotations

import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any, Dict, List, Optional, Type

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


class Stage(IntEnum):
    """Pipeline stages (matching Metroplex numbering)."""
    IDENTIFICATION = 1
    TRIAGE = 2
    STATIC = 3
    DYNAMIC = 4
    ENRICHMENT = 5
    REPORTING = 6


@dataclass
class PluginResult:
    """Uniform output envelope for every plugin."""
    plugin: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration: float = 0.0
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PluginContext:
    """
    Shared context passed to every plugin invocation.

    Attributes
    ----------
    storage : StorageBackend | None
        Persistence layer for cross-plugin data sharing.
    config : dict
        Merged configuration from ``vmdragonslayer.yml`` + env overrides.
    shared_data : dict
        In-memory scratchpad populated by earlier plugins in the same
        pipeline run (e.g. qiling trace used by angr/triton).
    sample_hash : str
        SHA-256 (or other canonical ID) of the sample under analysis.
    work_dir : str
        Writable directory for temporary artefacts.
    """
    storage: Any = None          # StorageBackend — typed as Any to avoid circular import
    config: Dict[str, Any] = field(default_factory=dict)
    shared_data: Dict[str, Any] = field(default_factory=dict)
    sample_hash: str = ""
    work_dir: str = ""

    def __post_init__(self) -> None:
        self._lock = threading.Lock()

    def set_shared(self, key: str, value: Any) -> None:
        """Thread-safe write to ``shared_data``."""
        with self._lock:
            self.shared_data[key] = value

    def get_shared(self, key: str, default: Any = None) -> Any:
        """Thread-safe read from ``shared_data``."""
        with self._lock:
            return self.shared_data.get(key, default)

    def update_shared(self, mapping: Dict[str, Any]) -> None:
        """Thread-safe bulk update of ``shared_data``."""
        with self._lock:
            self.shared_data.update(mapping)


# ---------------------------------------------------------------------------
# Plugin base class
# ---------------------------------------------------------------------------


class Plugin(ABC):
    """
    Abstract base for every analysis plugin.

    Subclasses *must* set ``name`` and ``stage`` as class attributes and
    implement :meth:`execute`.  Optionally override :meth:`available` to
    gate on heavy optional dependencies (angr, triton, …).
    """

    name: str = ""
    stage: Stage = Stage.STATIC
    description: str = ""

    @abstractmethod
    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        """Run the plugin on *file_data* and return a :class:`PluginResult`."""
        ...

    @classmethod
    def available(cls) -> bool:
        """Return ``True`` if all heavy dependencies are importable."""
        return True

    def _make_result(
        self,
        success: bool,
        data: Dict[str, Any] | None = None,
        error: str | None = None,
        duration: float = 0.0,
        confidence: float = 0.0,
    ) -> PluginResult:
        """Convenience factory."""
        return PluginResult(
            plugin=self.name,
            success=success,
            data=data or {},
            error=error,
            duration=duration,
            confidence=confidence,
        )

    #: Per-plugin timeout in seconds (0 = no timeout)
    timeout: float = 0

    def safe_execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        """Wraps :meth:`execute` with timing, timeout, and exception guard.

        If ``self.timeout`` is > 0 the plugin is run in a daemon thread
        and aborted if it exceeds the configured duration.
        """
        t0 = time.monotonic()

        effective_timeout = self.timeout or context.config.get(
            f"plugins.{self.name}.timeout", 0
        )

        if effective_timeout and effective_timeout > 0:
            return self._execute_with_timeout(
                file_path, file_data, context, effective_timeout, t0,
            )

        try:
            result = self.execute(file_path, file_data, context)
            if result.duration == 0.0:
                result.duration = time.monotonic() - t0
            return result
        except Exception as exc:
            logger.exception("Plugin %s failed", self.name)
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )

    def _execute_with_timeout(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
        timeout: float,
        t0: float,
    ) -> PluginResult:
        """Run :meth:`execute` in a daemon thread with a hard timeout."""
        result_holder: list[PluginResult] = []
        error_holder: list[Exception] = []

        def _worker() -> None:
            try:
                result_holder.append(
                    self.execute(file_path, file_data, context)
                )
            except Exception as exc:
                error_holder.append(exc)

        thread = threading.Thread(target=_worker, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        elapsed = time.monotonic() - t0
        if thread.is_alive():
            logger.warning(
                "Plugin %s timed out after %.1f s", self.name, timeout,
            )
            return self._make_result(
                success=False,
                error=f"Plugin timed out after {timeout}s",
                duration=elapsed,
            )

        if error_holder:
            logger.exception("Plugin %s failed", self.name, exc_info=error_holder[0])
            return self._make_result(
                success=False,
                error=str(error_holder[0]),
                duration=elapsed,
            )

        if result_holder:
            result = result_holder[0]
            if result.duration == 0.0:
                result.duration = elapsed
            return result

        return self._make_result(
            success=False,
            error="Plugin returned no result",
            duration=elapsed,
        )


# ---------------------------------------------------------------------------
# Plugin registry
# ---------------------------------------------------------------------------

_REGISTRY: Dict[str, Type[Plugin]] = {}


def register_plugin(cls: Type[Plugin]) -> Type[Plugin]:
    """Class decorator: register *cls* in the global plugin registry."""
    if not cls.name:
        raise ValueError(f"{cls.__qualname__} must set a 'name' class attribute")
    if cls.name in _REGISTRY:
        logger.warning(
            "Plugin name '%s' already registered by %s — overwritten by %s",
            cls.name, _REGISTRY[cls.name].__qualname__, cls.__qualname__,
        )
    _REGISTRY[cls.name] = cls
    return cls


def get_plugin(name: str) -> Plugin | None:
    """Instantiate a registered plugin by name, or ``None``."""
    cls = _REGISTRY.get(name)
    if cls is None:
        return None
    if not cls.available():
        return None
    return cls()


def list_plugins(stage: Stage | None = None, available_only: bool = True) -> List[str]:
    """Return names of registered plugins, optionally filtered by stage."""
    out: list[str] = []
    for name, cls in sorted(_REGISTRY.items()):
        if stage is not None and cls.stage != stage:
            continue
        if available_only and not cls.available():
            continue
        out.append(name)
    return out


def get_all_plugins(stage: Stage | None = None, available_only: bool = True) -> List[Plugin]:
    """Return instantiated plugin objects."""
    plugins: list[Plugin] = []
    for name in list_plugins(stage=stage, available_only=available_only):
        p = get_plugin(name)
        if p is not None:
            plugins.append(p)
    return plugins


# ---------------------------------------------------------------------------
# Auto-discover plugins from sub-packages on import
# ---------------------------------------------------------------------------

def _auto_discover() -> None:
    """Best-effort import of all plugin modules in sub-packages."""
    import importlib
    import pkgutil
    from pathlib import Path

    base_dir = Path(__file__).resolve().parent
    for subpkg in ("static", "dynamic", "enrichment", "reporting"):
        pkg_dir = base_dir / subpkg
        if not pkg_dir.is_dir():
            continue
        # First import the sub-package itself
        full_pkg = f"{__package__}.{subpkg}"
        try:
            importlib.import_module(full_pkg)
        except Exception:  # noqa: BLE001
            logger.debug("Could not import plugins.%s", subpkg, exc_info=True)
            continue
        # Then import every .py module inside it
        for mod_info in pkgutil.iter_modules([str(pkg_dir)]):
            try:
                importlib.import_module(f"{full_pkg}.{mod_info.name}")
            except ImportError:
                # Optional dependency missing — expected, debug-level
                logger.debug(
                    "Could not import plugins.%s.%s (missing dep)",
                    subpkg, mod_info.name,
                )
            except Exception:  # noqa: BLE001
                # Real bug — surface at WARNING
                logger.warning(
                    "Unexpected error importing plugins.%s.%s",
                    subpkg, mod_info.name,
                    exc_info=True,
                )


_auto_discover()
