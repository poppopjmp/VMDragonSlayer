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

import concurrent.futures
import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any, TypedDict, cast

if TYPE_CHECKING:
    from dragonslayer.api.storage import StorageBackend

logger = logging.getLogger(__name__)

__all__ = [
    "Stage",
    "PluginResult",
    "PluginContext",
    "Plugin",
    "register_plugin",
    "get_plugin",
    "list_plugins",
    "get_all_plugins",
    "validate_plugin_dependencies",
    "sort_plugins_by_deps",
]


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


class PluginResultDict(TypedDict):
    """Serialised shape of :meth:`PluginResult.to_dict`."""

    plugin: str
    success: bool
    data: dict[str, Any]
    error: str | None
    duration: float
    confidence: float


@dataclass
class PluginResult:
    """Uniform output envelope for every plugin.

    Attributes:
        plugin: Name of the plugin that produced this result.
        success: Whether the plugin completed without errors.
        data: Arbitrary output payload (JSON-serialisable).
        error: Error message if the plugin failed, else ``None``.
        duration: Wall-clock seconds the plugin took.
        confidence: Confidence score in the range ``[0, 1]``.
    """
    plugin: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration: float = 0.0
    confidence: float = 0.0

    def to_dict(self) -> PluginResultDict:
        return cast("PluginResultDict", asdict(self))


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
    storage: StorageBackend | None = None
    config: dict[str, Any] = field(default_factory=dict)
    shared_data: dict[str, Any] = field(default_factory=dict)
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

    def update_shared(self, mapping: dict[str, Any]) -> None:
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

    Dependency tracking
    -------------------
    ``depends_on`` — set of plugin **names** that must run before this
    plugin (within the same stage).  ``provides`` — set of
    ``shared_data`` **keys** this plugin writes, enabling downstream
    dependency validation.
    """

    name: str = ""
    stage: Stage = Stage.STATIC
    description: str = ""
    version: str = "0.0.0"

    #: Names of plugins this plugin depends on (intra-stage ordering).
    depends_on: set[str]
    #: ``shared_data`` keys this plugin provides to downstream plugins.
    provides: set[str]

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Ensure each subclass gets its own copy of mutable defaults
        # to avoid the classic shared-mutable-class-attribute bug.
        if "depends_on" not in cls.__dict__:
            cls.depends_on = set()
        if "provides" not in cls.__dict__:
            cls.provides = set()

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
        data: dict[str, Any] | None = None,
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
        """Run :meth:`execute` in a managed thread pool with a hard timeout."""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix=f"plugin-{self.name}") as pool:
            future = pool.submit(self.execute, file_path, file_data, context)
            try:
                result = future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                elapsed = time.monotonic() - t0
                logger.warning(
                    "Plugin %s timed out after %.1f s", self.name, timeout,
                )
                return self._make_result(
                    success=False,
                    error=f"Plugin timed out after {timeout}s",
                    duration=elapsed,
                )
            except Exception as exc:
                elapsed = time.monotonic() - t0
                logger.exception("Plugin %s failed", self.name, exc_info=exc)
                return self._make_result(
                    success=False,
                    error=str(exc),
                    duration=elapsed,
                )
            else:
                return result


# ---------------------------------------------------------------------------
# Plugin registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, type[Plugin]] = {}


def register_plugin(cls: type[Plugin]) -> type[Plugin]:
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
    _ensure_discovered()
    cls = _REGISTRY.get(name)
    if cls is None:
        return None
    if not cls.available():
        return None
    return cls()


def list_plugins(stage: Stage | None = None, available_only: bool = True) -> list[str]:
    """Return names of registered plugins, optionally filtered by stage."""
    _ensure_discovered()
    out: list[str] = []
    for name, cls in sorted(_REGISTRY.items()):
        if stage is not None and cls.stage != stage:
            continue
        if available_only and not cls.available():
            continue
        out.append(name)
    return out


def get_all_plugins(stage: Stage | None = None, available_only: bool = True) -> list[Plugin]:
    """Return instantiated plugin objects."""
    plugins: list[Plugin] = []
    for name in list_plugins(stage=stage, available_only=available_only):
        p = get_plugin(name)
        if p is not None:
            plugins.append(p)
    return plugins


# ---------------------------------------------------------------------------
# Dependency validation & topological sort
# ---------------------------------------------------------------------------


def validate_plugin_dependencies(
    stage: Stage | None = None,
) -> dict[str, list[str]]:
    """Check that every plugin's ``depends_on`` names are satisfiable.

    Returns a mapping of ``{plugin_name: [missing_dep_names]}`` for
    plugins whose declared dependencies are not present in the registry
    (or not available).  An empty dict means all dependencies are met.
    """
    _ensure_discovered()
    available_names = set(list_plugins(stage=stage, available_only=True))
    problems: dict[str, list[str]] = {}
    for name in available_names:
        cls = _REGISTRY.get(name)
        if cls is None:
            continue
        missing = [d for d in cls.depends_on if d not in available_names]
        if missing:
            problems[name] = missing
    return problems


def sort_plugins_by_deps(plugins: list[Plugin]) -> list[Plugin]:
    """Topological sort of *plugins* respecting ``depends_on``.

    Plugins with no dependencies come first.  If a cycle is detected
    the original order is returned unchanged with a warning logged.
    """
    if len(plugins) <= 1:
        return list(plugins)

    name_to_plugin = {p.name: p for p in plugins}
    available = set(name_to_plugin.keys())

    # Kahn's algorithm
    in_degree: dict[str, int] = {p.name: 0 for p in plugins}
    dependents: dict[str, list[str]] = {p.name: [] for p in plugins}
    for p in plugins:
        for dep in p.depends_on:
            if dep in available:
                in_degree[p.name] += 1
                dependents[dep].append(p.name)

    queue: list[str] = [n for n, d in in_degree.items() if d == 0]
    ordered: list[str] = []
    while queue:
        # Stable sort: pick alphabetically first among zero-in-degree
        queue.sort()
        node = queue.pop(0)
        ordered.append(node)
        for dep_name in dependents[node]:
            in_degree[dep_name] -= 1
            if in_degree[dep_name] == 0:
                queue.append(dep_name)

    if len(ordered) != len(plugins):
        logger.warning(
            "Cycle detected in plugin dependencies — running in original order"
        )
        return list(plugins)

    return [name_to_plugin[n] for n in ordered]


# ---------------------------------------------------------------------------
# Auto-discover plugins from sub-packages on import
# ---------------------------------------------------------------------------

def _auto_discover() -> None:
    """Best-effort import of all plugin modules in sub-packages.

    Called lazily on the first :func:`get_plugin` / :func:`list_plugins`
    invocation, **not** at import time.  This avoids import-time side
    effects and makes the discovery step testable.
    """
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
        except (ImportError, SyntaxError, AttributeError, RuntimeError, OSError):  # noqa: BLE001
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
            except (SyntaxError, AttributeError, RuntimeError, TypeError,
                    ValueError, OSError):  # noqa: BLE001
                # Real bug — surface at WARNING
                logger.warning(
                    "Unexpected error importing plugins.%s.%s",
                    subpkg, mod_info.name,
                    exc_info=True,
                )


_discovered = False
_discovery_lock = threading.Lock()


def _ensure_discovered() -> None:
    """Run :func:`_auto_discover` once on first access (thread-safe)."""
    global _discovered  # noqa: PLW0603
    if _discovered:          # fast path — no lock needed
        return
    with _discovery_lock:
        if not _discovered:  # double-checked locking
            _auto_discover()
            _discovered = True
