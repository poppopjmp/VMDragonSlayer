"""
Typed Pipeline State
====================

Defines the :class:`PipelineState` dataclass that replaces the untyped
``shared_data: Dict[str, Any]`` dictionary with a structured, validated
state object.  Every key previously scattered across ``shared_data`` is
now a named field with a declared type, a documented producer stage,
and an explicit default.

Stage Dependency DAG
--------------------

The :data:`STAGE_DEPENDENCIES` map declares which stages must complete
*before* each stage can run.  The pipeline validates ordering at startup
and rejects configurations that would produce wrong results.

Usage::

    from dragonslayer.core.pipeline_state import PipelineState, validate_stage_order

    state = PipelineState()
    state.binary_size = len(data)

    # Validate that stages are in a valid topological order
    validate_stage_order(["pattern_analysis", "vm_discovery", "classify"])
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, ClassVar, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Stage dependency graph
# ---------------------------------------------------------------------------

#: Map from stage name → set of stages that must have completed first.
#: A stage *may* run without its soft dependencies (data just won't be
#: there), but **hard** dependencies are enforced.
STAGE_DEPENDENCIES: Dict[str, Set[str]] = {
    # Early stages — no dependencies
    "binary_parse": set(),
    "pattern_analysis": set(),
    "vm_discovery": set(),
    "anti_evasion": set(),

    # Classify needs pattern matches
    "classify": {"pattern_analysis"},

    # Plugin stages — static first, then dynamic, then enrichment
    "static": set(),
    "dynamic": {"anti_evasion"},
    "enrichment": {"static", "dynamic"},

    # Analysis stages — need discovery results
    "taint_analysis": {"vm_discovery"},
    "symbolic_execution": {"vm_discovery"},
    "dispatcher_analysis": {"vm_discovery"},

    # Devirtualize needs almost everything
    "devirtualize": {
        "vm_discovery",
        "anti_evasion",
        "dispatcher_analysis",
    },

    # LLM stages — come after analysis
    "llm_analysis": set(),  # soft deps on everything; works with what's available
    "llm_summary": {"llm_analysis"},

    # Reporting — last
    "reporting": set(),
}


def validate_stage_order(stages: List[str]) -> List[str]:
    """Validate that *stages* respects the dependency DAG.

    Parameters
    ----------
    stages : list[str]
        Ordered list of stage names as configured by the user.

    Returns
    -------
    list[str]
        Warnings for soft dependency violations (stages that would
        benefit from a predecessor but can still run).

    Raises
    ------
    ValueError
        If a hard dependency is violated (stage X requires stage Y
        but Y comes *after* X or is missing entirely).
    """
    completed: set[str] = set()
    warnings: list[str] = []

    for stage in stages:
        deps = STAGE_DEPENDENCIES.get(stage, set())
        missing = deps - completed
        if missing:
            # Check if the missing deps are simply absent (soft) vs misordered (hard)
            present_later = {s for s in stages if s in missing and stages.index(s) > stages.index(stage)}
            absent = missing - set(stages)

            if present_later:
                raise ValueError(
                    f"Stage '{stage}' requires {present_later} to run first, "
                    f"but they appear later in the stage list. "
                    f"Move them before '{stage}'."
                )
            if absent:
                warnings.append(
                    f"Stage '{stage}' benefits from {absent} which are not "
                    f"in the stage list — results may be incomplete."
                )
        completed.add(stage)

    return warnings


# ---------------------------------------------------------------------------
# Typed pipeline state — replaces untyped shared_data dict
# ---------------------------------------------------------------------------

@dataclass
class PipelineState:
    """Structured state shared across all pipeline stages.

    Every field documents:
    - **Type**: exact Python type expected
    - **Producer**: which stage writes this field
    - **Consumers**: which stages read it

    The previous ``shared_data: Dict[str, Any]`` still exists for backward
    compatibility (plugin data, external keys), but pipeline-internal keys
    are migrated to typed fields.
    """

    # ------- Immutable context (set once in run()) -------------------------
    binary_size: int = 0
    """Size of the input binary in bytes.  Set by ``run()``."""

    sha256: str = ""
    """SHA-256 hex digest.  Set by ``run()``."""

    metadata: Dict[str, Any] = field(default_factory=dict)
    """Caller-provided metadata (filename, tags).  Set by ``run()``."""

    pipeline_stages_completed: List[str] = field(default_factory=list)
    """Stages that have finished, in execution order.  Updated by ``run()``."""

    # ------- binary_parse stage -------------------------------------------
    parsed_binary: Any = None
    """Parsed binary object.  Producer: ``binary_parse``."""

    image_base: int = 0
    """PE/ELF image base address.  Producer: ``binary_parse``."""

    entry_point: int = 0
    """Binary entry point address.  Producer: ``binary_parse``."""

    architecture: str = ""
    """Architecture string (``x86``, ``x86_64``, ``arm``, …).  Producer: ``binary_parse``."""

    binary_format: str = ""
    """Format string (``PE``, ``ELF``, ``MachO``).  Producer: ``binary_parse``."""

    sections: List[Dict[str, Any]] = field(default_factory=list)
    """Section headers.  Producer: ``binary_parse``."""

    # ------- pattern_analysis stage ----------------------------------------
    pattern_analysis: Dict[str, Any] = field(default_factory=dict)
    """Full pattern analysis result dict.  Producer: ``pattern_analysis``."""

    pattern_matches: List[Dict[str, Any]] = field(default_factory=list)
    """Individual match records.  Producer: ``pattern_analysis``.
    Consumers: ``classify``, ``llm_analysis``, ``llm_summary``."""

    # ------- vm_discovery stage --------------------------------------------
    vm_discovery: Dict[str, Any] = field(default_factory=dict)
    """Full VM discovery result dict.  Producer: ``vm_discovery``.
    Consumers: ``taint_analysis``, ``symbolic_execution``,
    ``devirtualize``, ``llm_analysis``, ``llm_summary``."""

    vm_detected: bool = False
    """Whether a VM protector was detected.  Producer: ``vm_discovery``."""

    vm_confidence: float = 0.0
    """Detection confidence [0.0, 1.0].  Producer: ``vm_discovery``."""

    # ------- anti_evasion stage --------------------------------------------
    anti_evasion: Dict[str, Any] = field(default_factory=dict)
    """Anti-evasion report dict.  Producer: ``anti_evasion``."""

    evasion_risk: float = 0.0
    """Evasion risk score.  Producer: ``anti_evasion``."""

    runtime_hook_set: Any = None
    """HookSet object for dynamic plugins.  Producer: ``anti_evasion``.
    Consumer: ``_run_plugin_stage`` (dynamic)."""

    # ------- classify stage ------------------------------------------------
    classification: Dict[str, Any] = field(default_factory=dict)
    """Pattern classification result.  Producer: ``classify``."""

    dominant_handler_type: Optional[str] = None
    """Most common handler type.  Producer: ``classify``."""

    vm_complexity: float = 0.0
    """VM complexity score.  Producer: ``classify``."""

    # ------- Plugin stage outputs -----------------------------------------
    #: Plugin results are dynamic and remain in the untyped overflow dict.
    #: The stage label keys ("static", "dynamic", "enrichment") are stored there.

    # ------- taint_analysis stage ------------------------------------------
    taint_results: Dict[str, Any] = field(default_factory=dict)
    """Taint analysis result.  Producer: ``taint_analysis``."""

    # ------- symbolic_execution stage --------------------------------------
    symbolic_execution: Dict[str, Any] = field(default_factory=dict)
    """Symbolic execution result.  Producer: ``symbolic_execution``."""

    _triton_path_constraints: List[Any] = field(default_factory=list)
    """Triton path constraints for seeding Z3.  Internal."""

    # ------- dispatcher_analysis stage -------------------------------------
    dispatcher_analysis: Dict[str, Any] = field(default_factory=dict)
    """Dispatcher analysis result.  Producer: ``dispatcher_analysis``."""

    handler_table: List[Dict[str, Any]] = field(default_factory=list)
    """Decoded handler table.  Producer: ``dispatcher_analysis``."""

    # ------- devirtualize stage --------------------------------------------
    detected_protector: str = ""
    """Identified protector name.  Producer: ``devirtualize``."""

    dispatcher_match: Dict[str, Any] = field(default_factory=dict)
    """Dispatcher match details.  Producer: ``devirtualize``."""

    vmprotect_dispatcher: Dict[str, Any] = field(default_factory=dict)
    """VMProtect-specific dispatcher data.  Producer: ``devirtualize``."""

    bytecode_decryptor: Dict[str, Any] = field(default_factory=dict)
    """Bytecode decryptor config/result.  Producer: ``devirtualize``."""

    decrypted_handler_table: Dict[str, Any] = field(default_factory=dict)
    """Decrypted handler table.  Producer: ``devirtualize``."""

    handler_extraction: Dict[str, Any] = field(default_factory=dict)
    """Handler extraction result.  Producer: ``devirtualize``."""

    vm_context_layout: Dict[str, Any] = field(default_factory=dict)
    """VM context register layout.  Producer: ``devirtualize``."""

    vm_entry_points: Dict[str, Any] = field(default_factory=dict)
    """VM entry point detection.  Producer: ``devirtualize``."""

    handler_clustering: Dict[str, Any] = field(default_factory=dict)
    """Handler clustering result.  Producer: ``devirtualize``."""

    handler_cfg: Dict[str, Any] = field(default_factory=dict)
    """Handler CFG result.  Producer: ``devirtualize``."""

    static_handler_cfg: Dict[str, Any] = field(default_factory=dict)
    """Static handler CFG overlay.  Producer: ``devirtualize``."""

    devirt_boundaries: List[Dict[str, Any]] = field(default_factory=list)
    """Final devirtualised handler boundaries.  Producer: ``devirtualize``."""

    # ------- LLM stages ---------------------------------------------------
    llm_analysis: Dict[str, Any] = field(default_factory=dict)
    """LLM analysis result.  Producer: ``llm_analysis``."""

    llm_summary: Dict[str, Any] = field(default_factory=dict)
    """LLM summary result.  Producer: ``llm_summary``."""

    # ------- Overflow for plugins / external data -------------------------
    _overflow: Dict[str, Any] = field(default_factory=dict)
    """Backward-compatible dict for plugin data, dynamic keys, and
    any data not yet migrated to typed fields."""

    _FIELD_NAMES: ClassVar[frozenset] = frozenset()  # populated by __init_subclass__

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Cache the set of valid field names for fast lookup.
        if hasattr(cls, "__dataclass_fields__"):
            cls._FIELD_NAMES = frozenset(
                f for f in cls.__dataclass_fields__ if not f.startswith("_")
            )

    def __post_init__(self) -> None:
        # For the base class itself (when __init_subclass__ fires before
        # @dataclass populates __dataclass_fields__).
        if not self._FIELD_NAMES and hasattr(self, "__dataclass_fields__"):
            type(self)._FIELD_NAMES = frozenset(
                f for f in self.__dataclass_fields__ if not f.startswith("_")
            )

    # ------------------------------------------------------------------
    # Dict-compatible interface for backward compatibility
    # ------------------------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        """Allow ``state["key"]`` access for backward compatibility."""
        if key in self._FIELD_NAMES:
            return getattr(self, key)
        return self._overflow[key]

    def __setitem__(self, key: str, value: Any) -> None:
        """Allow ``state["key"] = val`` for backward compatibility."""
        if key in self._FIELD_NAMES:
            setattr(self, key, value)
        else:
            self._overflow[key] = value

    def __contains__(self, key: str) -> bool:
        return key in self._FIELD_NAMES or key in self._overflow

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-like ``.get()`` — returns *default* only when the key is
        absent, matching ``dict.get`` semantics exactly."""
        if key in self._FIELD_NAMES:
            return getattr(self, key)
        return self._overflow.get(key, default)

    def setdefault(self, key: str, default: Any) -> Any:
        """Dict-like ``.setdefault()`` — only assigns *default* when the
        field value is ``None`` (the unset sentinel)."""
        if key in self._FIELD_NAMES:
            val = getattr(self, key)
            if val is None:
                setattr(self, key, default)
                return default
            return val
        return self._overflow.setdefault(key, default)

    def update(self, mapping: Dict[str, Any]) -> None:
        """Dict-like ``.update()`` for backward compatibility."""
        for k, v in mapping.items():
            self[k] = v

    def items(self) -> list:
        """Iterate over all state as (key, value) pairs."""
        pairs = []
        for f in self.__dataclass_fields__:
            if f.startswith("_"):
                continue
            pairs.append((f, getattr(self, f)))
        for k, v in self._overflow.items():
            pairs.append((k, v))
        return pairs

    def keys(self) -> list:
        """Return all known keys."""
        keys = [f for f in self.__dataclass_fields__ if not f.startswith("_")]
        keys.extend(self._overflow.keys())
        return keys

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a flat dictionary (for JSON / PipelineResult)."""
        d: Dict[str, Any] = {}
        for f in self.__dataclass_fields__:
            if f.startswith("_"):
                continue
            val = getattr(self, f)
            # Skip unpicklable objects
            if hasattr(val, "__dict__") and not isinstance(val, (dict, list, str, int, float, bool)):
                try:
                    d[f] = str(val)
                except Exception:
                    d[f] = "<unpicklable>"
            else:
                d[f] = val
        d.update(self._overflow)
        return d
