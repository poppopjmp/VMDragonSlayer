"""
ML Feature Pipeline
====================

Feature extraction and vector construction for the ML classification
pipeline.  :class:`FeatureExtractor` converts raw binary analysis
artefacts (disassembly, CFG stats, taint data) into numeric feature
vectors consumed by :class:`~dragonslayer.ml.model.BaseModel`.

:class:`HandlerFeatureExtractor` is a concrete extractor for VM handler
classification — it takes a handler dict (from handler_semantics or
trace ingestion) and produces a fixed-length numeric feature vector.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

import logging

logger = logging.getLogger(__name__)


@dataclass
class FeatureVector:
    """Numeric feature vector with metadata."""

    values: List[float] = field(default_factory=list)
    feature_names: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def dimension(self) -> int:
        return len(self.values)


class FeatureExtractor:
    """Convert analysis artefacts into :class:`FeatureVector` instances.

    Subclass or configure with a *feature_spec* dict that maps analysis
    keys to extraction callables.
    """

    def __init__(self, feature_spec: Dict[str, Any] | None = None) -> None:
        self._spec = feature_spec or {}

    def extract(self, analysis_data: Dict[str, Any]) -> FeatureVector:
        """Build a feature vector from *analysis_data*.

        Raises :exc:`NotImplementedError` until a concrete feature spec
        is supplied.
        """
        if not self._spec:
            raise NotImplementedError(
                "FeatureExtractor requires a feature_spec mapping to "
                "convert analysis data into numeric features"
            )
        values: List[float] = []
        names: List[str] = []
        for key, extractor_fn in self._spec.items():
            val = extractor_fn(analysis_data)
            if isinstance(val, (list, tuple)):
                values.extend(float(v) for v in val)
                names.extend(f"{key}_{i}" for i in range(len(val)))
            else:
                values.append(float(val))
                names.append(key)
        return FeatureVector(values=values, feature_names=names)


# ---------------------------------------------------------------------------
# Concrete handler feature extractor
# ---------------------------------------------------------------------------

# Mnemonic groups for feature counting.
_ARITH_MNEMS = {"add", "sub", "adc", "sbb", "inc", "dec", "neg", "imul", "mul", "idiv", "div"}
_LOGIC_MNEMS = {"and", "or", "xor", "not", "shl", "shr", "sar", "rol", "ror", "bt", "bsf", "bsr"}
_STACK_MNEMS = {"push", "pop", "pushf", "popf", "pusha", "popa"}
_MEM_MNEMS = {"mov", "movzx", "movsx", "movsxd", "lea", "xchg", "bswap", "cmova", "cmovb",
              "cmove", "cmovg", "cmovl", "cmovne", "cmovge", "cmovle", "cmovae", "cmovbe"}
_BRANCH_MNEMS = {"jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae",
                 "jb", "jbe", "call", "ret", "loop", "loope", "loopne", "jcxz", "jecxz"}
_NOP_MNEMS = {"nop", "fnop", "pause", "ud2"}

HANDLER_FEATURE_NAMES: List[str] = [
    "instruction_count",
    "unique_mnemonic_count",
    "arith_ratio",
    "logic_ratio",
    "stack_ratio",
    "mem_ratio",
    "branch_ratio",
    "nop_ratio",
    "read_count",
    "write_count",
    "has_memory_read",
    "has_memory_write",
    "has_indirect_branch",
    "max_operand_width",
    "block_count",
]


def extract_handler_features(handler: Dict[str, Any]) -> FeatureVector:
    """Extract a :class:`FeatureVector` from a handler dict.

    The input should at minimum contain ``instructions`` (list of
    dicts with ``mnemonic`` keys) or ``mnemonics`` (list of str).
    Additional keys: ``reads``, ``writes``, ``block_count``,
    ``operand_width``.
    """
    mnemonics: List[str] = handler.get("mnemonics", [])
    if not mnemonics:
        for insn in handler.get("instructions", []):
            m = insn.get("mnemonic", "")
            if m:
                mnemonics.append(m.lower())

    n = max(len(mnemonics), 1)
    unique = len(set(mnemonics))

    arith = sum(1 for m in mnemonics if m in _ARITH_MNEMS) / n
    logic = sum(1 for m in mnemonics if m in _LOGIC_MNEMS) / n
    stack = sum(1 for m in mnemonics if m in _STACK_MNEMS) / n
    mem = sum(1 for m in mnemonics if m in _MEM_MNEMS) / n
    branch = sum(1 for m in mnemonics if m in _BRANCH_MNEMS) / n
    nop = sum(1 for m in mnemonics if m in _NOP_MNEMS) / n

    reads = handler.get("reads", [])
    writes = handler.get("writes", [])

    has_mem_read = 1.0 if any("[" in str(r) or "(" in str(r) for r in reads) else 0.0
    has_mem_write = 1.0 if any("[" in str(w) or "(" in str(w) for w in writes) else 0.0

    has_indirect = 1.0 if any(
        m == "jmp" and i + 1 < len(mnemonics)
        for i, m in enumerate(mnemonics)
    ) else 0.0

    operand_width = float(handler.get("operand_width", 8))
    block_count = float(handler.get("block_count", 1))

    values = [
        float(len(mnemonics)),
        float(unique),
        arith, logic, stack, mem, branch, nop,
        float(len(reads)),
        float(len(writes)),
        has_mem_read,
        has_mem_write,
        has_indirect,
        operand_width,
        block_count,
    ]

    return FeatureVector(
        values=values,
        feature_names=list(HANDLER_FEATURE_NAMES),
        metadata={"source": "handler"},
    )
