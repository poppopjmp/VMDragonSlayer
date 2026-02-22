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

Extended features (see :func:`extract_extended_features`):

* **Mnemonic bigrams** — capture sequential instruction patterns that
  distinguish handler categories (e.g. ``push→mov`` for stack,
  ``xor→shr`` for logic).
* **Register-effect features** — which general-purpose registers are
  net-read or net-written, normalised across the register file.
* **Operand pattern features** — memory dereference patterns,
  immediate usage, register-only vs. memory-register mix.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

import logging
import re as _re

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
            raise ValueError(
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

# Mnemonic groups for feature counting (frozenset — immutable, hashable constants).
_ARITH_MNEMS = frozenset({"add", "sub", "adc", "sbb", "inc", "dec", "neg", "imul", "mul", "idiv", "div"})
_LOGIC_MNEMS = frozenset({"and", "or", "xor", "not", "shl", "shr", "sar", "rol", "ror", "bt", "bsf", "bsr"})
_STACK_MNEMS = frozenset({"push", "pop", "pushf", "popf", "pusha", "popa"})
_MEM_MNEMS = frozenset({"mov", "movzx", "movsx", "movsxd", "lea", "xchg", "bswap", "cmova", "cmovb",
                        "cmove", "cmovg", "cmovl", "cmovne", "cmovge", "cmovle", "cmovae", "cmovbe"})
_BRANCH_MNEMS = frozenset({"jmp", "je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle", "ja", "jae",
                           "jb", "jbe", "call", "ret", "loop", "loope", "loopne", "jcxz", "jecxz"})
_NOP_MNEMS = frozenset({"nop", "fnop", "pause", "ud2"})
_CMP_MNEMS = frozenset({"cmp", "test"})

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
    "has_cmp_insn",
    "has_test_insn",
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

    has_indirect = 0.0
    instructions = handler.get("instructions", [])
    for insn in instructions:
        m = insn.get("mnemonic", "").lower()
        if m in ("jmp", "call"):
            ops = insn.get("operands", "")
            # Indirect if the operand is a register name or memory dereference,
            # NOT an immediate hex/decimal address.
            if ops and not ops.lstrip().startswith("0") and not ops.lstrip().startswith("-"):
                # B67: use module-level _re instead of inline import
                # Matches register names like rax, eax, r12, etc.
                if _re.match(r"^[a-z][a-z0-9]*$", ops.strip().lower()):
                    has_indirect = 1.0
                    break
                # Matches memory dereference [rax], [rax+8], etc.
                if "[" in ops or "(" in ops:
                    has_indirect = 1.0
                    break
    # Fallback: if no instruction dicts, check mnemonic list for jmp existence
    if has_indirect == 0.0 and not instructions:
        if any(m in ("jmp", "call") for m in mnemonics):
            # Can't distinguish direct vs indirect without operand info
            has_indirect = 0.5  # uncertain

    operand_width = float(handler.get("operand_width", 8))
    block_count = float(handler.get("block_count", 1))

    # B80: explicit comparison-instruction features
    has_cmp_insn = 1.0 if any(m == "cmp" for m in mnemonics) else 0.0
    has_test_insn = 1.0 if any(m == "test" for m in mnemonics) else 0.0

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
        has_cmp_insn,
        has_test_insn,
    ]

    return FeatureVector(
        values=values,
        feature_names=list(HANDLER_FEATURE_NAMES),
        metadata={"source": "handler"},
    )


# ═══════════════════════════════════════════════════════════════════════════
# Extended features — n-grams, register effects, operand patterns
# ═══════════════════════════════════════════════════════════════════════════

from collections import Counter as _Counter

# -- Mnemonic bigrams -------------------------------------------------------
# The top-25 mnemonic bigrams that empirically distinguish VMProtect handler
# categories.  We compute a fixed-length vector of bigram frequencies.

VMPROTECT_BIGRAMS: List[tuple[str, str]] = [
    # Arithmetic
    ("mov", "add"),
    ("add", "mov"),
    ("mov", "sub"),
    ("sub", "mov"),
    ("mov", "imul"),
    ("mov", "neg"),
    # Logic
    ("mov", "xor"),
    ("xor", "mov"),
    ("mov", "and"),
    ("and", "mov"),
    ("mov", "or"),
    ("mov", "shl"),
    ("shl", "or"),
    ("xor", "shr"),
    ("mov", "not"),
    # Stack
    ("push", "mov"),
    ("mov", "pop"),
    ("push", "push"),
    ("pop", "pop"),
    # Load/Store
    ("mov", "mov"),
    ("movzx", "mov"),
    ("mov", "movzx"),
    # Branch
    ("cmp", "jne"),
    ("test", "je"),
    ("cmp", "jmp"),
]

_BIGRAM_INDEX: Dict[tuple[str, str], int] = {
    bg: i for i, bg in enumerate(VMPROTECT_BIGRAMS)
}

# General-purpose register names (x86-64) for register-effect features.
_GP_REGS_64: List[str] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]


def extract_bigram_features(mnemonics: List[str]) -> List[float]:
    """Compute normalised bigram frequency vector for *mnemonics*.

    Returns a float list of length ``len(VMPROTECT_BIGRAMS)`` where each
    element is the fraction of consecutive mnemonic pairs that match the
    corresponding bigram.
    """
    n_pairs = max(len(mnemonics) - 1, 1)
    counts = [0] * len(VMPROTECT_BIGRAMS)
    for i in range(len(mnemonics) - 1):
        pair = (mnemonics[i], mnemonics[i + 1])
        idx = _BIGRAM_INDEX.get(pair)
        if idx is not None:
            counts[idx] += 1
    return [c / n_pairs for c in counts]


# -- B56: Mnemonic trigrams --------------------------------------------------

VMPROTECT_TRIGRAMS: List[tuple[str, str, str]] = [
    # Arithmetic handler patterns
    ("mov", "add", "mov"),
    ("mov", "sub", "mov"),
    ("mov", "imul", "mov"),
    ("mov", "neg", "add"),
    # Logic handler patterns
    ("mov", "xor", "mov"),
    ("mov", "and", "mov"),
    ("mov", "or", "mov"),
    ("mov", "shl", "or"),
    ("xor", "shr", "mov"),
    ("mov", "not", "mov"),
    # Stack manipulation
    ("push", "push", "mov"),
    ("mov", "pop", "pop"),
    ("push", "mov", "mov"),
    # Load-store chains
    ("mov", "mov", "mov"),
    ("movzx", "mov", "mov"),
    # Dispatch patterns
    ("cmp", "jne", "mov"),
    ("add", "jmp", "mov"),
    ("test", "je", "jmp"),
    # Key-transform patterns
    ("xor", "rol", "xor"),
    ("xor", "add", "xor"),
]

_TRIGRAM_INDEX: Dict[tuple[str, str, str], int] = {
    tg: i for i, tg in enumerate(VMPROTECT_TRIGRAMS)
}


def extract_trigram_features(mnemonics: List[str]) -> List[float]:
    """Compute normalised trigram frequency vector for *mnemonics*.

    Returns a float list of length ``len(VMPROTECT_TRIGRAMS)``.
    """
    n_triples = max(len(mnemonics) - 2, 1)
    counts = [0] * len(VMPROTECT_TRIGRAMS)
    for i in range(len(mnemonics) - 2):
        triple = (mnemonics[i], mnemonics[i + 1], mnemonics[i + 2])
        idx = _TRIGRAM_INDEX.get(triple)
        if idx is not None:
            counts[idx] += 1
    return [c / n_triples for c in counts]


# -- B56: Opcode frequency histogram ----------------------------------------

OPCODE_VOCAB: List[str] = [
    "mov", "push", "pop", "add", "sub", "xor", "and", "or",
    "shl", "shr", "sar", "not", "neg", "imul", "lea", "test",
    "cmp", "jmp", "jne", "je", "jz", "jnz", "call", "ret",
    "movzx", "movsx", "nop", "rol", "ror", "bswap", "inc", "dec",
]


def extract_opcode_histogram(mnemonics: List[str]) -> List[float]:
    """Compute normalised per-opcode frequency histogram.

    Returns a float list of length ``len(OPCODE_VOCAB)`` — each element
    is the fraction of instructions that use that opcode.
    """
    total = max(len(mnemonics), 1)
    freq: Dict[str, int] = {}
    for m in mnemonics:
        freq[m] = freq.get(m, 0) + 1
    return [freq.get(op, 0) / total for op in OPCODE_VOCAB]


def extract_register_effects(handler: Dict[str, Any]) -> List[float]:
    """Extract per-register read/write indicators (32 floats).

    For each of the 16 GP registers, produces two values:
    ``(read_indicator, write_indicator)`` in {0.0, 1.0}.

    Sources (checked in order):
    1. ``handler["reg_reads"]`` / ``handler["reg_writes"]`` -- explicit sets.
    2. ``handler["instructions"]`` -- parsed from operand strings.
    3. All zeros if no information available.
    """
    reg_reads: set[str] = set()
    reg_writes: set[str] = set()

    # Source 1: explicit
    if "reg_reads" in handler:
        reg_reads = {r.lower() for r in handler["reg_reads"]}
    if "reg_writes" in handler:
        reg_writes = {r.lower() for r in handler["reg_writes"]}

    # Source 2: infer from instructions
    if not reg_reads and not reg_writes:
        for insn in handler.get("instructions", []):
            ops_raw = insn.get("operands", "")
            if isinstance(ops_raw, str):
                ops = [o.strip().lower() for o in ops_raw.split(",")]
            elif isinstance(ops_raw, (list, tuple)):
                ops = [str(o).strip().lower() for o in ops_raw]
            else:
                continue
            mnem = insn.get("mnemonic", "").lower()
            for i, op in enumerate(ops):
                regs_found = _re.findall(
                    r'\b(r(?:ax|bx|cx|dx|si|di|bp|sp|[89]|1[0-5]))\b', op
                )
                for r in regs_found:
                    reg_reads.add(r)
                    if i == 0 and mnem not in ("push", "cmp", "test"):
                        reg_writes.add(r)

    # Build the 32-element vector: [rax_r, rax_w, rbx_r, rbx_w, ...]
    result: List[float] = []
    for reg in _GP_REGS_64:
        result.append(1.0 if reg in reg_reads else 0.0)
        result.append(1.0 if reg in reg_writes else 0.0)
    return result


def extract_operand_pattern_features(handler: Dict[str, Any]) -> List[float]:
    """Extract operand-pattern features (6 floats).

    Returns:
        [imm_ratio, mem_deref_ratio, reg_only_ratio,
         avg_operand_count, has_scale_index, has_rip_relative]
    """
    instructions = handler.get("instructions", [])
    if not instructions:
        return [0.0] * 6

    total_ops = 0
    imm_count = 0
    mem_deref_count = 0
    reg_only_count = 0
    has_scale = 0.0
    has_rip = 0.0

    for insn in instructions:
        ops_raw = insn.get("operands", "")
        if isinstance(ops_raw, str):
            ops = [o.strip() for o in ops_raw.split(",")] if ops_raw else []
        elif isinstance(ops_raw, (list, tuple)):
            ops = [str(o).strip() for o in ops_raw]
        else:
            continue

        for op in ops:
            total_ops += 1
            op_l = op.lower()
            if "[" in op_l:
                mem_deref_count += 1
                if "*" in op_l:
                    has_scale = 1.0
                if "rip" in op_l:
                    has_rip = 1.0
            elif _re.match(r'^-?(?:0x)?[0-9a-f]+$', op_l):
                imm_count += 1
            else:
                reg_only_count += 1

    n = max(total_ops, 1)
    avg_ops = total_ops / max(len(instructions), 1)
    return [
        imm_count / n,
        mem_deref_count / n,
        reg_only_count / n,
        avg_ops,
        has_scale,
        has_rip,
    ]


# -- Extended feature names --------------------------------------------------

BIGRAM_FEATURE_NAMES: List[str] = [
    f"bg_{a}_{b}" for a, b in VMPROTECT_BIGRAMS
]
REGISTER_FEATURE_NAMES: List[str] = []
for _r in _GP_REGS_64:
    REGISTER_FEATURE_NAMES.append(f"reg_read_{_r}")
    REGISTER_FEATURE_NAMES.append(f"reg_write_{_r}")

OPERAND_PATTERN_NAMES: List[str] = [
    "imm_ratio", "mem_deref_ratio", "reg_only_ratio",
    "avg_operand_count", "has_scale_index", "has_rip_relative",
]

# B56: Trigram and opcode histogram feature names
TRIGRAM_FEATURE_NAMES: List[str] = [
    f"tg_{a}_{b}_{c}" for a, b, c in VMPROTECT_TRIGRAMS
]
OPCODE_HIST_NAMES: List[str] = [
    f"freq_{op}" for op in OPCODE_VOCAB
]


# ═══════════════════════════════════════════════════════════════════════════
# CFG-derived features
# ═══════════════════════════════════════════════════════════════════════════

CFG_FEATURE_NAMES: List[str] = [
    "cfg_edge_count",
    "cfg_edge_density",       # edge_count / block_count
    "cfg_loop_count",
    "cfg_max_loop_depth",
    "cfg_has_back_edge",
    "cfg_exit_block_count",
    "cfg_cyclomatic_complexity",  # edges - nodes + 2
]


def extract_cfg_features(handler: Dict[str, Any]) -> List[float]:
    """Extract CFG-derived features from handler data.

    The handler dict may contain ``cfg`` (a dict with ``edge_count``,
    ``loop_headers``, ``back_edges``, ``loop_tree_depth``, ``exit_blocks``)
    populated by :mod:`dragonslayer.analysis.bytecode_cfg`.
    """
    cfg = handler.get("cfg", {})
    if not cfg:
        # Fallback: use scalar block_count if available
        bc = float(handler.get("block_count", 1))
        return [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, max(0.0, 0. - bc + 2.0)]

    edge_count = float(cfg.get("edge_count", 0))
    block_count = float(cfg.get("block_count", handler.get("block_count", 1)))
    edge_density = edge_count / max(block_count, 1.0)

    loop_headers = cfg.get("loop_headers", [])
    loop_count = float(len(loop_headers))
    max_loop_depth = float(cfg.get("loop_tree_depth", cfg.get("max_loop_depth", 0)))

    back_edges = cfg.get("back_edges", [])
    has_back_edge = 1.0 if back_edges else 0.0

    exit_blocks = cfg.get("exit_blocks", [])
    exit_block_count = float(len(exit_blocks))

    # Cyclomatic complexity: M = E - N + 2P (P=1 for single component)
    cyclomatic = max(0.0, edge_count - block_count + 2.0)

    return [
        edge_count,
        edge_density,
        loop_count,
        max_loop_depth,
        has_back_edge,
        exit_block_count,
        cyclomatic,
    ]


# ═══════════════════════════════════════════════════════════════════════════
# Taint-derived features
# ═══════════════════════════════════════════════════════════════════════════

TAINT_FEATURE_NAMES: List[str] = [
    "taint_def_count",
    "taint_use_count",
    "taint_kill_count",
    "taint_net_spread",      # |taint_out| - |taint_in|
    "taint_memory_def_count",
    "taint_memory_use_count",
    "taint_transfer_fan_out",
]


def extract_taint_features(handler: Dict[str, Any]) -> List[float]:
    """Extract taint-analysis features from handler data.

    The handler dict may contain ``taint`` (a dict from
    :class:`HandlerTaintSummary.to_dict()`).
    """
    taint = handler.get("taint", {})
    if not taint:
        return [0.0] * len(TAINT_FEATURE_NAMES)

    defs = taint.get("defs", [])
    uses = taint.get("uses", [])
    kill = taint.get("kill", [])
    taint_in = taint.get("taint_in", [])
    taint_out = taint.get("taint_out", [])
    memory_defs = taint.get("memory_defs", [])
    memory_uses = taint.get("memory_uses", [])
    transfer = taint.get("transfer", [])

    net_spread = float(len(taint_out)) - float(len(taint_in))

    return [
        float(len(defs)),
        float(len(uses)),
        float(len(kill)),
        net_spread,
        float(len(memory_defs)),
        float(len(memory_uses)),
        float(len(transfer)),
    ]


# ═══════════════════════════════════════════════════════════════════════════
# Combined extended feature names (all groups)
# ═══════════════════════════════════════════════════════════════════════════

EXTENDED_FEATURE_NAMES: List[str] = (
    list(HANDLER_FEATURE_NAMES)
    + BIGRAM_FEATURE_NAMES
    + REGISTER_FEATURE_NAMES
    + OPERAND_PATTERN_NAMES
    + TRIGRAM_FEATURE_NAMES
    + OPCODE_HIST_NAMES
    + CFG_FEATURE_NAMES
    + TAINT_FEATURE_NAMES
)


def extract_extended_features(handler: Dict[str, Any]) -> FeatureVector:
    """Extract a rich feature vector for ML training.

    Combines the base 17 handler features with mnemonic bigrams (25),
    register effects (32), operand patterns (6), trigrams (20),
    opcode histogram (32), CFG features (7), and taint features (7)
    for a total of **146 features**.
    """
    base = extract_handler_features(handler)

    # Recover mnemonics for n-gram extraction
    mnemonics: List[str] = handler.get("mnemonics", [])
    if not mnemonics:
        for insn in handler.get("instructions", []):
            m = insn.get("mnemonic", "")
            if m:
                mnemonics.append(m.lower())

    bigram_vals = extract_bigram_features(mnemonics)
    reg_vals = extract_register_effects(handler)
    op_vals = extract_operand_pattern_features(handler)
    trigram_vals = extract_trigram_features(mnemonics)
    histogram_vals = extract_opcode_histogram(mnemonics)
    cfg_vals = extract_cfg_features(handler)
    taint_vals = extract_taint_features(handler)

    all_values = (
        base.values + bigram_vals + reg_vals + op_vals
        + trigram_vals + histogram_vals + cfg_vals + taint_vals
    )

    all_names = (
        list(HANDLER_FEATURE_NAMES)
        + BIGRAM_FEATURE_NAMES
        + REGISTER_FEATURE_NAMES
        + OPERAND_PATTERN_NAMES
        + TRIGRAM_FEATURE_NAMES
        + OPCODE_HIST_NAMES
        + CFG_FEATURE_NAMES
        + TAINT_FEATURE_NAMES
    )

    return FeatureVector(
        values=all_values,
        feature_names=all_names,
        metadata={"source": "handler_extended"},
    )
