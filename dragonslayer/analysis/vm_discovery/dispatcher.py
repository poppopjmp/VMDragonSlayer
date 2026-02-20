"""
VM Discovery — Dispatcher Identification & Handler Table Reconstruction
========================================================================

Identifies the VM dispatcher (central fetch-decode-execute loop) and
reconstructs the handler dispatch table by correlating:

* Pattern-matching the VMProtect fetch-decode-dispatch cycle.
* Raw byte-level dispatcher patterns from :mod:`detector`.
* Control-flow information from lifted instructions.
* Symbolic execution handler classifications from :mod:`symbolic_execution`.
* Signature database matches from :mod:`database`.

The core algorithm matches the canonical VMProtect dispatcher pattern::

    movzx  reg, byte ptr [vIP]        ; opcode fetch
    {xor|not|add ...}                   ; optional opcode decode
    {add|sub|inc|lea} vIP, delta       ; vIP advance
    jmp    [table_base + reg * scale]  ; dispatch to handler

Usage::

    from dragonslayer.analysis.vm_discovery.dispatcher import (
        DispatcherAnalyzer,
        find_vmprotect_dispatcher,
        find_dispatcher_in_trace,
    )

    # From lifted instructions
    info = find_vmprotect_dispatcher(lifted_insns, bit_width=64)

    # From execution traces
    info = find_dispatcher_in_trace(trace_records, bit_width=64)

    # Existing DispatcherAnalyzer API still works
    analyzer = DispatcherAnalyzer()
    result = analyzer.analyze(binary_data, shared_data=ctx.shared_data)
"""

from __future__ import annotations

import logging
import re
import struct
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# VMProtect-specific dispatcher pattern matching
# ═══════════════════════════════════════════════════════════════════════════

# -- Register sets -----------------------------------------------------------

_GP_REGS_64 = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
}
_GP_REGS_32 = {
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
}

# Combined set: includes both widths so decode/fetch on 32-bit sub-regs works
_GP_ALL_WIDTHS_64 = _GP_REGS_64 | {
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    "ax", "bx", "cx", "dx", "si", "di",
    "al", "bl", "cl", "dl", "sil", "dil",
}
_GP_ALL_WIDTHS_32 = _GP_REGS_32 | {
    "ax", "bx", "cx", "dx", "si", "di",
    "al", "bl", "cl", "dl",
}
_FETCH_MNEMONICS = {"movzx", "movsx", "movsxd", "mov"}
_ADVANCE_MNEMONICS = {"add", "sub", "inc", "dec", "lea"}
_DECODE_MNEMONICS = {"xor", "not", "rol", "ror", "add", "sub", "neg", "bswap"}

_MEM_DEREF_RE = re.compile(r"\[([a-z0-9+\-*\s]+)\]", re.IGNORECASE)
_SCALE_RE = re.compile(r"(\w+)\s*\*\s*(\d+)", re.IGNORECASE)
_TABLE_LOOKUP_RE = re.compile(
    r"(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)(?:\s*([+\-])\s*(0x[0-9a-f]+|\d+))?",
    re.IGNORECASE,
)

# Register alias map: maps any sub-register to all its aliases
_REG_ALIASES: Dict[str, Set[str]] = {}

def _build_alias_map() -> Dict[str, Set[str]]:
    """Build a map from any register name to all aliases of the same physical reg."""
    families = [
        {"rax", "eax", "ax", "al", "ah"},
        {"rbx", "ebx", "bx", "bl", "bh"},
        {"rcx", "ecx", "cx", "cl", "ch"},
        {"rdx", "edx", "dx", "dl", "dh"},
        {"rsi", "esi", "si", "sil"},
        {"rdi", "edi", "di", "dil"},
        {"rbp", "ebp", "bp", "bpl"},
        {"rsp", "esp", "sp", "spl"},
        {"r8", "r8d", "r8w", "r8b"},
        {"r9", "r9d", "r9w", "r9b"},
        {"r10", "r10d", "r10w", "r10b"},
        {"r11", "r11d", "r11w", "r11b"},
        {"r12", "r12d", "r12w", "r12b"},
        {"r13", "r13d", "r13w", "r13b"},
        {"r14", "r14d", "r14w", "r14b"},
        {"r15", "r15d", "r15w", "r15b"},
    ]
    m: Dict[str, Set[str]] = {}
    for family in families:
        for name in family:
            m[name] = family
    return m

_REG_ALIASES = _build_alias_map()


def _reg_in_expr(reg_name: str, expr: str) -> bool:
    """Check if *reg_name* or any of its aliases appears in *expr*."""
    expr_lower = expr.lower()
    aliases = _REG_ALIASES.get(reg_name.lower(), {reg_name.lower()})
    for alias in aliases:
        if re.search(r'\b' + re.escape(alias) + r'\b', expr_lower):
            return True
    return False


# -- Internal candidate dataclasses -----------------------------------------

@dataclass
class _FetchCandidate:
    """Potential opcode-fetch instruction."""
    address: int
    vip_reg: str          # register used as pointer (e.g. rsi)
    fetch_reg: str        # register written with fetched value
    width: int            # 1 or 2
    insn_index: int


@dataclass
class _AdvanceCandidate:
    """Potential vIP-advance instruction."""
    address: int
    reg: str
    delta: int            # +1, -1, +2, -2, etc.
    insn_index: int


@dataclass
class _DispatchCandidate:
    """Indirect jump that could be the dispatch instruction."""
    address: int
    insn_index: int
    target_reg: str
    table_base_expr: str
    uses_memory: bool
    dispatch_style: str = "jmp"  # "jmp" | "push_ret" | "call" | "computed_goto"


@dataclass
class _DecodeCandidate:
    """Opcode decode/transform instruction (xor, not, etc.)."""
    address: int
    insn_index: int
    operation: str
    operand_reg: str
    detail: str


# -- VMProtect DispatcherMatch dataclass ------------------------------------

@dataclass
class VMProtectDispatcherMatch:
    """Fully-resolved VMProtect dispatcher description.

    This provides significantly more detail than the basic
    :class:`DispatcherInfo` — it captures the *semantic* structure of the
    dispatcher loop (vIP register, opcode fetch width, handler table
    layout, decode transforms) rather than just a byte-pattern match.
    """
    entry_address: int = 0
    indirect_jump_address: int = 0
    vip_register: str = ""
    fetch_register: str = ""
    fetch_width: int = 1
    table_base: int = 0
    table_scale: int = 8
    vip_delta: int = 1
    handler_addresses: List[int] = field(default_factory=list)
    confidence: float = 0.0
    vm_entry_address: int = 0
    context_registers: Dict[str, str] = field(default_factory=dict)
    decode_transforms: List[str] = field(default_factory=list)
    dispatch_style: str = "jmp"  # "jmp" | "push_ret" | "call" | "computed_goto"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_address": self.entry_address,
            "indirect_jump_address": self.indirect_jump_address,
            "vip_register": self.vip_register,
            "fetch_register": self.fetch_register,
            "fetch_width": self.fetch_width,
            "table_base": self.table_base,
            "table_scale": self.table_scale,
            "vip_delta": self.vip_delta,
            "handler_addresses": self.handler_addresses,
            "confidence": self.confidence,
            "vm_entry_address": self.vm_entry_address,
            "context_registers": self.context_registers,
            "decode_transforms": self.decode_transforms,
            "dispatch_style": self.dispatch_style,
        }


# -- Public API: VMProtect dispatcher identification -------------------------

def find_vmprotect_dispatcher(
    instructions: list,
    *,
    bit_width: int = 64,
    binary_data: Optional[bytes] = None,
    base_address: int = 0,
) -> Optional[VMProtectDispatcherMatch]:
    """Identify the VMProtect dispatcher loop in a lifted instruction stream.

    Pattern-matches the canonical VMProtect fetch→decode→advance→dispatch
    cycle rather than relying on back-edge heuristics.

    Parameters
    ----------
    instructions : list
        Lifted instruction objects with ``.address``, ``.mnemonic``,
        ``.operands``, ``.is_branch``, ``.branch_target`` attributes.
    bit_width : int
        Architecture bit-width (32 or 64).
    binary_data : bytes | None
        Raw binary for handler-table extraction.
    base_address : int
        Base address corresponding to ``binary_data[0]``.

    Returns
    -------
    VMProtectDispatcherMatch | None
        Fully-populated dispatcher match, or ``None`` if no dispatcher found.
    """
    if not instructions:
        return None

    gp_regs = _GP_REGS_64 if bit_width == 64 else _GP_REGS_32
    gp_all = _GP_ALL_WIDTHS_64 if bit_width == 64 else _GP_ALL_WIDTHS_32

    # Phase 1: Find all candidate components
    # Fetch uses pointer-width regs for vIP, but any width for dest
    fetches = _find_fetch_candidates(instructions, gp_regs, gp_all)
    advances = _find_advance_candidates(instructions, gp_regs)
    dispatches = _find_dispatch_candidates(instructions, gp_regs)
    decodes = _find_decode_candidates(instructions, gp_all)

    if not dispatches:
        logger.debug("No indirect jump candidates found — not a VM dispatcher")
        return None

    if not fetches:
        logger.debug("No opcode-fetch candidates found — not a VM dispatcher")
        return None

    # Phase 2: Score each (fetch, dispatch) pair for coherence
    best_score = 0.0
    best_info: Optional[VMProtectDispatcherMatch] = None

    for dispatch in dispatches:
        for fetch in fetches:
            score, info = _score_dispatcher_candidate(
                fetch, dispatch, advances, decodes,
                instructions, gp_regs, bit_width,
                binary_data, base_address,
            )
            if score > best_score:
                best_score = score
                best_info = info

    if best_info is not None and best_info.confidence >= 0.3:
        # Phase 3: Extract handler table if binary data available
        if binary_data and best_info.table_base:
            handlers = _extract_handler_table_binary(
                binary_data, base_address,
                best_info.table_base, best_info.table_scale, bit_width,
            )
            if handlers:
                best_info.handler_addresses = handlers

        logger.info(
            "VMProtect dispatcher: entry=0x%x, vIP=%s, table=0x%x, conf=%.2f",
            best_info.entry_address, best_info.vip_register,
            best_info.table_base, best_info.confidence,
        )
        return best_info

    logger.debug("No high-confidence dispatcher candidate (best=%.2f)", best_score)
    return None


def find_dispatcher_in_trace(
    trace_records: List[Dict[str, Any]],
    *,
    bit_width: int = 64,
) -> Optional[VMProtectDispatcherMatch]:
    """Identify the dispatcher from an execution trace (list of dicts).

    Each trace record should have ``address`` (int) and ``disassembly`` (str).
    Optionally ``registers`` (dict) and ``raw_bytes`` (hex str).

    Works by finding the most-visited indirect-jump site, extracting the
    surrounding basic block, and running pattern matching on it.
    """
    if not trace_records:
        return None

    addr_freq: Counter = Counter()
    for rec in trace_records:
        addr = rec.get("address", 0)
        if addr:
            addr_freq[addr] += 1

    # Find indirect jumps in the trace
    indirect_jumps: List[Dict[str, Any]] = []
    for rec in trace_records:
        disasm = rec.get("disassembly", "").lower().strip()
        mnem = disasm.split(None, 1)[0] if disasm else ""
        if mnem == "jmp":
            operands = disasm.split(None, 1)[1] if len(disasm.split(None, 1)) > 1 else ""
            if operands and not operands.startswith("0x") and not operands.lstrip("-").isdigit():
                indirect_jumps.append(rec)

    if not indirect_jumps:
        return None

    # Dispatcher is the hottest indirect jump
    best_dispatch = None
    best_freq = 0
    for rec in indirect_jumps:
        addr = rec.get("address", 0)
        freq = addr_freq.get(addr, 0)
        if freq > best_freq:
            best_freq = freq
            best_dispatch = rec

    if not best_dispatch or best_freq < 3:
        return None

    dispatch_addr = best_dispatch["address"]
    dispatch_block = _extract_block_around(trace_records, dispatch_addr, window=12)
    if not dispatch_block:
        return None

    pseudo_insns = _trace_to_pseudo_instructions(dispatch_block)
    gp_regs = _GP_REGS_64 if bit_width == 64 else _GP_REGS_32

    fetches = _find_fetch_candidates(pseudo_insns, gp_regs)
    advances = _find_advance_candidates(pseudo_insns, gp_regs)
    dispatches_list = _find_dispatch_candidates(pseudo_insns, gp_regs)
    decodes = _find_decode_candidates(pseudo_insns, gp_regs)

    if not dispatches_list or not fetches:
        return None

    best_score = 0.0
    best_info: Optional[VMProtectDispatcherMatch] = None

    for disp in dispatches_list:
        for fetch in fetches:
            score, info = _score_dispatcher_candidate(
                fetch, disp, advances, decodes,
                pseudo_insns, gp_regs, bit_width, None, 0,
            )
            if score > best_score:
                best_score = score
                best_info = info

    if best_info is None or best_info.confidence < 0.3:
        return None

    # Enhance with trace-derived handler addresses
    handler_addrs = _extract_handlers_from_trace_visits(trace_records, dispatch_addr)
    if handler_addrs:
        best_info.handler_addresses = sorted(handler_addrs)

    vip_from_trace = _identify_vip_from_trace_registers(trace_records, dispatch_addr)
    if vip_from_trace and not best_info.vip_register:
        best_info.vip_register = vip_from_trace

    return best_info


# -- Phase 1: Candidate extraction ------------------------------------------

def _find_fetch_candidates(
    instructions: list, gp_regs: set, gp_all: Optional[set] = None,
) -> List[_FetchCandidate]:
    """Find movzx/movsx/mov instructions that fetch from [reg].

    VMProtect opcode fetch pattern::
        movzx ecx, byte ptr [rsi]     ; fetch 1-byte opcode
        movzx ecx, word ptr [rsi]     ; fetch 2-byte opcode

    Excludes table-lookup patterns like ``mov rax, [r12+rcx*8]`` (which have
    index*scale in the memory operand).
    """
    if gp_all is None:
        gp_all = gp_regs
    candidates: List[_FetchCandidate] = []
    for idx, insn in enumerate(instructions):
        mnem = _get_mnemonic(insn).lower()
        if mnem not in _FETCH_MNEMONICS:
            continue
        ops = _get_operands(insn)
        if len(ops) < 2:
            continue
        dst = ops[0].strip().lower()
        src = ops[1].strip().lower()
        mem_match = _MEM_DEREF_RE.search(src)
        if not mem_match:
            continue
        inner = mem_match.group(1).strip().lower()

        # Exclude table-lookup patterns: [reg+reg*scale] or [reg+reg+disp]
        # A valid fetch is either [reg] or [reg+disp] (single register)
        if "*" in inner:
            continue  # Scale factor → table lookup, not opcode fetch
        inner_regs = [r for r in re.findall(r'\b([a-z][a-z0-9]*)\b', inner)
                      if r in gp_regs or r in gp_all]
        if len(inner_regs) > 1:
            continue  # Multi-register → table lookup

        ptr_reg = inner_regs[0] if inner_regs else inner.strip()
        if ptr_reg not in gp_regs:
            # Try the raw inner as a GP reg
            simple_parts = re.split(r'[+\-]', inner)
            ptr_reg = simple_parts[0].strip()
            if ptr_reg not in gp_regs:
                continue

        width = _infer_fetch_width(src, dst)
        fetch_dst = _normalize_reg(dst)
        candidates.append(_FetchCandidate(
            address=_get_address(insn), vip_reg=ptr_reg,
            fetch_reg=fetch_dst, width=width, insn_index=idx,
        ))
    return candidates


def _find_advance_candidates(instructions: list, gp_regs: set) -> List[_AdvanceCandidate]:
    """Find instructions that advance/decrement a GP register (vIP advance)."""
    candidates: List[_AdvanceCandidate] = []
    for idx, insn in enumerate(instructions):
        mnem = _get_mnemonic(insn).lower()
        if mnem not in _ADVANCE_MNEMONICS:
            continue
        ops = _get_operands(insn)
        if not ops:
            continue
        reg = ops[0].strip().lower()
        if mnem == "inc" and reg in gp_regs:
            candidates.append(_AdvanceCandidate(
                address=_get_address(insn), reg=reg, delta=1, insn_index=idx))
        elif mnem == "dec" and reg in gp_regs:
            candidates.append(_AdvanceCandidate(
                address=_get_address(insn), reg=reg, delta=-1, insn_index=idx))
        elif mnem in ("add", "sub") and len(ops) >= 2:
            if reg not in gp_regs:
                continue
            imm = _parse_immediate(ops[1].strip())
            if imm is not None and 0 < abs(imm) <= 8:
                delta = imm if mnem == "add" else -imm
                candidates.append(_AdvanceCandidate(
                    address=_get_address(insn), reg=reg, delta=delta, insn_index=idx))
        elif mnem == "lea" and len(ops) >= 2:
            if reg not in gp_regs:
                continue
            src = ops[1].strip().lower()
            mem_match = _MEM_DEREF_RE.search(src)
            if mem_match:
                inner = mem_match.group(1).strip()
                delta = _parse_lea_delta(inner, reg)
                if delta is not None and 0 < abs(delta) <= 8:
                    candidates.append(_AdvanceCandidate(
                        address=_get_address(insn), reg=reg, delta=delta, insn_index=idx))
    return candidates


def _find_dispatch_candidates(instructions: list, gp_regs: set) -> List[_DispatchCandidate]:
    """Find indirect control-flow transfers that could be the dispatch instruction.

    Recognises four dispatch styles used by VMProtect and similar VMs:

    1. **jmp reg / jmp [mem]** — classic indirect jump (most common).
    2. **push reg; ret** — push the handler address then retn to it.
       VMProtect v2 and some Themida variants use this to avoid ``jmp``
       pattern signatures.
    3. **call reg / call [mem]** — indirect call used as dispatch when
       the handler itself returns back to the dispatcher.
    4. **Computed goto via stack** — patterns like ``xchg [rsp], reg; ret``
       or ``mov [rsp], reg; ret`` that load a handler address onto the
       stack and then use ``ret`` to transfer control.
    """
    candidates: List[_DispatchCandidate] = []
    for idx, insn in enumerate(instructions):
        mnem = _get_mnemonic(insn).lower()

        # -- Style 1: jmp reg / jmp [mem] ------------------------------------
        if mnem == "jmp":
            ops_raw = _get_operands_raw(insn)
            if not ops_raw:
                continue
            operand = ops_raw.strip().lower()
            reg_target = _normalize_reg(operand)
            if reg_target in gp_regs:
                candidates.append(_DispatchCandidate(
                    address=_get_address(insn), insn_index=idx,
                    target_reg=reg_target, table_base_expr=operand,
                    uses_memory=False, dispatch_style="jmp"))
                continue
            mem_match = _MEM_DEREF_RE.search(operand)
            if mem_match:
                inner = mem_match.group(1).strip()
                used_regs = [r for r in re.findall(r'\b([a-z][a-z0-9]*)\b', inner) if r in gp_regs]
                target_reg = used_regs[0] if used_regs else ""
                candidates.append(_DispatchCandidate(
                    address=_get_address(insn), insn_index=idx,
                    target_reg=target_reg, table_base_expr=inner,
                    uses_memory=True, dispatch_style="jmp"))
                continue
            branch_target = getattr(insn, "branch_target", None)
            if branch_target is None:
                candidates.append(_DispatchCandidate(
                    address=_get_address(insn), insn_index=idx,
                    target_reg="", table_base_expr=operand,
                    uses_memory="[" in operand, dispatch_style="jmp"))
            continue

        # -- Style 2: push reg; ret ------------------------------------------
        # Look for a ``ret``; the preceding instruction should be ``push reg``
        # (possibly with one or two nops/padding in between).
        if mnem in ("ret", "retn"):
            # Scan back up to 3 instructions looking for push reg
            for back in range(1, min(4, idx + 1)):
                prev_insn = instructions[idx - back]
                prev_mnem = _get_mnemonic(prev_insn).lower()
                if prev_mnem in ("nop", "endbr64", "endbr32"):
                    continue  # skip padding
                if prev_mnem == "push":
                    prev_ops = _get_operands(prev_insn)
                    if prev_ops:
                        push_op = prev_ops[0].strip().lower()
                        push_reg = _normalize_reg(push_op)
                        if push_reg in gp_regs:
                            candidates.append(_DispatchCandidate(
                                address=_get_address(prev_insn),
                                insn_index=idx - back,
                                target_reg=push_reg,
                                table_base_expr=push_op,
                                uses_memory=False,
                                dispatch_style="push_ret"))
                break  # stop scanning after first non-nop

        # -- Style 3: call reg / call [mem] ----------------------------------
        if mnem == "call":
            ops_raw = _get_operands_raw(insn)
            if not ops_raw:
                continue
            operand = ops_raw.strip().lower()
            reg_target = _normalize_reg(operand)
            if reg_target in gp_regs:
                candidates.append(_DispatchCandidate(
                    address=_get_address(insn), insn_index=idx,
                    target_reg=reg_target, table_base_expr=operand,
                    uses_memory=False, dispatch_style="call"))
                continue
            mem_match = _MEM_DEREF_RE.search(operand)
            if mem_match:
                inner = mem_match.group(1).strip()
                used_regs = [r for r in re.findall(r'\b([a-z][a-z0-9]*)\b', inner) if r in gp_regs]
                target_reg = used_regs[0] if used_regs else ""
                candidates.append(_DispatchCandidate(
                    address=_get_address(insn), insn_index=idx,
                    target_reg=target_reg, table_base_expr=inner,
                    uses_memory=True, dispatch_style="call"))

        # -- Style 4: computed goto via stack --------------------------------
        # Patterns: ``xchg [rsp], reg; ret``  or  ``mov [rsp], reg; ret``
        # The address is placed at [rsp] and control transfers via ret.
        if mnem in ("ret", "retn"):
            for back in range(1, min(4, idx + 1)):
                prev_insn = instructions[idx - back]
                prev_mnem = _get_mnemonic(prev_insn).lower()
                if prev_mnem in ("nop", "endbr64", "endbr32"):
                    continue
                if prev_mnem in ("xchg", "mov"):
                    prev_ops = _get_operands(prev_insn)
                    if len(prev_ops) >= 2:
                        dst = prev_ops[0].strip().lower()
                        src = prev_ops[1].strip().lower()
                        # Check for [rsp]/[esp] as destination
                        sp_deref = "[rsp]" if "rsp" in dst else ("[esp]" if "esp" in dst else "")
                        if sp_deref and dst.replace(" ", "") in ("[rsp]", "[esp]"):
                            src_reg = _normalize_reg(src)
                            if src_reg in gp_regs:
                                candidates.append(_DispatchCandidate(
                                    address=_get_address(prev_insn),
                                    insn_index=idx - back,
                                    target_reg=src_reg,
                                    table_base_expr=src,
                                    uses_memory=False,
                                    dispatch_style="computed_goto"))
                break

    return candidates


def _find_decode_candidates(instructions: list, gp_regs: set) -> List[_DecodeCandidate]:
    """Find opcode decode/obfuscation transforms between fetch and dispatch."""
    candidates: List[_DecodeCandidate] = []
    for idx, insn in enumerate(instructions):
        mnem = _get_mnemonic(insn).lower()
        if mnem not in _DECODE_MNEMONICS:
            continue
        ops = _get_operands(insn)
        if not ops:
            continue
        reg = _normalize_reg(ops[0].strip().lower())
        if reg not in gp_regs:
            continue
        detail = f"{mnem} {', '.join(ops)}"
        candidates.append(_DecodeCandidate(
            address=_get_address(insn), insn_index=idx,
            operation=mnem, operand_reg=reg, detail=detail))
    return candidates


# -- Phase 2: Scoring -------------------------------------------------------

def _score_dispatcher_candidate(
    fetch: _FetchCandidate,
    dispatch: _DispatchCandidate,
    advances: List[_AdvanceCandidate],
    decodes: List[_DecodeCandidate],
    instructions: list,
    gp_regs: set,
    bit_width: int,
    binary_data: Optional[bytes],
    base_address: int,
) -> Tuple[float, Optional[VMProtectDispatcherMatch]]:
    """Score how well a (fetch, dispatch) pair matches VMProtect's dispatcher."""
    score = 0.0

    # 1. Fetch must precede dispatch in instruction order
    if fetch.insn_index >= dispatch.insn_index:
        return 0.0, None

    # 2. Distance check: fetch and dispatch should be close
    distance = dispatch.insn_index - fetch.insn_index
    if distance <= 15:
        score += 0.15
    elif distance <= 30:
        score += 0.05

    # 3. vIP advance matches fetch register
    matching_advance: Optional[_AdvanceCandidate] = None
    for adv in advances:
        if adv.reg == fetch.vip_reg and fetch.insn_index < adv.insn_index <= dispatch.insn_index + 2:
            matching_advance = adv
            score += 0.2
            break
    if matching_advance is None:
        for adv in advances:
            if adv.reg == fetch.vip_reg:
                score += 0.05
                matching_advance = adv
                break

    # 4. Data flow: fetched register used in dispatch expression (alias-aware)
    fetch_reg = fetch.fetch_reg
    dispatch_expr = dispatch.table_base_expr.lower()
    if _reg_in_expr(fetch_reg, dispatch_expr):
        score += 0.25
    else:
        for dec in decodes:
            if (dec.operand_reg == fetch_reg
                    and fetch.insn_index < dec.insn_index < dispatch.insn_index):
                if _reg_in_expr(dec.operand_reg, dispatch_expr):
                    score += 0.2
                    break
                score += 0.08
                break

    # 5. Table lookup pattern (base+index*scale)
    table_base = 0
    table_scale = bit_width // 8
    if dispatch.uses_memory:
        tbl_match = _TABLE_LOOKUP_RE.search(dispatch_expr)
        if tbl_match:
            score += 0.2
            try:
                table_scale = int(tbl_match.group(3))
            except ValueError:
                pass
        elif _SCALE_RE.search(dispatch_expr):
            score += 0.1
            scale_match = _SCALE_RE.search(dispatch_expr)
            if scale_match:
                try:
                    table_scale = int(scale_match.group(2))
                except ValueError:
                    pass
        else:
            score += 0.05
    else:
        for i in range(max(0, dispatch.insn_index - 5), dispatch.insn_index):
            insn = instructions[i]
            m = _get_mnemonic(insn).lower()
            if m in ("mov", "lea"):
                o = _get_operands(insn)
                if len(o) >= 2:
                    dst = _normalize_reg(o[0].strip().lower())
                    src = o[1].strip().lower()
                    if dst == dispatch.target_reg and "[" in src:
                        if _TABLE_LOOKUP_RE.search(src):
                            score += 0.15
                            break
                        elif _SCALE_RE.search(src):
                            score += 0.08
                            break

    # 6. Decode transforms between fetch and dispatch
    decode_detail: List[str] = []
    for dec in decodes:
        if (dec.operand_reg == fetch_reg
                and fetch.insn_index < dec.insn_index < dispatch.insn_index):
            decode_detail.append(dec.detail)
    if decode_detail:
        score += 0.1

    # 7. Handler back-edges (handlers jump back to dispatcher)
    dispatch_addr = _get_address(instructions[dispatch.insn_index])
    fetch_addr = _get_address(instructions[fetch.insn_index])
    dispatcher_region = range(min(fetch_addr, dispatch_addr),
                             max(fetch_addr, dispatch_addr) + 16)
    back_edges = 0
    for insn in instructions:
        m = _get_mnemonic(insn).lower()
        target = getattr(insn, "branch_target", None)
        if m == "jmp" and target is not None and target in dispatcher_region:
            insn_addr = _get_address(insn)
            if insn_addr not in dispatcher_region:
                back_edges += 1
    if back_edges >= 2:
        score += 0.1
    elif back_edges >= 1:
        score += 0.05

    # Build result
    confidence = min(score, 1.0)
    vip_delta = matching_advance.delta if matching_advance else fetch.width
    ctx_regs: Dict[str, str] = {fetch.vip_reg: "vIP"}

    # Obfuscated dispatch styles get a small bonus — they signal that
    # the binary deliberately avoids plain ``jmp`` patterns, which is
    # strong evidence of a VM dispatcher (rather than regular code).
    _style = dispatch.dispatch_style
    if _style in ("push_ret", "computed_goto"):
        confidence = min(confidence + 0.05, 1.0)
    elif _style == "call":
        confidence = min(confidence + 0.02, 1.0)

    info = VMProtectDispatcherMatch(
        entry_address=fetch_addr,
        indirect_jump_address=dispatch_addr,
        vip_register=fetch.vip_reg,
        fetch_register=fetch.fetch_reg,
        fetch_width=fetch.width,
        table_base=table_base,
        table_scale=table_scale,
        vip_delta=vip_delta,
        confidence=confidence,
        context_registers=ctx_regs,
        decode_transforms=decode_detail,
        dispatch_style=_style,
    )
    return confidence, info


# -- Phase 3: Handler table extraction from binary ---------------------------

def _extract_handler_table_binary(
    binary_data: bytes,
    base_address: int,
    table_base: int,
    scale: int,
    bit_width: int,
    max_entries: int = 256,
) -> List[int]:
    """Read handler addresses from the binary's handler table."""
    offset = table_base - base_address
    if offset < 0 or offset >= len(binary_data):
        return []
    entry_size = scale if scale in (4, 8) else (8 if bit_width == 64 else 4)
    fmt = "<Q" if entry_size == 8 else "<I"
    handlers: List[int] = []
    binary_end = base_address + len(binary_data)
    for i in range(max_entries):
        pos = offset + i * entry_size
        if pos + entry_size > len(binary_data):
            break
        addr = struct.unpack(fmt, binary_data[pos:pos + entry_size])[0]
        if addr == 0:
            break
        if base_address <= addr < binary_end:
            handlers.append(addr)
        elif handlers:
            break
    return handlers


# -- Trace-based helpers -----------------------------------------------------

def _extract_block_around(
    trace_records: List[Dict[str, Any]],
    target_addr: int,
    window: int = 12,
) -> List[Dict[str, Any]]:
    """Extract trace records forming the basic block around *target_addr*."""
    indices = [i for i, r in enumerate(trace_records) if r.get("address") == target_addr]
    if not indices:
        return []
    idx = indices[0]
    return trace_records[max(0, idx - window):min(len(trace_records), idx + window + 1)]


def _extract_handlers_from_trace_visits(
    trace_records: List[Dict[str, Any]],
    dispatch_addr: int,
) -> List[int]:
    """Extract handler entry addresses by finding the instruction after dispatch."""
    handler_addrs: Set[int] = set()
    for i, rec in enumerate(trace_records):
        if rec.get("address") == dispatch_addr and i + 1 < len(trace_records):
            next_addr = trace_records[i + 1].get("address", 0)
            if next_addr and next_addr != dispatch_addr:
                handler_addrs.add(next_addr)
    return sorted(handler_addrs)


def _identify_vip_from_trace_registers(
    trace_records: List[Dict[str, Any]],
    dispatch_addr: int,
) -> Optional[str]:
    """Identify vIP register by checking which register changes monotonically."""
    visit_regs: List[Dict[str, int]] = []
    for rec in trace_records:
        if rec.get("address") == dispatch_addr:
            regs = rec.get("registers", {})
            if regs:
                visit_regs.append(regs)
    if len(visit_regs) < 3:
        return None
    best_reg = None
    best_score = 0.0
    all_regs: Set[str] = set()
    for vr in visit_regs:
        all_regs.update(vr.keys())
    for reg in all_regs:
        if reg.lower() in ("rsp", "esp", "rip", "eip"):
            continue
        values = [vr.get(reg) for vr in visit_regs if reg in vr]
        if len(values) < 3 or not all(isinstance(v, (int, float)) for v in values):
            continue
        diffs = [values[i + 1] - values[i] for i in range(len(values) - 1)]
        if not diffs:
            continue
        if all(d > 0 for d in diffs) or all(d < 0 for d in diffs):
            consistency = len(set(diffs)) == 1
            s = 0.7 + (0.3 if consistency else 0.0)
            if s > best_score:
                best_score = s
                best_reg = reg.lower()
    return best_reg


def _trace_to_pseudo_instructions(trace_records: List[Dict[str, Any]]) -> list:
    """Convert trace record dicts to lightweight pseudo-instruction objects."""
    return [_PseudoInstruction(
        address=rec.get("address", 0),
        disassembly=rec.get("disassembly", ""),
    ) for rec in trace_records]


class _PseudoInstruction:
    """Minimal instruction-like object for dispatcher analysis."""
    def __init__(self, address: int = 0, disassembly: str = ""):
        self.address = address
        parts = disassembly.strip().split(None, 1) if disassembly else []
        self.mnemonic = parts[0].lower() if parts else ""
        self.operands = parts[1] if len(parts) > 1 else ""
        self.is_branch = self.mnemonic.startswith("j") or self.mnemonic in ("call", "ret")
        self.branch_target = None
        self.size = 1


# -- Utility helpers ---------------------------------------------------------

def _get_mnemonic(insn: Any) -> str:
    if hasattr(insn, "mnemonic"):
        return insn.mnemonic or ""
    if hasattr(insn, "disassembly"):
        parts = insn.disassembly.strip().split(None, 1) if insn.disassembly else []
        return parts[0] if parts else ""
    return ""


def _get_operands(insn: Any) -> List[str]:
    raw = _get_operands_raw(insn)
    return [o.strip() for o in raw.split(",")] if raw else []


def _get_operands_raw(insn: Any) -> str:
    if hasattr(insn, "operands") and insn.operands:
        return insn.operands
    if hasattr(insn, "disassembly") and insn.disassembly:
        parts = insn.disassembly.strip().split(None, 1)
        return parts[1] if len(parts) > 1 else ""
    return ""


def _get_address(insn: Any) -> int:
    return getattr(insn, "address", 0)


def _normalize_reg(name: str) -> str:
    name = name.strip().lower()
    for prefix in ("byte ptr ", "word ptr ", "dword ptr ", "qword ptr "):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name.strip()


def _infer_fetch_width(src: str, dst: str) -> int:
    src_lower = src.lower()
    if "byte ptr" in src_lower or "byte" in src_lower:
        return 1
    if "word ptr" in src_lower or "word" in src_lower:
        return 2
    if "dword ptr" in src_lower:
        return 4
    dst_lower = dst.lower().strip()
    if dst_lower.endswith(("b", "l", "h")):
        return 1
    if dst_lower in ("ax", "bx", "cx", "dx", "si", "di"):
        return 2
    return 1


def _parse_immediate(s: str) -> Optional[int]:
    s = s.strip()
    try:
        if s.startswith("0x") or s.startswith("-0x"):
            return int(s, 16)
        if s.lstrip("-").isdigit():
            return int(s)
    except ValueError:
        pass
    return None


def _parse_lea_delta(inner: str, reg: str) -> Optional[int]:
    inner = inner.strip().lower()
    reg = reg.strip().lower()
    m = re.match(rf"^{re.escape(reg)}\s*([+\-])\s*(0x[0-9a-f]+|\d+)$", inner)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        try:
            return sign * int(m.group(2), 0)
        except ValueError:
            return None
    return None


# ═══════════════════════════════════════════════════════════════════════════
# Original DispatcherAnalyzer (enhanced with VMProtect pattern matching)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class DispatcherInfo:
    """Information about a detected VM dispatcher."""
    address: int
    pattern: str          # e.g. "jmp eax", "jmp [ecx*4+disp32]"
    dispatch_type: str    # "register", "table", "computed"
    handler_count: int = 0
    loop_detected: bool = False
    confidence: float = 0.0
    table_entries: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "pattern": self.pattern,
            "dispatch_type": self.dispatch_type,
            "handler_count": self.handler_count,
            "loop_detected": self.loop_detected,
            "confidence": round(self.confidence, 4),
            "table_entries_count": len(self.table_entries),
        }


@dataclass
class HandlerEntry:
    """Entry in the reconstructed handler dispatch table."""
    opcode: int                      # VM opcode / index
    handler_address: int             # Address of the handler code
    category: str = "unknown"        # Handler semantic category
    size: int = 0                    # Approximate handler size in bytes
    returns_to_dispatcher: bool = False
    reads: List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "opcode": self.opcode,
            "handler_address": self.handler_address,
            "category": self.category,
            "size": self.size,
            "returns_to_dispatcher": self.returns_to_dispatcher,
            "reads": self.reads,
            "writes": self.writes,
        }


@dataclass
class DispatchTableResult:
    """Complete dispatcher analysis result."""
    success: bool
    dispatchers: List[DispatcherInfo] = field(default_factory=list)
    handler_table: List[HandlerEntry] = field(default_factory=list)
    total_handlers: int = 0
    opcode_range: Optional[tuple] = None
    protector: str = "unknown"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "dispatchers": [d.to_dict() for d in self.dispatchers],
            "handler_table": [h.to_dict() for h in self.handler_table],
            "total_handlers": self.total_handlers,
            "opcode_range": list(self.opcode_range) if self.opcode_range else None,
            "protector": self.protector,
            "error": self.error,
        }


class DispatcherAnalyzer:
    """
    Identifies VM dispatchers and reconstructs handler dispatch tables.

    Combines structural analysis (byte patterns) with semantic analysis
    (from symbolic execution) to build a mapping of VM opcodes → handlers.
    """

    # Common VMProtect dispatch patterns
    VMPROTECT_DISPATCH_SIGS = [
        # push addr; ret  (VMProtect 3.x entry)
        (b"\x68", 5, "push_ret_entry"),
        # jmp [reg*4+table]  (dispatch via jump table)
        (b"\xff\x24\x85", 7, "jmp_table_eax"),
        (b"\xff\x24\x8d", 7, "jmp_table_ecx"),
        (b"\xff\x24\x95", 7, "jmp_table_edx"),
        (b"\xff\x24\x9d", 7, "jmp_table_ebx"),
    ]

    def analyze(
        self,
        binary_data: bytes,
        *,
        shared_data: Optional[Dict[str, Any]] = None,
    ) -> DispatchTableResult:
        """
        Analyse binary data with cross-stage context to identify
        dispatchers and reconstruct the handler table.

        Parameters
        ----------
        binary_data : bytes
            Raw binary data.
        shared_data : dict | None
            Pipeline shared data (vm_discovery, symbolic_execution, etc.).
        """
        shared = shared_data or {}

        try:
            # 1. Collect dispatcher candidates from VM discovery
            vm_info = shared.get("vm_discovery", {})
            raw_dispatchers = vm_info.get("dispatchers", [])
            protector = vm_info.get("protector", "unknown")

            dispatcher_infos: List[DispatcherInfo] = []
            for d in raw_dispatchers:
                if isinstance(d, dict):
                    dispatcher_infos.append(DispatcherInfo(
                        address=d.get("offset", 0),
                        pattern=d.get("mnemonic", "unknown"),
                        dispatch_type=self._classify_dispatch_type(d.get("mnemonic", "")),
                        confidence=0.5,
                    ))

            # 2. Scan for jump-table dispatchers (indirect jump with table)
            table_dispatchers = self._find_jump_tables(binary_data)
            for td in table_dispatchers:
                # Check for duplicates
                existing = any(
                    abs(d.address - td.address) < 16 for d in dispatcher_infos
                )
                if not existing:
                    dispatcher_infos.append(td)

            # 2b. Scan for push imm32; ret sequences (obfuscated jumps)
            push_ret_entries = self._find_push_ret_sequences(
                binary_data,
                image_base=vm_info.get("image_base", 0),
            )

            # 3. Merge with symbolic execution handler data
            sym_info = shared.get("symbolic_execution", {})
            sym_handlers = sym_info.get("handlers", [])
            sym_handler_table = sym_info.get("handler_table", {})

            # 4. Build handler table
            handler_table: List[HandlerEntry] = []
            seen_addrs: Set[int] = set()

            # From symbolic execution classified handlers
            for i, h in enumerate(sym_handlers):
                addr = h.get("address", 0) if isinstance(h, dict) else getattr(h, "address", 0)
                if addr in seen_addrs:
                    continue
                seen_addrs.add(addr)

                cat = h.get("category", "unknown") if isinstance(h, dict) else getattr(h, "category", "unknown")
                handler_table.append(HandlerEntry(
                    opcode=i,
                    handler_address=addr,
                    category=cat,
                    size=h.get("instruction_count", 0) if isinstance(h, dict) else 0,
                    reads=h.get("reads", []) if isinstance(h, dict) else [],
                    writes=h.get("writes", []) if isinstance(h, dict) else [],
                ))

            # From jump table extraction
            for td in table_dispatchers:
                for entry in td.table_entries:
                    if entry not in seen_addrs:
                        seen_addrs.add(entry)
                        handler_table.append(HandlerEntry(
                            opcode=len(handler_table),
                            handler_address=entry,
                            category="table_entry",
                        ))

            # From push/ret sequences — add targets as handler entry points
            for pr_addr, pr_target in push_ret_entries:
                if pr_target not in seen_addrs:
                    seen_addrs.add(pr_target)
                    handler_table.append(HandlerEntry(
                        opcode=len(handler_table),
                        handler_address=pr_target,
                        category="push_ret_target",
                    ))
                # Register the push/ret site as a dispatcher if enough
                # targets converge in a small region
            if push_ret_entries:
                pr_dispatcher = DispatcherInfo(
                    address=push_ret_entries[0][0],
                    pattern="push_ret",
                    dispatch_type="push_ret",
                    handler_count=len(push_ret_entries),
                    confidence=min(1.0, 0.4 + len(push_ret_entries) * 0.1),
                    table_entries=[t for _, t in push_ret_entries],
                )
                dispatcher_infos.append(pr_dispatcher)

            # 5. Detect dispatcher loops
            for di in dispatcher_infos:
                # push_ret dispatchers already have accurate counts
                if di.dispatch_type == "push_ret":
                    if di.handler_count > 3:
                        di.loop_detected = True
                    continue

                di.handler_count = len([
                    h for h in handler_table
                    if abs(h.handler_address - di.address) < 0x10000
                ])
                if di.handler_count > 3:
                    di.loop_detected = True
                    di.confidence = min(1.0, di.confidence + 0.3)

            # 6. Compute opcode range
            opcodes = [h.opcode for h in handler_table]
            opcode_range = (min(opcodes), max(opcodes)) if opcodes else None

            return DispatchTableResult(
                success=True,
                dispatchers=dispatcher_infos,
                handler_table=handler_table,
                total_handlers=len(handler_table),
                opcode_range=opcode_range,
                protector=protector,
            )

        except Exception as exc:
            logger.exception("Dispatcher analysis failed")
            return DispatchTableResult(success=False, error=str(exc))

    @staticmethod
    def _classify_dispatch_type(mnemonic: str) -> str:
        """Classify dispatch type from mnemonic pattern."""
        mn = mnemonic.lower()
        if "table" in mn or "*4" in mn or "*8" in mn:
            return "table"
        if "jmp" in mn and any(r in mn for r in ("eax", "ecx", "edx", "ebx", "rax", "rcx")):
            return "register"
        return "computed"

    def _find_jump_tables(self, data: bytes) -> List[DispatcherInfo]:
        """
        Scan for indirect jump instructions followed by potential jump tables.

        A jump table is typically: jmp [reg*4+base], where base points to
        an array of code addresses.
        """
        results: List[DispatcherInfo] = []

        for pattern, length, name in self.VMPROTECT_DISPATCH_SIGS:
            start = 0
            while True:
                idx = data.find(pattern, start)
                if idx == -1 or idx + length > len(data):
                    break
                start = idx + 1

                # For jmp [reg*4+disp32] patterns, extract table base
                if len(pattern) == 3 and idx + 7 <= len(data):
                    try:
                        disp = struct.unpack_from("<I", data, idx + 3)[0]
                        # Validate: table entries should be plausible addresses
                        table_entries = self._extract_table_entries(data, disp, max_entries=256)
                        if len(table_entries) >= 2:
                            di = DispatcherInfo(
                                address=idx,
                                pattern=name,
                                dispatch_type="table",
                                handler_count=len(table_entries),
                                confidence=min(1.0, 0.3 + len(table_entries) * 0.05),
                                table_entries=table_entries,
                            )
                            results.append(di)
                    except (struct.error, IndexError):
                        pass

                if len(results) >= 20:
                    break

        return results

    # ------------------------------------------------------------------
    # push imm32 ; ret  detection
    # ------------------------------------------------------------------

    @staticmethod
    def _find_push_ret_sequences(
        data: bytes,
        *,
        image_base: int = 0,
        max_sequences: int = 512,
    ) -> List[tuple]:
        """Scan for ``push imm32; ret`` (``\\x68 <4B> \\xC3``) obfuscated jumps.

        VMProtect (and similar protectors) replace direct ``jmp addr`` with a
        ``push addr; ret`` pair.  This method finds all such 6-byte sequences
        whose pushed value looks like a plausible code pointer.

        Parameters
        ----------
        data : bytes
            Raw binary data.
        image_base : int
            VA of the binary image base (used for pointer validation).
        max_sequences : int
            Cap on the number of returned results.

        Returns
        -------
        list[tuple[int, int]]
            ``(file_offset_of_push, pushed_address)`` pairs.
        """
        results: List[tuple] = []
        data_len = len(data)
        # Pattern: 0x68 <imm32 LE> 0xC3
        needle = b"\x68"
        start = 0

        while len(results) < max_sequences:
            idx = data.find(needle, start)
            if idx == -1 or idx + 6 > data_len:
                break
            start = idx + 1

            # Next byte after the 4-byte immediate must be 0xC3 (ret)
            if data[idx + 5] != 0xC3:
                continue

            pushed = struct.unpack_from("<I", data, idx + 1)[0]

            # Basic validation: pushed value should be a plausible code address
            if pushed == 0:
                continue

            # If we know image_base, target should be >= image_base
            if image_base and pushed < image_base:
                continue

            # For raw files without a known image_base, accept addresses that
            # fit within a 32-bit VA range and aren't tiny constants.
            if pushed < 0x1000:
                continue

            results.append((idx, pushed))

        logger.info("Found %d push/ret sequences", len(results))
        return results

    @staticmethod
    def _extract_table_entries(
        data: bytes,
        table_offset: int,
        max_entries: int = 256,
        entry_size: int = 4,
    ) -> List[int]:
        """
        Extract potential jump table entries starting at table_offset.

        Parameters
        ----------
        entry_size : int
            4 for 32-bit, 8 for 64-bit binaries.
        """
        entries: List[int] = []
        data_len = len(data)
        fmt = "<I" if entry_size == 4 else "<Q"
        max_addr = 0x7FFFFFFF if entry_size == 4 else 0x7FFFFFFFFFFF

        for i in range(max_entries):
            off = table_offset + i * entry_size
            if off + entry_size > data_len:
                break
            try:
                addr = struct.unpack_from(fmt, data, off)[0]
            except struct.error:
                break

            # Basic validation: address should be non-zero and within
            # a plausible code range
            if addr == 0 or addr > max_addr:
                break
            entries.append(addr)

        return entries
