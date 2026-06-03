"""Protector-agnostic structural VM detection.

Commercial-protector detection (``VMDetector``) is signature-driven: it
looks for VMProtect/Themida/Enigma sections, watermarks and import names.
That cannot recognise an *unknown* or *custom* VM.

This module detects the **structure** every threaded-/bytecode-interpreter VM
shares, regardless of who built it, from an execution trace:

* a tight **dispatch loop** — a small set of addresses that account for most
  of the executed instructions (the fetch/decode/dispatch cycle runs once per
  virtual instruction);
* a **monotonic virtual instruction pointer** — a register that walks a
  bytecode stream;
* **indirect dispatch** — ``jmp/call`` through a register or handler table
  (or a ``ret``-trampoline), the hallmark of opcode-table dispatch.

These signals are what let the rest of the pipeline devirtualise custom VMs
even when no protector signature matches.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .handler_boundaries import identify_vip_register

_MEM_OPERAND_RE = re.compile(r"\[([^\]]+)\]")
_REG_TOKEN_RE = re.compile(r"[a-z][a-z0-9]+")


def _read_base_regs(disasm: str) -> set[str]:
    """Base registers of memory operands that are *read* (load sources).

    The vIP is dereferenced to *read* the opcode stream (``movzx eax,[rsi]``),
    whereas a decrypt/copy pointer is the *write* destination of a store
    (``xor byte[rax], key``) and the VM-context pointer is the destination of
    the vIP write-back (``mov [r15], rbp``).  Only the source-position memory
    operand (after the first comma), or a lone memory operand (``jmp [..]``),
    counts — so write bases are excluded.  Scaled indices (``rax*8``) are not
    bases.
    """
    d = disasm.lower()
    if "," in d:                      # keep only the source operand(s)
        d = d.split(",", 1)[1]
    out: set[str] = set()
    for inner in _MEM_OPERAND_RE.findall(d):
        for term in inner.split("+"):
            term = term.strip()
            if "*" in term:           # scaled index (rax*8), not a base
                continue
            m = _REG_TOKEN_RE.match(term)
            if m:
                out.add(m.group(0))
                break
    return out


def _enclosing_nested_vip(
    slice_insns: list[Any], outer_vip: str
) -> tuple[str, tuple[int, ...]] | None:
    """Pick the *enclosing* nested interpreter's vIP within a handler slice.

    When a handler slice contains more than one nested dispatcher (a VM that
    enters a deeper VM), the enclosing interpreter's vIP advances across the
    **whole** slice while the inner ones only span sub-ranges.  We therefore
    choose, among registers that are dereferenced as a memory base (pointers,
    not accumulators) and advance monotonically, the one with the widest
    change span — and return it with the dispatch loop localised around its
    hottest fetch site.  Deeper layers are recovered by recursion.
    """
    outer = (outer_vip or "").lower()
    values: dict[str, list[tuple[int, int]]] = {}
    fetch_sites: dict[str, Counter[int]] = {}
    for idx, ti in enumerate(slice_insns):
        for r, v in (ti.registers or {}).items():
            values.setdefault(r.lower(), []).append((idx, v))
        for base in _read_base_regs(getattr(ti, "disassembly", "") or ""):
            fetch_sites.setdefault(base, Counter())[ti.address] += 1

    # rip/eip (instruction pointer, from `lea reg,[rip+...]`) and the stack
    # pointer are monotonic memory bases but never the vIP.
    _NEVER_VIP = {"rsp", "esp", "rip", "eip"}
    best: tuple[int, int] | None = None
    best_reg: str | None = None
    for reg, seq in values.items():
        if reg in _NEVER_VIP or reg == outer or reg not in fetch_sites:
            continue
        diffs = [seq[i + 1][1] - seq[i][1] for i in range(len(seq) - 1)]
        nz = [d for d in diffs if d != 0]
        if len(nz) < 2:
            continue
        pos = sum(1 for d in nz if d > 0)
        mono = max(pos, len(nz) - pos) / len(nz)
        if mono < 0.6:
            continue
        change_idx = [seq[i + 1][0] for i in range(len(seq) - 1) if diffs[i] != 0]
        key = (change_idx[-1] - change_idx[0], -change_idx[0])  # widest, then earliest
        if best is None or key > best:
            best, best_reg = key, reg

    if best_reg is None:
        return None
    site = fetch_sites[best_reg].most_common(1)[0][0]
    # Capture the invariant fetch + dispatch block *around* the opcode fetch
    # (forward too) so a cmp/je decode chain that follows the fetch is treated
    # as dispatcher infrastructure and stripped from handler classification.
    disp = _fetch_dispatch_block(slice_insns, site)
    return best_reg, tuple(sorted(disp))


def _fetch_dispatch_block(
    slice_insns: list[Any], site: int, *, before: int = 1, after: int = 8
) -> set[int]:
    """Invariant fetch/decode/dispatch addresses around an opcode-fetch site.

    Looks both backward and forward from each execution of *site* and keeps the
    addresses present in a majority of those windows — i.e. the instructions
    that run every iteration (the fetch and any ``cmp/je`` decode chain),
    excluding the per-opcode handler bodies that diverge after the dispatch.
    """
    windows: list[set[int]] = []
    for i, ti in enumerate(slice_insns):
        if ti.address == site:
            windows.append({
                slice_insns[j].address
                for j in range(max(0, i - before), min(len(slice_insns), i + after + 1))
            })
    if not windows:
        return set()
    freq: Counter[int] = Counter()
    for w in windows:
        freq.update(w)
    thresh = max(1, (len(windows) + 1) // 2)
    return {a for a, f in freq.items() if f >= thresh}


def _is_indirect_target(operands: str) -> bool:
    """True if a branch operand is a register or memory ref (not a literal)."""
    op = operands.strip().lower()
    if not op:
        return False
    if "[" in op:                       # jmp [table+idx*8]
        return True
    # A bare register operand (jmp rax) — not a numeric/label target.
    first = op.split(",")[0].split()[-1] if op.split() else ""
    return first.isalpha() and not first.startswith("0x")


def _mnem_ops(ti: Any) -> tuple[str, str]:
    """Return ``(mnemonic, operands)`` for a trace/lifted instruction.

    Handles both ``LiftedInstruction`` (``.mnemonic``/``.operands``) and
    ``TraceInstruction`` (only ``.disassembly``).
    """
    mnem = getattr(ti, "mnemonic", "") or ""
    ops = getattr(ti, "operands", "") or ""
    if not mnem:
        parts = str(getattr(ti, "disassembly", "")).strip().split(None, 1)
        mnem = parts[0] if parts else ""
        ops = parts[1] if len(parts) > 1 else ""
    return mnem.lower(), ops


def localized_outer_dispatch(trace: Any) -> list[int]:
    """Return only the *outermost* interpreter's fetch/dispatch block.

    For segmenting the top-level VM, the dispatcher set must contain just the
    outer dispatch loop — not every hot loop in the trace.  A naive global
    hot-address set also includes inner (nested) dispatchers and would flatten
    the nesting.  The outermost dispatcher is the repeatedly-executed indirect
    dispatch site that runs *first* (entered before any nested layer); for a
    purely ``cmp/je`` interpreter (no indirect dispatch) we fall back to the
    global hot loop, which is the dispatch chain itself.
    """
    insns = getattr(trace, "instructions", None) or []
    if len(insns) < 8:
        return []
    counts: Counter[int] = Counter()
    first_seen: dict[int, int] = {}
    for i, ti in enumerate(insns):
        mnem, ops = _mnem_ops(ti)
        if mnem in ("ret", "retn") or (
            mnem in ("jmp", "call") and _is_indirect_target(ops)
        ):
            counts[ti.address] += 1
            first_seen.setdefault(ti.address, i)
    repeated = [a for a, c in counts.items() if c >= 2]
    if repeated:
        outer_site = min(repeated, key=lambda a: first_seen[a])
        return sorted(_localize_dispatch_loop(insns, outer_site))
    addr_counts = Counter(ti.address for ti in insns)
    max_c = max(addr_counts.values())
    return sorted(a for a, c in addr_counts.items() if c >= max(2, int(max_c * 0.5)))


def analyse_vm_structure(trace: Any) -> dict[str, Any]:
    """Score how strongly *trace* exhibits VM-interpreter structure.

    Returns a dict with ``is_vm``, ``confidence`` (0..1), and the supporting
    structural evidence.  Works on any architecture/protector.
    """
    report: dict[str, Any] = {
        "is_vm": False,
        "confidence": 0.0,
        "dispatch_loop": False,
        "indirect_dispatch": False,
        "threaded_dispatch": False,
        "vip_register": None,
        "estimated_handlers": 0,
        "loop_addresses": [],
        "evidence": [],
    }
    insns = getattr(trace, "instructions", None) or []
    n = len(insns)
    if n < 8:
        return report

    counts = Counter(ti.address for ti in insns)
    max_c = max(counts.values())
    unique = len(counts)

    # Dispatch loop: a small set of hot addresses carrying most of execution.
    loop = {a for a, c in counts.items() if c >= max(2, int(max_c * 0.5))}
    loop_density = sum(counts[a] for a in loop) / n
    has_loop = (
        max_c >= 3
        and len(loop) <= max(2, int(0.4 * unique))
        and loop_density >= 0.30
    )

    # Indirect dispatch sites across the whole trace (jmp/call through a
    # register or table, or a ret-trampoline), with their execution counts.
    disp_counts: Counter[int] = Counter()
    for ti in insns:
        mnem, ops = _mnem_ops(ti)
        if mnem in ("ret", "retn") or (
            mnem in ("jmp", "call") and _is_indirect_target(ops)
        ):
            disp_counts[ti.address] += 1
    indirect_sites = set(disp_counts)
    indirect_in_loop = any(a in loop for a in indirect_sites)

    # A *repeatedly executed* indirect dispatch site is a real dispatcher even
    # when a hotter, unrelated loop (classically a startup decrypt/init loop)
    # dominates the trace and masks it.  When that hottest dispatcher is not
    # part of the globally-hottest loop, relocate the dispatch loop around it
    # so indirect_dispatch / estimated_handlers / loop_addresses reflect the
    # true interpreter rather than the decryptor.
    dsite, dhits = disp_counts.most_common(1)[0] if disp_counts else (None, 0)
    has_repeated_dispatcher = dhits >= 3
    masked = has_repeated_dispatcher and dsite is not None and dsite not in loop
    dispatch_block = _localize_dispatch_loop(insns, dsite) if masked else set()

    # Monotonic virtual instruction pointer walking a bytecode stream.  Prefer
    # the relocated dispatch block (the genuine fetch/decode site) when masked.
    vip = identify_vip_register(trace, list(dispatch_block or loop))
    has_vip = vip is not None and getattr(vip, "monotonic_ratio", 0.0) >= 0.6

    # Direct-threaded dispatch: the fetch/decode/dispatch is *inlined* at the
    # end of every handler, so no single address dominates the trace (no tight
    # loop) — but a monotonic vIP is still threaded through several distinct
    # indirect-dispatch sites.  This is the classic defeat of hot-loop
    # heuristics; the monotonic-vIP requirement guards against mistaking
    # ordinary indirect-call-heavy code (no walking pointer) for a VM.
    threaded = (
        not has_loop
        and not dispatch_block
        and has_vip
        and len(indirect_sites) >= 2
    )

    indirect = indirect_in_loop or threaded or (masked and bool(dispatch_block))

    evidence: list[str] = []
    score = 0.0
    if has_loop:
        score += 0.40
        evidence.append(
            f"tight dispatch loop ({len(loop)} addrs, {loop_density:.0%} of trace)"
        )
    elif threaded:
        score += 0.30
        evidence.append(
            f"direct-threaded dispatch ({len(indirect_sites)} inline sites)"
        )
    if dispatch_block:
        evidence.append(
            f"dispatcher relocated past hot init/decrypt loop "
            f"({len(dispatch_block)} addrs, {dhits} dispatches)"
        )
    if has_vip and vip is not None:
        score += 0.35
        evidence.append(f"monotonic vIP={vip.name} (ratio={vip.monotonic_ratio:.2f})")
    if indirect:
        score += 0.25
        evidence.append("indirect/handler-table dispatch")

    if dispatch_block:
        est_handlers = dhits
        loop_report = sorted(dispatch_block)[:16]
    elif has_loop:
        est_handlers = max_c
        loop_report = sorted(loop)[:16]
    elif threaded:
        est_handlers = len(indirect_sites)
        loop_report = sorted(indirect_sites)[:16]
    else:
        est_handlers = 0
        loop_report = []

    report.update(
        is_vm=score >= 0.50,
        confidence=round(min(score, 1.0), 3),
        dispatch_loop=has_loop or bool(dispatch_block),
        indirect_dispatch=indirect,
        threaded_dispatch=threaded,
        vip_register=vip.name if vip else None,
        estimated_handlers=est_handlers,
        loop_addresses=loop_report,
        evidence=evidence,
    )
    return report


def _localize_dispatch_loop(
    instructions: list[Any], dispatch_addr: int | None, *, window: int = 3
) -> set[int]:
    """Localise the fetch/decode/dispatch block around *dispatch_addr*.

    Returns the addresses that appear in a majority of the short instruction
    windows ending at each execution of the dispatch site — i.e. the invariant
    fetch/decode instructions that run every iteration — excluding the varying
    handler tails.  Used to recover the real dispatcher when a hotter,
    unrelated loop (e.g. a startup decryptor) dominates the trace.
    """
    if dispatch_addr is None:
        return set()
    windows: list[set[int]] = []
    for i, ti in enumerate(instructions):
        if ti.address == dispatch_addr:
            windows.append(
                {instructions[j].address for j in range(max(0, i - window), i + 1)}
            )
    if not windows:
        return set()
    freq: Counter[int] = Counter()
    for w in windows:
        freq.update(w)
    thresh = max(1, (len(windows) + 1) // 2)
    return {a for a, f in freq.items() if f >= thresh}


@dataclass
class NestedVM:
    """A nested (inner) VM discovered *inside* an outer handler slice.

    Real protectors (notably Themida/WinLicense) virtualise code with more
    than one interpreter layer: an outer handler does not perform an
    arithmetic op, it *enters another VM*.  A single-vIP model collapses
    that inner interpreter into one opaque handler and mislabels it.  This
    record marks a handler slice that is itself a VM so the pipeline can
    recurse into it.
    """

    outer_handler_address: int
    trace_start: int
    trace_end: int
    vip_register: str
    dispatch_addresses: tuple[int, ...] = ()
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)


def find_nested_vms(
    trace: Any,
    boundaries: Any,
    outer_vip_register: str | None,
    *,
    min_slice_insns: int = 8,
) -> list[NestedVM]:
    """Detect nested VMs by asking of each handler slice: *is this a VM?*

    For every outer handler boundary, the corresponding trace slice is run
    back through :func:`analyse_vm_structure`.  A slice that exhibits its
    own dispatch loop **and** a monotonic vIP in a register *different* from
    the outer vIP is a nested interpreter — regardless of its dispatch shape
    (``cmp/je`` chain, jump table or ``ret``-trampoline).  This is purely
    structural, so it fires even when the outer handler was mislabelled
    (e.g. as ``vm_cmp``) by opcode classification.

    Args:
        trace: The full execution trace (needs ``.instructions``).
        boundaries: Outer handler boundaries from :func:`segment_trace`.
        outer_vip_register: Name of the outer vIP, to require a *distinct*
            inner vIP (a real second interpreter, not the same loop).
        min_slice_insns: Minimum slice length to bother analysing
            (``analyse_vm_structure`` itself needs at least 8 instructions).

    Returns:
        A list of :class:`NestedVM`, one per handler slice that is itself a
        VM, in trace order.
    """
    from ..trace_ingestion import ExecutionTrace

    insns = getattr(trace, "instructions", None) or []
    nested: list[NestedVM] = []
    outer = (outer_vip_register or "").lower()

    for b in boundaries:
        start = getattr(b, "trace_start", None)
        end = getattr(b, "trace_end", None)
        if start is None or end is None:
            continue
        slice_insns = insns[start:end]
        if len(slice_insns) < min_slice_insns:
            continue

        sub = ExecutionTrace(instructions=list(slice_insns))
        report = analyse_vm_structure(sub)
        if not report.get("is_vm"):
            continue

        # Prefer the *enclosing* nested dispatcher (widest-span fetch pointer)
        # so multi-layer slices peel outer-first; deeper layers are recovered
        # by recursion.  Fall back to the structural single answer.
        enclosing = _enclosing_nested_vip(slice_insns, outer)
        if enclosing is not None:
            inner_vip, disp_addrs = enclosing
        else:
            inner_vip = (report.get("vip_register") or "").lower()
            disp_addrs = tuple(report.get("loop_addresses", ()))

        # A genuine nested VM: the slice is a VM in its own right and its
        # vIP is a *different* register than the enclosing interpreter's.
        if inner_vip and inner_vip != outer:
            nested.append(NestedVM(
                outer_handler_address=int(getattr(b, "handler_address", 0)),
                trace_start=int(start),
                trace_end=int(end),
                vip_register=inner_vip,
                dispatch_addresses=disp_addrs,
                confidence=float(report.get("confidence", 0.0)),
                evidence=list(report.get("evidence", [])),
            ))
    return nested
