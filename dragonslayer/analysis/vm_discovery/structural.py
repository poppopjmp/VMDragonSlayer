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

from collections import Counter
from typing import Any

from .handler_boundaries import identify_vip_register


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

    # Indirect dispatch executed from within the loop.
    indirect = False
    for ti in insns:
        if ti.address not in loop:
            continue
        mnem, ops = _mnem_ops(ti)
        if mnem in ("ret", "retn"):
            indirect = True
            break
        if mnem in ("jmp", "call") and _is_indirect_target(ops):
            indirect = True
            break

    # Monotonic virtual instruction pointer walking a bytecode stream.
    vip = identify_vip_register(trace, list(loop))
    has_vip = vip is not None and getattr(vip, "monotonic_ratio", 0.0) >= 0.6

    evidence: list[str] = []
    score = 0.0
    if has_loop:
        score += 0.40
        evidence.append(
            f"tight dispatch loop ({len(loop)} addrs, {loop_density:.0%} of trace)"
        )
    if has_vip and vip is not None:
        score += 0.35
        evidence.append(f"monotonic vIP={vip.name} (ratio={vip.monotonic_ratio:.2f})")
    if indirect:
        score += 0.25
        evidence.append("indirect/handler-table dispatch")

    report.update(
        is_vm=score >= 0.50,
        confidence=round(min(score, 1.0), 3),
        dispatch_loop=has_loop,
        indirect_dispatch=indirect,
        vip_register=vip.name if vip else None,
        estimated_handlers=max_c if has_loop else 0,
        loop_addresses=sorted(loop)[:16],
        evidence=evidence,
    )
    return report
