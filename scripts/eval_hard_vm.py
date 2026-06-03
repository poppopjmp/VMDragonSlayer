#!/usr/bin/env python3
"""Honest capability probe: run the *unmodified* devirtualization pipeline
against the hard nested/mutated/opaque-predicate VM sample and report,
without sugar-coating, what it recovers and where it breaks.

Usage:  python scripts/eval_hard_vm.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.fixtures.build_vm_sample_hard import build  # noqa: E402


def _line(c="-", n=72):
    print(c * n)


def main() -> int:
    from dragonslayer.analysis.trace_engine import (
        UNICORN_AVAILABLE,
        TraceConfig,
        TraceEngine,
    )

    if not UNICORN_AVAILABLE:
        print("unicorn not available; cannot run")
        return 2

    elf, meta = build()
    print("HARD VM SAMPLE — ground truth")
    _line()
    print(f"  entry_va           = {meta['entry_va']:#x}")
    print(f"  outer dispatch_va  = {meta['dispatch_va']:#x}  (jump-table)")
    print(f"  outer bytecode_va  = {meta['outer_bytecode_va']:#x}")
    print(f"  inner bytecode_va  = {meta['inner_bytecode_va']:#x}")
    print(f"  expected acc (ebx) = {meta['expected_result']}")
    print("  outer program: LOAD 10; ADD 5; XOR 3; ADD2 7; VMCALL; HALT")
    print("  inner program: ILOAD 4; IMUL 6; IRET   (=> 24)")
    print("  ground-truth distinct VM ops: LOAD, ADD, XOR, ADD(dup), VMCALL/nested, MUL")
    print()

    # ---- 1. Does the engine actually run this VM to the right answer? ----
    engine = TraceEngine(arch="x86_64", config=TraceConfig(max_instructions=4000))
    trace = engine.trace(elf, entry_va=meta["entry_va"], image_base=meta["base"])
    regs_final = trace.instructions[-1].registers if trace.instructions else {}
    ebx = regs_final.get("ebx", regs_final.get("rbx"))
    if isinstance(ebx, int):
        ebx &= 0xFFFFFFFF
    print("STEP 1 — Unicorn execution (is the sample a valid program?)")
    _line()
    print(f"  trace length        = {len(trace.instructions)} instructions")
    print(f"  final ebx (acc)     = {ebx}   (expected {meta['expected_result']})")
    print(f"  VALID PROGRAM       = {ebx == meta['expected_result']}")
    print()

    mnems = [ti.disassembly.split()[0] for ti in trace.instructions if ti.disassembly]
    from collections import Counter
    print("  mnemonic histogram :", dict(Counter(mnems)))
    print()

    # ---- 2. Dispatcher discovery (no ground truth fed in) ----
    print("STEP 2 — Dispatcher discovery (find_dispatcher_in_trace)")
    _line()
    from dragonslayer.analysis.vm_discovery.dispatcher import find_dispatcher_in_trace

    records = [ti.to_dict() if hasattr(ti, "to_dict") else {
        "address": ti.address, "disassembly": ti.disassembly,
        "registers": ti.registers,
    } for ti in trace.instructions]
    match = find_dispatcher_in_trace(records, bit_width=64)
    disp_addrs: tuple[int, ...] = ()
    if match is None:
        print("  RESULT: no dispatcher found")
    else:
        entry = match.entry_address
        ijmp = match.indirect_jump_address
        print(f"  dispatcher entry    = {entry:#x}  (indirect jmp @ {ijmp:#x})")
        print(f"  ground-truth outer  = {meta['dispatch_va']:#x}")
        print(f"  CORRECT OUTER DISP  = {entry == meta['dispatch_va']}")
        print(f"  vip/fetch/scale/delta = {match.vip_register}/{match.fetch_register}/{match.table_scale}/{match.vip_delta}")
        print(f"  handler_addresses   = {[hex(h) for h in match.handler_addresses]}")
        # The dispatcher is the contiguous instruction block from the opcode
        # fetch through the indirect jump; feed the whole block to segmentation
        # (as the orchestrator does), not just the entry address.
        lo, hi = min(entry, ijmp), max(entry, ijmp)
        disp_addrs = tuple(sorted({
            ti.address for ti in trace.instructions if lo <= ti.address <= hi
        }))
        print(f"  dispatcher block    = {[hex(a) for a in disp_addrs]}")
    print()

    # ---- 3. Structural (protector-agnostic) detection ----
    print("STEP 3 — Structural VM detection (analyse_vm_structure)")
    _line()
    from dragonslayer.analysis.vm_discovery.structural import analyse_vm_structure

    struct_res = analyse_vm_structure(trace)
    for k, v in struct_res.items():
        print(f"  {k} = {v}")
    print()

    # ---- 4. vIP identification ----
    print("STEP 4 — vIP identification (identify_vip_register)")
    _line()
    from dragonslayer.analysis.vm_discovery.handler_boundaries import (
        identify_vip_register,
        segment_trace,
    )

    vip = identify_vip_register(trace, disp_addrs or (meta["dispatch_va"],))
    if vip is None:
        print("  RESULT: no vIP found")
        return 0
    print(f"  vIP register        = {vip.name}  (ground truth outer vIP = rsi)")
    print(f"  monotonic_ratio     = {getattr(vip, 'monotonic_ratio', '?')}")
    print(f"  NOTE: inner VM uses a *second* vIP (rdi) — single-vIP model can't represent both")
    print()

    # ---- 5. Handler segmentation + semantic classification ----
    print("STEP 5 — Segmentation + semantic classification")
    _line()
    seg = segment_trace(trace, vip, disp_addrs or (meta["dispatch_va"],))
    print(f"  handler slices      = {len(seg.boundaries)}")

    from dragonslayer.analysis.handler_semantics import analyse_handler_semantics
    table = analyse_handler_semantics(
        trace, seg.boundaries,
        vip_register=vip.name,
        dispatcher_addresses=tuple(disp_addrs or (meta["dispatch_va"],)),
    )
    print(f"  classified opcodes  = {len(table.entries)}")
    ops = []
    for e in table.entries:
        op = e.semantic.operation
        conf = getattr(e.semantic, "confidence", None)
        ops.append(op)
        addr = getattr(e, "handler_address", None)
        astr = f"{addr:#x}" if isinstance(addr, int) else str(addr)
        print(f"    handler @ {astr:>12} -> {op!r:>14}  conf={conf}")
    print()
    print(f"  distinct recovered ops = {sorted(set(ops))}")
    print()

    # ---- 6. Pseudocode emission ----
    print("STEP 6 — Pseudocode emission (emit_linear)")
    _line()
    from dragonslayer.analysis.pseudocode import emit_linear
    result = emit_linear(table, seg.boundaries)
    print(result.text)
    print()
    print(f"  pseudocode lines    = {result.line_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
