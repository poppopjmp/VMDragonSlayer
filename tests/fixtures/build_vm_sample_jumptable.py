#!/usr/bin/env python3
"""Generate a valid x86-64 ELF whose VM uses a **jump-table dispatcher**.

Companion to ``build_vm_sample.py`` (which uses a cmp/je dispatch chain).
A jump-table dispatch (``jmp [table + opcode*8]``) is the canonical VM
shape that VMDragonSlayer's dispatcher heuristics target, so this fixture
exercises the ``find_dispatcher`` detection path.

Not a real protector / not malware — a hand-laid-out bytecode interpreter.

VM model:  rsi = vIP, r10 = handler-table base, ebx = accumulator.
opcodes:   0 HALT ; 1 LOAD imm32 ; 2 ADD imm32 ; 3 XOR imm32
bytecode:  LOAD 10 ; ADD 5 ; XOR 3 ; HALT   =>  (10 + 5) ^ 3 = 12
"""
from __future__ import annotations

import struct
from pathlib import Path

BASE = 0x400000
EHDR = 64
PHDR = 56
CODE_VADDR = BASE + EHDR + PHDR

# Each item: (label, kind, payload)
#   kind "b": literal bytes (fixed-size instruction)
#   kind "lea": 3 prefix bytes + rip-relative disp32 to <target label>
#   kind "jz8": 0x74 + rel8 to <target>
#   kind "jmp32": 0xE9 + rel32 to <target>
#   kind "qword": 8-byte absolute VA of <target label> (0 if target is None)
#   kind "data": literal data bytes
_ITEMS = [
    ("_start", "lea", (b"\x48\x8d\x35", "bytecode")),   # lea rsi,[rip+bytecode]
    (None,     "lea", (b"\x4c\x8d\x15", "htable")),      # lea r10,[rip+htable]
    ("loop",   "b",   b"\x0f\xb6\x06"),                   # movzx eax,byte[rsi]
    (None,     "b",   b"\x48\xff\xc6"),                   # inc rsi
    (None,     "b",   b"\x85\xc0"),                       # test eax,eax
    (None,     "jz8", "done"),                            # jz done
    (None,     "b",   b"\x41\xff\x24\xc2"),               # jmp [r10+rax*8]
    ("h_load", "b",   b"\x8b\x1e"),                       # mov ebx,[rsi]
    (None,     "b",   b"\x48\x83\xc6\x04"),               # add rsi,4
    (None,     "jmp32", "loop"),                          # jmp loop
    ("h_add",  "b",   b"\x03\x1e"),                       # add ebx,[rsi]
    (None,     "b",   b"\x48\x83\xc6\x04"),               # add rsi,4
    (None,     "jmp32", "loop"),                          # jmp loop
    ("h_xor",  "b",   b"\x33\x1e"),                       # xor ebx,[rsi]
    (None,     "b",   b"\x48\x83\xc6\x04"),               # add rsi,4
    (None,     "jmp32", "loop"),                          # jmp loop
    ("done",   "b",   b"\xf4"),                            # hlt
    ("htable", "qword", None),                            # opcode 0 (unused)
    (None,     "qword", "h_load"),                        # opcode 1
    (None,     "qword", "h_add"),                         # opcode 2
    (None,     "qword", "h_xor"),                         # opcode 3
    ("bytecode", "data",
     b"\x01" + struct.pack("<i", 10)
     + b"\x02" + struct.pack("<i", 5)
     + b"\x03" + struct.pack("<i", 3)
     + b"\x00"),
]

_SIZES = {"lea": 7, "jz8": 2, "jmp32": 5, "qword": 8}


def _item_size(kind: str, payload) -> int:
    if kind == "b":
        return len(payload)
    if kind == "data":
        return len(payload)
    return _SIZES[kind]


def build() -> tuple[bytes, dict]:
    # Pass 1: assign offsets and record label positions.
    labels: dict[str, int] = {}
    off = 0
    for label, kind, payload in _ITEMS:
        if label:
            labels[label] = off
        off += _item_size(kind, payload)

    # Pass 2: emit bytes, resolving relocations.
    code = bytearray()
    for _label, kind, payload in _ITEMS:
        pos = len(code)
        if kind == "b" or kind == "data":
            code += payload
        elif kind == "lea":
            prefix, target = payload
            disp = labels[target] - (pos + 7)
            code += prefix + struct.pack("<i", disp)
        elif kind == "jz8":
            disp = labels[payload] - (pos + 2)
            code += b"\x74" + struct.pack("<b", disp)
        elif kind == "jmp32":
            disp = labels[payload] - (pos + 5)
            code += b"\xe9" + struct.pack("<i", disp)
        elif kind == "qword":
            va = (CODE_VADDR + labels[payload]) if payload else 0
            code += struct.pack("<Q", va)

    payload = bytes(code)
    total = EHDR + PHDR + len(payload)
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2, 62, 1, CODE_VADDR, EHDR, 0, 0, EHDR, PHDR, 1, 0, 0, 0,
    )
    phdr = struct.pack(
        "<IIQQQQQQ", 1, 7, 0, BASE, BASE, total, total + 0x1000, 0x1000,
    )
    elf = ehdr + phdr + payload
    meta = {
        "base": BASE,
        "entry_va": CODE_VADDR,
        "dispatch_va": CODE_VADDR + labels["loop"],
        "htable_va": CODE_VADDR + labels["htable"],
        "bytecode_va": CODE_VADDR + labels["bytecode"],
        "expected_result": (10 + 5) ^ 3,
    }
    return elf, meta


if __name__ == "__main__":
    elf, meta = build()
    out = Path(__file__).with_name("vm_sample_jumptable.elf")
    out.write_bytes(elf)
    print(f"wrote {out} ({len(elf)} bytes)")
    print(f"metadata: {meta}")
