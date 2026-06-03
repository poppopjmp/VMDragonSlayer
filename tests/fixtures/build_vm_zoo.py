#!/usr/bin/env python3
"""A *zoo* of compiled bytecode-VM ELFs that push structural VM detection.

Each builder returns ``(elf_bytes, metadata)`` for a genuine, executable
x86-64 interpreter exercising a different *structural* dimension that the
detector (:func:`analyse_vm_structure`) and the VMProtect dispatcher finder
(:func:`find_dispatcher_in_trace`) must cope with:

* ``build_ret_trampoline`` — dispatch via ``push <handler>; ret`` (no jmp).
* ``build_call_table``      — dispatch via ``call [table + op*8]``; handlers ret.
* ``build_stack_vm``        — stack-based VM with a competing monotonic
                              pointer (vSP) racing the real vIP.
* ``build_threaded``        — *direct-threaded* code: the fetch/dispatch is
                              inlined at the end of every handler, so there is
                              no single hot dispatch address (the classic
                              defeat of "tight dispatch loop" heuristics).
* ``build_wide_opcode``     — 12-opcode register VM (scale / many handlers).

None are real protectors or malware — they are hand-written interpreters.
All use the same toy program shape so results are comparable:
``(10 + 5) ^ 3 = 12`` (accumulator) unless noted.
"""
from __future__ import annotations

import struct
from pathlib import Path

BASE = 0x400000
EHDR = 64
PHDR = 56
CODE_VADDR = BASE + EHDR + PHDR


def _wrap_elf(asm: str, *, extra_memsz: int = 0x2000) -> tuple[bytes, int]:
    """Assemble *asm* at ``CODE_VADDR`` and wrap it in a minimal PT_LOAD ELF.

    Returns ``(elf_bytes, code_len)``.
    """
    from keystone import KS_ARCH_X86, KS_MODE_64, Ks

    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    enc, _ = ks.asm(asm, CODE_VADDR)
    code = bytes(enc)
    total = EHDR + PHDR + len(code)

    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2, 62, 1, CODE_VADDR, EHDR, 0, 0, EHDR, PHDR, 1, 0, 0, 0,
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1, 7, 0, BASE, BASE, total, total + extra_memsz, 0x1000,
    )
    return ehdr + phdr + code, len(code)


_ACC_BC = """
bc:
    .byte 1
    .long 10
    .byte 2
    .long 5
    .byte 3
    .long 3
    .byte 0
"""


def _meta(code_len: int, *, expected: int = (10 + 5) ^ 3, **extra: object) -> dict:
    m = {
        "base": BASE,
        "entry_va": CODE_VADDR,
        "code_len": code_len,
        "expected_result": expected,
    }
    m.update(extra)
    return m


# ---------------------------------------------------------------------------
# 1. ret-trampoline dispatch  (push <handler>; ret)
# ---------------------------------------------------------------------------
def build_ret_trampoline() -> tuple[bytes, dict]:
    asm = """
_start:
    lea rsi, [rip + bc]
    lea r10, [rip + tbl]
oloop:
    movzx eax, byte ptr [rsi]
    inc rsi
    mov rdx, qword ptr [r10 + rax*8]
    push rdx
    ret
h_halt:
    hlt
h_load:
    mov ebx, dword ptr [rsi]
    add rsi, 4
    jmp oloop
h_add:
    add ebx, dword ptr [rsi]
    add rsi, 4
    jmp oloop
h_xor:
    xor ebx, dword ptr [rsi]
    add rsi, 4
    jmp oloop
tbl:
    .quad h_halt
    .quad h_load
    .quad h_add
    .quad h_xor
""" + _ACC_BC
    elf, n = _wrap_elf(asm)
    return elf, _meta(n, dispatch_style="ret_trampoline")


# ---------------------------------------------------------------------------
# 2. call-table dispatch  (call [table + op*8]; handlers ret)
# ---------------------------------------------------------------------------
def build_call_table() -> tuple[bytes, dict]:
    asm = """
_start:
    lea rsi, [rip + bc]
    lea r10, [rip + tbl]
oloop:
    movzx eax, byte ptr [rsi]
    inc rsi
    test eax, eax
    jz odone
    call qword ptr [r10 + rax*8]
    jmp oloop
odone:
    hlt
h_load:
    mov ebx, dword ptr [rsi]
    add rsi, 4
    ret
h_add:
    add ebx, dword ptr [rsi]
    add rsi, 4
    ret
h_xor:
    xor ebx, dword ptr [rsi]
    add rsi, 4
    ret
tbl:
    .quad 0
    .quad h_load
    .quad h_add
    .quad h_xor
""" + _ACC_BC
    elf, n = _wrap_elf(asm)
    return elf, _meta(n, dispatch_style="call_table")


# ---------------------------------------------------------------------------
# 3. stack-based VM  (virtual stack; vSP competes with vIP)
# ---------------------------------------------------------------------------
def build_stack_vm() -> tuple[bytes, dict]:
    # rsi = vIP, r11 = vSP (into vstack), opcodes:
    #   0 HALT ; 1 PUSH imm32 ; 2 ADD ; 3 XOR
    # program: PUSH 10 ; PUSH 5 ; ADD ; PUSH 3 ; XOR ; HALT  -> top = 12
    asm = """
_start:
    lea rsi, [rip + bc]
    lea r10, [rip + tbl]
    lea r11, [rip + vstack]
oloop:
    movzx eax, byte ptr [rsi]
    inc rsi
    jmp qword ptr [r10 + rax*8]
h_halt:
    mov ebx, dword ptr [r11 - 8]
    hlt
h_push:
    mov eax, dword ptr [rsi]
    add rsi, 4
    mov qword ptr [r11], rax
    add r11, 8
    jmp oloop
h_add:
    sub r11, 8
    mov rax, qword ptr [r11]
    sub r11, 8
    mov rdx, qword ptr [r11]
    add rdx, rax
    mov qword ptr [r11], rdx
    add r11, 8
    jmp oloop
h_xor:
    sub r11, 8
    mov rax, qword ptr [r11]
    sub r11, 8
    mov rdx, qword ptr [r11]
    xor rdx, rax
    mov qword ptr [r11], rdx
    add r11, 8
    jmp oloop
tbl:
    .quad h_halt
    .quad h_push
    .quad h_add
    .quad h_xor
bc:
    .byte 1
    .long 10
    .byte 1
    .long 5
    .byte 2
    .byte 1
    .long 3
    .byte 3
    .byte 0
vstack:
    .zero 128
"""
    elf, n = _wrap_elf(asm)
    return elf, _meta(n, dispatch_style="jump_table", vm_kind="stack")


# ---------------------------------------------------------------------------
# 4. direct-threaded code  (dispatch inlined into every handler)
# ---------------------------------------------------------------------------
def build_threaded() -> tuple[bytes, dict]:
    # No central dispatch loop: each handler ends with its own
    # fetch+inc+indirect-jmp, so the dispatch site differs per handler and
    # no single address dominates the trace.
    disp = (
        "    movzx eax, byte ptr [rsi]\n"
        "    inc rsi\n"
        "    jmp qword ptr [r10 + rax*8]\n"
    )
    asm = f"""
_start:
    lea rsi, [rip + bc]
    lea r10, [rip + tbl]
{disp}
h_halt:
    hlt
h_load:
    mov ebx, dword ptr [rsi]
    add rsi, 4
{disp}
h_add:
    add ebx, dword ptr [rsi]
    add rsi, 4
{disp}
h_xor:
    xor ebx, dword ptr [rsi]
    add rsi, 4
{disp}
tbl:
    .quad h_halt
    .quad h_load
    .quad h_add
    .quad h_xor
""" + _ACC_BC
    elf, n = _wrap_elf(asm)
    return elf, _meta(n, dispatch_style="direct_threaded")


# ---------------------------------------------------------------------------
# 5. wide opcode set  (12 handlers; scale)
# ---------------------------------------------------------------------------
def build_wide_opcode() -> tuple[bytes, dict]:
    # 12 opcodes (0 HALT + 11 arithmetic), jump-table dispatch.  Program
    # exercises a spread of them.  Each handler: <op> ebx,[rsi]; add rsi,4.
    ops = [
        ("h_load", "mov ebx, dword ptr [rsi]"),
        ("h_add",  "add ebx, dword ptr [rsi]"),
        ("h_sub",  "sub ebx, dword ptr [rsi]"),
        ("h_xor",  "xor ebx, dword ptr [rsi]"),
        ("h_or",   "or ebx, dword ptr [rsi]"),
        ("h_and",  "and ebx, dword ptr [rsi]"),
        ("h_imul", "imul ebx, dword ptr [rsi]"),
        ("h_shl",  "shl ebx, 1"),
        ("h_shr",  "shr ebx, 1"),
        ("h_inc",  "inc ebx"),
        ("h_neg",  "neg ebx"),
    ]
    body = []
    for label, insn in ops:
        # shl/shr/inc/neg take no imm; load/add/sub/xor/or/and/imul read imm32.
        reads_imm = "[rsi]" in insn
        body.append(f"{label}:\n    {insn}\n")
        if reads_imm:
            body.append("    add rsi, 4\n")
        body.append("    jmp oloop\n")
    handlers = "".join(body)
    table = "    .quad h_halt\n" + "".join(f"    .quad {lab}\n" for lab, _ in ops)
    # program: LOAD 10; ADD 5; SUB 2; XOR 3; OR 8; AND 0x0E; IMUL 3; SHL; INC; NEG; HALT
    prog = (
        b"\x01" + struct.pack("<i", 10)
        + b"\x02" + struct.pack("<i", 5)
        + b"\x03" + struct.pack("<i", 2)
        + b"\x04" + struct.pack("<i", 3)
        + b"\x05" + struct.pack("<i", 8)
        + b"\x06" + struct.pack("<i", 0x0E)
        + b"\x07" + struct.pack("<i", 3)
        + b"\x08"
        + b"\x09"
        + b"\x0a"
        + b"\x00"
    )
    bc_lines = "bc:\n" + "".join(f"    .byte {b}\n" for b in prog)
    asm = f"""
_start:
    lea rsi, [rip + bc]
    lea r10, [rip + tbl]
oloop:
    movzx eax, byte ptr [rsi]
    inc rsi
    jmp qword ptr [r10 + rax*8]
h_halt:
    hlt
{handlers}
tbl:
{table}
{bc_lines}
"""
    elf, n = _wrap_elf(asm)
    return elf, _meta(n, expected=None, dispatch_style="jump_table", opcode_count=12)


_ALL = {
    "ret_trampoline": build_ret_trampoline,
    "call_table": build_call_table,
    "stack_vm": build_stack_vm,
    "threaded": build_threaded,
    "wide_opcode": build_wide_opcode,
}


if __name__ == "__main__":
    out_dir = Path(__file__).parent
    for name, fn in _ALL.items():
        elf, meta = fn()
        path = out_dir / f"vm_zoo_{name}.elf"
        path.write_bytes(elf)
        print(f"wrote {path.name} ({len(elf)} bytes)  meta={meta}")
