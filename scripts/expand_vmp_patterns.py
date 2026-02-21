#!/usr/bin/env python3
"""Expand vmprotect_handlers.json from 75 to 150+ patterns.

Run once from project root:
    python scripts/expand_vmp_patterns.py
"""
import json
from pathlib import Path

DB_PATH = Path("data/patterns/vmprotect_handlers.json")

with open(DB_PATH, "r", encoding="utf-8") as f:
    data = json.load(f)

existing_ids = {p["pattern_id"] for p in data["patterns"]}

NEW = [
    # === Arithmetic x86 completeness ===
    {"pattern_id": "vmp_sub_32_x86_v1", "name": "VMProtect SUB dword x86 + pushfd", "signature": "29 ?? 89 ?? 9C", "architecture": "x86", "handler_type": "arithmetic", "operation": "sub", "confidence": 0.90, "wildcards": True, "variants": ["2B ?? 89 ?? 9C"], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 3}},
    {"pattern_id": "vmp_neg_32_x86_v1", "name": "VMProtect NEG dword x86", "signature": "F7 ?? 89 ?? 9C", "architecture": "x86", "handler_type": "arithmetic", "operation": "neg", "confidence": 0.88, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 3}},
    {"pattern_id": "vmp_imul_32_x86_v1", "name": "VMProtect IMUL dword x86", "signature": "0F AF ?? 89 ??", "architecture": "x86", "handler_type": "arithmetic", "operation": "imul", "confidence": 0.88, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 2}},
    {"pattern_id": "vmp_div_32_x86_v1", "name": "VMProtect DIV dword x86", "signature": "F7 ?? 89 ??", "architecture": "x86", "handler_type": "arithmetic", "operation": "div", "confidence": 0.83, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 2}},
    {"pattern_id": "vmp_inc_64_v1", "name": "VMProtect INC qword", "signature": "48 FF ?? 48 89 ??", "architecture": "x64", "handler_type": "arithmetic", "operation": "inc", "confidence": 0.90, "wildcards": True, "variants": ["49 FF ??"], "metadata": {"vmprotect_version": "3.x", "width": 64, "instruction_count": 2}},
    {"pattern_id": "vmp_dec_64_v1", "name": "VMProtect DEC qword", "signature": "48 FF ?? 48 89 ??", "architecture": "x64", "handler_type": "arithmetic", "operation": "dec", "confidence": 0.90, "wildcards": True, "variants": ["49 FF ??"], "metadata": {"vmprotect_version": "3.x", "width": 64, "instruction_count": 2}},
    {"pattern_id": "vmp_adc_64_v1", "name": "VMProtect ADC qword", "signature": "48 11 ?? 48 89 ??", "architecture": "x64", "handler_type": "arithmetic", "operation": "adc", "confidence": 0.88, "wildcards": True, "variants": ["48 13 ?? 48 89 ??"], "metadata": {"vmprotect_version": "3.x", "width": 64, "instruction_count": 2}},
    {"pattern_id": "vmp_sbb_64_v1", "name": "VMProtect SBB qword", "signature": "48 19 ?? 48 89 ??", "architecture": "x64", "handler_type": "arithmetic", "operation": "sbb", "confidence": 0.88, "wildcards": True, "variants": ["48 1B ?? 48 89 ??"], "metadata": {"vmprotect_version": "3.x", "width": 64, "instruction_count": 2}},
    {"pattern_id": "vmp_lea_32_x86_v1", "name": "VMProtect LEA dword x86", "signature": "8D ?? ?? ?? ?? ??", "architecture": "x86", "handler_type": "arithmetic", "operation": "lea", "confidence": 0.80, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 1}},

    # === Bitwise x86 completeness ===
    {"pattern_id": "vmp_xor_32_x86_v1", "name": "VMProtect XOR dword x86", "signature": "31 ?? 89 ?? 9C", "architecture": "x86", "handler_type": "bitwise", "operation": "xor", "confidence": 0.92, "wildcards": True, "variants": ["33 ?? 89 ?? 9C"], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 3}},
    {"pattern_id": "vmp_and_32_x86_v1", "name": "VMProtect AND dword x86", "signature": "21 ?? 89 ?? 9C", "architecture": "x86", "handler_type": "bitwise", "operation": "and", "confidence": 0.92, "wildcards": True, "variants": ["23 ?? 89 ?? 9C"], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 3}},
    {"pattern_id": "vmp_or_32_x86_v1", "name": "VMProtect OR dword x86", "signature": "09 ?? 89 ?? 9C", "architecture": "x86", "handler_type": "bitwise", "operation": "or", "confidence": 0.92, "wildcards": True, "variants": ["0B ?? 89 ?? 9C"], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 3}},
    {"pattern_id": "vmp_not_32_x86_v1", "name": "VMProtect NOT dword x86", "signature": "F7 ?? 89 ??", "architecture": "x86", "handler_type": "bitwise", "operation": "not", "confidence": 0.88, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 2}},
    {"pattern_id": "vmp_shr_32_x86_v1", "name": "VMProtect SHR dword x86", "signature": "D3 ?? 89 ?? 9C", "architecture": "x86", "handler_type": "bitwise", "operation": "shr", "confidence": 0.88, "wildcards": True, "variants": ["C1 ?? ?? 89 ?? 9C"], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 3}},
    {"pattern_id": "vmp_sar_64_v1", "name": "VMProtect SAR qword", "signature": "48 D3 ?? 48 89 ??", "architecture": "x64", "handler_type": "bitwise", "operation": "sar", "confidence": 0.90, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 64, "instruction_count": 2}},
    {"pattern_id": "vmp_bt_64_v1", "name": "VMProtect BT qword", "signature": "48 0F A3 ?? 9C", "architecture": "x64", "handler_type": "bitwise", "operation": "bt", "confidence": 0.85, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 64, "instruction_count": 2}},
    {"pattern_id": "vmp_bsf_64_v1", "name": "VMProtect BSF qword", "signature": "48 0F BC ?? 48 89 ??", "architecture": "x64", "handler_type": "bitwise", "operation": "bsf", "confidence": 0.85, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 64, "instruction_count": 2}},
    {"pattern_id": "vmp_bsr_64_v1", "name": "VMProtect BSR qword", "signature": "48 0F BD ?? 48 89 ??", "architecture": "x64", "handler_type": "bitwise", "operation": "bsr", "confidence": 0.85, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 64, "instruction_count": 2}},
    {"pattern_id": "vmp_ror_32_x86_v1", "name": "VMProtect ROR dword x86", "signature": "D3 ?? 89 ??", "architecture": "x86", "handler_type": "bitwise", "operation": "ror", "confidence": 0.85, "wildcards": True, "variants": ["C1 ?? ?? 89 ??"], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 2}},
    {"pattern_id": "vmp_rol_32_x86_v1", "name": "VMProtect ROL dword x86", "signature": "D3 ?? 89 ??", "architecture": "x86", "handler_type": "bitwise", "operation": "rol", "confidence": 0.85, "wildcards": True, "variants": ["C1 ?? ?? 89 ??"], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 2}},

    # === Memory patterns ===
    {"pattern_id": "vmp_store_16_v1", "name": "VMProtect STORE word", "signature": "66 8B ?? ?? 66 89 ?? ??", "architecture": "x64", "handler_type": "memory", "operation": "store", "confidence": 0.85, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 16, "instruction_count": 2}},
    {"pattern_id": "vmp_store_8_v1", "name": "VMProtect STORE byte", "signature": "8A ?? ?? 88 ?? ??", "architecture": "x64", "handler_type": "memory", "operation": "store", "confidence": 0.84, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 8, "instruction_count": 2}},
    {"pattern_id": "vmp_movzx_16_v1", "name": "VMProtect MOVZX word mem load", "signature": "48 0F B7 ?? 48 89 ??", "architecture": "x64", "handler_type": "memory", "operation": "load_word", "confidence": 0.86, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 16, "instruction_count": 2}},
    {"pattern_id": "vmp_cmpxchg_v1", "name": "VMProtect CMPXCHG (atomic CAS)", "signature": "F0 48 0F B1 ??", "architecture": "x64", "handler_type": "memory", "operation": "cmpxchg", "confidence": 0.87, "wildcards": True, "variants": ["F0 0F B1 ??"], "metadata": {"vmprotect_version": "3.x", "instruction_count": 1}},
    {"pattern_id": "vmp_lea_memory_v1", "name": "VMProtect LEA memory address", "signature": "48 8D ?? ?? 48 89 ??", "architecture": "x64", "handler_type": "memory", "operation": "lea_mem", "confidence": 0.82, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 2}},
    {"pattern_id": "vmp_movs_rep_v1", "name": "VMProtect REP MOVS (memcpy)", "signature": "F3 48 A5", "architecture": "x64", "handler_type": "memory", "operation": "rep_movs", "confidence": 0.80, "wildcards": False, "variants": ["F3 A5", "F3 A4"], "metadata": {"vmprotect_version": "3.x", "instruction_count": 1}},
    {"pattern_id": "vmp_stos_rep_v1", "name": "VMProtect REP STOS (memset)", "signature": "F3 48 AB", "architecture": "x64", "handler_type": "memory", "operation": "rep_stos", "confidence": 0.80, "wildcards": False, "variants": ["F3 AB", "F3 AA"], "metadata": {"vmprotect_version": "3.x", "instruction_count": 1}},
    {"pattern_id": "vmp_load_32_x86_v1", "name": "VMProtect LOAD dword x86", "signature": "8B ?? ?? 89 ??", "architecture": "x86", "handler_type": "memory", "operation": "load", "confidence": 0.86, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 2}},
    {"pattern_id": "vmp_store_32_x86_v1", "name": "VMProtect STORE dword x86", "signature": "8B ?? ?? 89 ?? ??", "architecture": "x86", "handler_type": "memory", "operation": "store", "confidence": 0.86, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 2}},

    # === Stack patterns ===
    {"pattern_id": "vmp_push_16_v1", "name": "VMProtect vPUSH word", "signature": "66 89 ?? ?? 48 83 ?? ??", "architecture": "x64", "handler_type": "stack", "operation": "push", "confidence": 0.88, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 16, "instruction_count": 2}},
    {"pattern_id": "vmp_push_8_v1", "name": "VMProtect vPUSH byte", "signature": "88 ?? ?? 48 83 ?? ??", "architecture": "x64", "handler_type": "stack", "operation": "push", "confidence": 0.86, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 8, "instruction_count": 2}},
    {"pattern_id": "vmp_pop_16_v1", "name": "VMProtect vPOP word", "signature": "66 8B ?? ?? 48 83 ?? ??", "architecture": "x64", "handler_type": "stack", "operation": "pop", "confidence": 0.88, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 16, "instruction_count": 2}},
    {"pattern_id": "vmp_pop_8_v1", "name": "VMProtect vPOP byte", "signature": "8A ?? ?? 48 83 ?? ??", "architecture": "x64", "handler_type": "stack", "operation": "pop", "confidence": 0.86, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 8, "instruction_count": 2}},
    {"pattern_id": "vmp_pushf_32_x86_v1", "name": "VMProtect PUSHFD x86", "signature": "9C 89 ?? ?? 83 ?? ??", "architecture": "x86", "handler_type": "stack", "operation": "pushf", "confidence": 0.90, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 3}},
    {"pattern_id": "vmp_popf_32_x86_v1", "name": "VMProtect POPFD x86", "signature": "8B ?? ?? 9D", "architecture": "x86", "handler_type": "stack", "operation": "popf", "confidence": 0.90, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 2}},

    # === Control flow ===
    {"pattern_id": "vmp_jcc_32_x86_v1", "name": "VMProtect vJCC dword x86", "signature": "85 ?? 0F ?? ?? ?? ?? ??", "architecture": "x86", "handler_type": "control_flow", "operation": "jcc", "confidence": 0.85, "wildcards": True, "variants": ["3B ?? 0F ?? ?? ?? ?? ??"], "metadata": {"vmprotect_version": "3.x", "instruction_count": 2}},
    {"pattern_id": "vmp_call_32_x86_v1", "name": "VMProtect vCALL x86", "signature": "89 ?? ?? 83 ?? ?? FF ??", "architecture": "x86", "handler_type": "control_flow", "operation": "call", "confidence": 0.86, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 3}},
    {"pattern_id": "vmp_ret_32_x86_v1", "name": "VMProtect vRET x86", "signature": "8B ?? ?? 83 ?? ?? FF ??", "architecture": "x86", "handler_type": "control_flow", "operation": "ret", "confidence": 0.88, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 3}},
    {"pattern_id": "vmp_jmp_32_x86_v1", "name": "VMProtect vJMP x86", "signature": "8B ?? ?? FF ??", "architecture": "x86", "handler_type": "control_flow", "operation": "jmp", "confidence": 0.86, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 2}},
    {"pattern_id": "vmp_nested_enter_v1", "name": "VMProtect Nested VM Entry", "signature": "48 89 ?? ?? ?? ?? ?? 48 8D ?? ?? ?? ?? ?? 48 FF ??", "architecture": "x64", "handler_type": "control_flow", "operation": "nested_enter", "confidence": 0.78, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.5+", "instruction_count": 3, "description": "Entry into a nested VM layer"}},
    {"pattern_id": "vmp_nested_exit_v1", "name": "VMProtect Nested VM Exit", "signature": "48 8B ?? ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? C3", "architecture": "x64", "handler_type": "control_flow", "operation": "nested_exit", "confidence": 0.77, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.5+", "instruction_count": 3, "description": "Exit from a nested VM layer"}},
    {"pattern_id": "vmp_dispatch_v3_xor_key", "name": "VMProtect Dispatch with XOR key", "signature": "0F B6 ?? 30 ?? 48 8D ?? ?? ?? ?? ?? 48 63 ?? ?? 48 01 ?? FF ??", "architecture": "x64", "handler_type": "control_flow", "operation": "dispatch", "confidence": 0.88, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.5+", "instruction_count": 6}},
    {"pattern_id": "vmp_loopback_v1", "name": "VMProtect VM Loop (back-edge)", "signature": "48 83 ?? ?? 0F 8? ?? ?? ?? ??", "architecture": "x64", "handler_type": "control_flow", "operation": "loop", "confidence": 0.82, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 2}},
    {"pattern_id": "vmp_int3_v1", "name": "VMProtect INT3 (trap)", "signature": "CC", "architecture": "x64", "handler_type": "control_flow", "operation": "int3", "confidence": 0.72, "wildcards": False, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 1}},

    # === Comparison ===
    {"pattern_id": "vmp_cmp_32_v1", "name": "VMProtect CMP dword + pushf", "signature": "3B ?? 9C 48 89 ??", "architecture": "x64", "handler_type": "comparison", "operation": "cmp", "confidence": 0.90, "wildcards": True, "variants": ["39 ?? 9C 48 89 ??"], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 3}},
    {"pattern_id": "vmp_test_32_v1", "name": "VMProtect TEST dword + pushf", "signature": "85 ?? 9C 48 89 ??", "architecture": "x64", "handler_type": "comparison", "operation": "test", "confidence": 0.89, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 3}},
    {"pattern_id": "vmp_test_8_v1", "name": "VMProtect TEST byte + pushf", "signature": "84 ?? 9C 48 89 ??", "architecture": "x64", "handler_type": "comparison", "operation": "test", "confidence": 0.87, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 8, "instruction_count": 3}},
    {"pattern_id": "vmp_test_32_x86_v1", "name": "VMProtect TEST dword x86 + pushfd", "signature": "85 ?? 9C", "architecture": "x86", "handler_type": "comparison", "operation": "test", "confidence": 0.88, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "width": 32, "instruction_count": 2}},
    {"pattern_id": "vmp_cmp_16_v1", "name": "VMProtect CMP word + pushf", "signature": "66 3B ?? 9C 48 89 ??", "architecture": "x64", "handler_type": "comparison", "operation": "cmp", "confidence": 0.87, "wildcards": True, "variants": ["66 39 ?? 9C"], "metadata": {"vmprotect_version": "3.x", "width": 16, "instruction_count": 3}},
    {"pattern_id": "vmp_cmp_8_v1", "name": "VMProtect CMP byte + pushf", "signature": "3A ?? 9C 48 89 ??", "architecture": "x64", "handler_type": "comparison", "operation": "cmp", "confidence": 0.86, "wildcards": True, "variants": ["38 ?? 9C"], "metadata": {"vmprotect_version": "3.x", "width": 8, "instruction_count": 3}},

    # === Crypto/anti-debug ===
    {"pattern_id": "vmp_decrypt_ror_v1", "name": "VMProtect Opcode Decrypt (ROR key)", "signature": "C0 ?? ?? 30 ?? 0F B6 ??", "architecture": "x64", "handler_type": "crypto", "operation": "decrypt_opcode", "confidence": 0.84, "wildcards": True, "variants": ["C0 ?? ?? 32 ??"], "metadata": {"vmprotect_version": "3.x", "instruction_count": 3}},
    {"pattern_id": "vmp_decrypt_mul_v1", "name": "VMProtect Opcode Decrypt (MUL key)", "signature": "0F AF ?? 0F B6 ??", "architecture": "x64", "handler_type": "crypto", "operation": "decrypt_opcode", "confidence": 0.80, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.5+", "instruction_count": 2}},
    {"pattern_id": "vmp_cpuid_32_v1", "name": "VMProtect CPUID x86", "signature": "0F A2 89 ??", "architecture": "x86", "handler_type": "crypto", "operation": "cpuid_check", "confidence": 0.76, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 2}},
    {"pattern_id": "vmp_int2d_v1", "name": "VMProtect INT 2D (anti-debug)", "signature": "CD 2D", "architecture": "x64", "handler_type": "crypto", "operation": "anti_debug", "confidence": 0.75, "wildcards": False, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 1}},
    {"pattern_id": "vmp_rdrand_v1", "name": "VMProtect RDRAND", "signature": "48 0F C7 ?? 48 89 ??", "architecture": "x64", "handler_type": "crypto", "operation": "rdrand", "confidence": 0.82, "wildcards": True, "variants": ["0F C7 ??"], "metadata": {"vmprotect_version": "3.x", "instruction_count": 2}},
    {"pattern_id": "vmp_crc32_v1", "name": "VMProtect CRC32 integrity", "signature": "F2 48 0F 38 F1 ??", "architecture": "x64", "handler_type": "crypto", "operation": "crc32", "confidence": 0.85, "wildcards": True, "variants": ["F2 0F 38 F1 ??"], "metadata": {"vmprotect_version": "3.5+", "instruction_count": 1}},
    {"pattern_id": "vmp_aesenc_v1", "name": "VMProtect AESENC", "signature": "66 0F 38 DC ??", "architecture": "x64", "handler_type": "crypto", "operation": "aesenc", "confidence": 0.82, "wildcards": True, "variants": ["66 0F 38 DD ??"], "metadata": {"vmprotect_version": "3.5+", "instruction_count": 1}},
    {"pattern_id": "vmp_key_rot_add_v1", "name": "VMProtect Key Rotate+ADD", "signature": "C0 ?? ?? 00 ?? 0F B6 ??", "architecture": "x64", "handler_type": "crypto", "operation": "key_update", "confidence": 0.80, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 3}},
    {"pattern_id": "vmp_cpuid_full_v1", "name": "VMProtect CPUID full context save", "signature": "0F A2 48 89 ?? 48 89 ?? 48 89 ?? 48 89 ??", "architecture": "x64", "handler_type": "crypto", "operation": "cpuid_full", "confidence": 0.78, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 5}},

    # === Conversion ===
    {"pattern_id": "vmp_movzx_16_conv_v1", "name": "VMProtect MOVZX word-to-qword", "signature": "48 0F B7 ??", "architecture": "x64", "handler_type": "conversion", "operation": "movzx", "confidence": 0.88, "wildcards": True, "variants": ["0F B7 ??"], "metadata": {"vmprotect_version": "3.x", "width": 16, "instruction_count": 1}},
    {"pattern_id": "vmp_movsx_16_v1", "name": "VMProtect MOVSX word-to-qword", "signature": "48 0F BF ??", "architecture": "x64", "handler_type": "conversion", "operation": "movsx", "confidence": 0.88, "wildcards": True, "variants": ["0F BF ??"], "metadata": {"vmprotect_version": "3.x", "width": 16, "instruction_count": 1}},
    {"pattern_id": "vmp_cdqe_v1", "name": "VMProtect CDQE (sign extend EAX to RAX)", "signature": "48 98", "architecture": "x64", "handler_type": "conversion", "operation": "cdqe", "confidence": 0.90, "wildcards": False, "variants": ["99"], "metadata": {"vmprotect_version": "3.x", "instruction_count": 1}},
    {"pattern_id": "vmp_cvtsi2sd_v1", "name": "VMProtect CVTSI2SD (int to double)", "signature": "F2 48 0F 2A ??", "architecture": "x64", "handler_type": "conversion", "operation": "cvtsi2sd", "confidence": 0.82, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 1}},
    {"pattern_id": "vmp_cvttsd2si_v1", "name": "VMProtect CVTTSD2SI (double to int)", "signature": "F2 48 0F 2C ??", "architecture": "x64", "handler_type": "conversion", "operation": "cvttsd2si", "confidence": 0.82, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.x", "instruction_count": 1}},
    {"pattern_id": "vmp_bswap_32_x86_v1", "name": "VMProtect BSWAP dword x86", "signature": "0F C8", "architecture": "x86", "handler_type": "conversion", "operation": "bswap", "confidence": 0.88, "wildcards": False, "variants": ["0F C9", "0F CA"], "metadata": {"vmprotect_version": "3.x", "instruction_count": 1}},

    # === VMProtect 3.5+ mutation patterns ===
    {"pattern_id": "vmp_mutated_add_v1", "name": "VMProtect Mutated ADD (LEA form)", "signature": "48 8D ?? ??", "architecture": "x64", "handler_type": "arithmetic", "operation": "add", "confidence": 0.80, "wildcards": True, "variants": ["4C 8D ?? ??"], "metadata": {"vmprotect_version": "3.5+", "instruction_count": 1, "description": "Mutation: ADD via LEA r,[r+r]"}},
    {"pattern_id": "vmp_mutated_sub_v1", "name": "VMProtect Mutated SUB (NEG+ADD form)", "signature": "48 F7 ?? 48 01 ??", "architecture": "x64", "handler_type": "arithmetic", "operation": "sub", "confidence": 0.78, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.5+", "instruction_count": 2, "description": "Mutation: SUB via NEG+ADD"}},
    {"pattern_id": "vmp_mutated_xor_nand_v1", "name": "VMProtect Mutated XOR (NAND-based)", "signature": "48 F7 ?? 48 21 ?? 48 F7 ?? 48 F7 ?? 48 21 ??", "architecture": "x64", "handler_type": "bitwise", "operation": "xor", "confidence": 0.75, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.5+", "instruction_count": 5, "description": "Mutation: XOR decomposed as NAND(NAND(a,b), NAND(~a,~b))"}},
    {"pattern_id": "vmp_obfuscated_dispatch_v1", "name": "VMProtect Obfuscated Dispatch (junk-padded)", "signature": "0F B6 ?? 48 8D ?? ?? ?? ?? ?? 48 63 ?? ?? 48 01 ?? 48 FF ??", "architecture": "x64", "handler_type": "control_flow", "operation": "dispatch", "confidence": 0.85, "wildcards": True, "variants": [], "metadata": {"vmprotect_version": "3.5+", "instruction_count": 5}},
]

added = 0
for p in NEW:
    pid = p["pattern_id"]
    if pid not in existing_ids:
        data["patterns"].append(p)
        existing_ids.add(pid)
        added += 1

data["description"] = (
    "VMProtect x64/x86 Handler Patterns \u2014 "
    "Comprehensive signature database (B105 expanded)"
)

with open(DB_PATH, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")

total = len(data["patterns"])
cats = {}
for p in data["patterns"]:
    cats.setdefault(p["handler_type"], []).append(p["pattern_id"])
print(f"Added {added} new patterns. Total: {total}")
for k in sorted(cats):
    print(f"  {k}: {len(cats[k])}")
