"""
B48 — Symbolic Key Recovery & Decoder Integration Tests
=========================================================

Tests for:
1. Abstract register file tracking
2. Instruction interpretation (mov imm, lea rip, mov reg, xor self, arith)
3. recover_key_from_entry with dict-based instructions
4. recover_key_from_entry with dispatcher match inference
5. Integration with make_decryptor_from_dispatcher fallback
6. End-to-end: entry stub → key recovery → rolling decrypt → verify
"""

import pytest

from dragonslayer.analysis.key_recovery import (
    RecoveredKey,
    _AbstractRegFile,
    _RegValue,
    _interpret_instruction,
    recover_key_from_entry,
)

from dragonslayer.analysis.bytecode_decrypt import (
    BytecodeDecryptor,
    KeyTransform,
    TransformOp,
    parse_decode_transforms,
    make_decryptor_from_dispatcher,
)


# ---------------------------------------------------------------------------
# 1. Abstract register file
# ---------------------------------------------------------------------------

class TestAbstractRegFile:
    def test_set_get_concrete(self):
        rf = _AbstractRegFile(bit_width=64)
        rf.set_concrete("rax", 42)
        assert rf.get_concrete("rax") == 42

    def test_unknown_register(self):
        rf = _AbstractRegFile(bit_width=64)
        assert rf.get_concrete("rax") is None

    def test_case_insensitive(self):
        rf = _AbstractRegFile(bit_width=64)
        rf.set_concrete("RAX", 100)
        assert rf.get_concrete("rax") == 100

    def test_mask_32bit(self):
        rf = _AbstractRegFile(bit_width=32)
        rf.set_concrete("eax", 0x1_FFFF_FFFF)
        assert rf.get_concrete("eax") == 0xFFFF_FFFF

    def test_snapshot(self):
        rf = _AbstractRegFile(bit_width=64)
        rf.set_concrete("rax", 1)
        rf.set_concrete("rbx", 2)
        snap = rf.snapshot()
        assert snap == {"rax": 1, "rbx": 2}


# ---------------------------------------------------------------------------
# 2. Instruction interpretation
# ---------------------------------------------------------------------------

class TestInstructionInterpret:
    def _run(self, mnemonic, operands, regs=None, addr=0x1000, size=5):
        rf = regs or _AbstractRegFile(rip_base=addr, bit_width=64)
        _interpret_instruction(rf, mnemonic, operands, addr, size)
        return rf

    def test_mov_imm(self):
        rf = self._run("mov", "ecx, 0xDEADBEEF")
        assert rf.get_concrete("ecx") == 0xDEADBEEF

    def test_mov_imm_decimal(self):
        rf = self._run("mov", "edx, 42")
        assert rf.get_concrete("edx") == 42

    def test_lea_rip_plus(self):
        rf = self._run("lea", "rdi, [rip + 0x100]", addr=0x1000, size=7)
        # rip after instruction = 0x1007, plus 0x100 = 0x1107
        assert rf.get_concrete("rdi") == 0x1107

    def test_lea_rip_minus(self):
        rf = self._run("lea", "rsi, [rip - 0x10]", addr=0x2000, size=7)
        assert rf.get_concrete("rsi") == 0x2007 - 0x10

    def test_mov_reg(self):
        rf = _AbstractRegFile(bit_width=64)
        rf.set_concrete("rax", 0x1234)
        _interpret_instruction(rf, "mov", "rbx, rax", 0, 3)
        assert rf.get_concrete("rbx") == 0x1234

    def test_xor_self(self):
        rf = _AbstractRegFile(bit_width=64)
        rf.set_concrete("rcx", 0xFFFF)
        _interpret_instruction(rf, "xor", "rcx, rcx", 0, 2)
        assert rf.get_concrete("rcx") == 0

    def test_add_imm(self):
        rf = _AbstractRegFile(bit_width=64)
        rf.set_concrete("rax", 10)
        _interpret_instruction(rf, "add", "rax, 5", 0, 3)
        assert rf.get_concrete("rax") == 15

    def test_sub_imm(self):
        rf = _AbstractRegFile(bit_width=64)
        rf.set_concrete("rax", 10)
        _interpret_instruction(rf, "sub", "rax, 3", 0, 3)
        assert rf.get_concrete("rax") == 7

    def test_xor_imm(self):
        rf = _AbstractRegFile(bit_width=64)
        rf.set_concrete("rax", 0xFF)
        _interpret_instruction(rf, "xor", "rax, 0x0F", 0, 3)
        assert rf.get_concrete("rax") == 0xF0

    def test_not_reg(self):
        rf = _AbstractRegFile(bit_width=32)
        rf.set_concrete("eax", 0)
        _interpret_instruction(rf, "not", "eax", 0, 2)
        assert rf.get_concrete("eax") == 0xFFFFFFFF

    def test_neg_reg(self):
        rf = _AbstractRegFile(bit_width=32)
        rf.set_concrete("eax", 1)
        _interpret_instruction(rf, "neg", "eax", 0, 2)
        assert rf.get_concrete("eax") == 0xFFFFFFFF  # -1 as unsigned

    def test_push_preserves_regs(self):
        rf = _AbstractRegFile(bit_width=64)
        rf.set_concrete("rbx", 42)
        _interpret_instruction(rf, "push", "rbx", 0, 1)
        assert rf.get_concrete("rbx") == 42

    def test_pop_kills_reg(self):
        rf = _AbstractRegFile(bit_width=64)
        rf.set_concrete("rax", 42)
        _interpret_instruction(rf, "pop", "rax", 0, 1)
        assert rf.get_concrete("rax") is None  # unknown after pop


# ---------------------------------------------------------------------------
# 3. recover_key_from_entry
# ---------------------------------------------------------------------------

class TestRecoverKeyFromEntry:
    """Test key recovery from dict-based instructions."""

    def _make_insn(self, addr, size, mnemonic, operands):
        return {
            "address": addr,
            "size": size,
            "mnemonic": mnemonic,
            "operands": operands,
        }

    def test_simple_mov_key(self):
        """VMProtect entry: mov ecx, 0xDEADBEEF; jmp dispatcher"""
        insns = [
            self._make_insn(0x1000, 5, "mov", "ecx, 0xDEADBEEF"),
        ]
        match = {"context_registers": {"ecx": "vKey"}, "vip_register": "rdi"}
        result = recover_key_from_entry(insns, match)
        assert result is not None
        assert result.key_value == 0xDEADBEEF
        assert result.key_register == "ecx"
        assert result.source == "immediate"

    def test_key_with_arithmetic(self):
        """Entry: mov ecx, 0x100; add ecx, 0x23 → key = 0x123"""
        insns = [
            self._make_insn(0x1000, 5, "mov", "ecx, 0x100"),
            self._make_insn(0x1005, 3, "add", "ecx, 0x23"),
        ]
        match = {"context_registers": {"ecx": "vKey"}}
        result = recover_key_from_entry(insns, match)
        assert result is not None
        assert result.key_value == 0x123

    def test_key_and_vip_recovery(self):
        """Recover both key (ecx) and vIP (rdi)."""
        insns = [
            self._make_insn(0x1000, 7, "lea", "rdi, [rip + 0x200]"),
            self._make_insn(0x1007, 5, "mov", "ecx, 0xCAFEBABE"),
        ]
        match = {
            "context_registers": {"ecx": "vKey"},
            "vip_register": "rdi",
        }
        result = recover_key_from_entry(insns, match)
        assert result is not None
        assert result.key_value == 0xCAFEBABE
        assert result.vip_initial == 0x1007 + 0x200  # rip after lea + 0x200

    def test_infer_key_from_decode_transforms(self):
        """Key register inferred from decode_transforms."""
        insns = [
            self._make_insn(0x1000, 5, "mov", "edx, 0xABCD"),
        ]
        match = {"decode_transforms": ["xor edx, ecx"]}
        result = recover_key_from_entry(insns, match)
        assert result is not None
        assert result.key_register == "edx"
        assert result.key_value == 0xABCD

    def test_no_instructions(self):
        assert recover_key_from_entry([], {}) is None

    def test_key_not_found(self):
        """Instructions don't set the key register."""
        insns = [
            self._make_insn(0x1000, 1, "push", "rbp"),
            self._make_insn(0x1001, 1, "push", "rdi"),
        ]
        match = {"context_registers": {"ecx": "vKey"}}
        result = recover_key_from_entry(insns, match)
        assert result is None

    def test_mov_reg_chain(self):
        """Key loaded via register chain: mov eax, 0x42; mov ecx, eax"""
        insns = [
            self._make_insn(0x1000, 5, "mov", "eax, 0x42"),
            self._make_insn(0x1005, 2, "mov", "ecx, eax"),
        ]
        match = {"context_registers": {"ecx": "vKey"}}
        result = recover_key_from_entry(insns, match)
        assert result is not None
        assert result.key_value == 0x42

    def test_auto_detect_key_register(self):
        """When no key register specified, try common candidates."""
        insns = [
            self._make_insn(0x1000, 5, "mov", "ecx, 0x999"),
        ]
        match = {}  # No context_registers, no decode_transforms
        result = recover_key_from_entry(insns, match)
        assert result is not None
        assert result.key_value == 0x999
        assert result.key_register == "ecx"


# ---------------------------------------------------------------------------
# 4. Integration with make_decryptor_from_dispatcher
# ---------------------------------------------------------------------------

class TestMakeDecryptorFallback:
    """Test that make_decryptor_from_dispatcher uses key_recovery as fallback."""

    def test_fallback_uses_entry_instructions(self):
        """When no trace provided, entry_instructions drive key recovery."""
        match = {
            "decode_transforms": ["xor ecx, edx"],
            "fetch_register": "edx",
            "fetch_width": 1,
            "context_registers": {"ecx": "vKey"},
            "entry_instructions": [
                {"address": 0x1000, "size": 5, "mnemonic": "mov",
                 "operands": "ecx, 0xDEADBEEF"},
            ],
        }
        decryptor = make_decryptor_from_dispatcher(match, trace_records=None)
        assert decryptor is not None
        assert decryptor.initial_key == 0xDEADBEEF

    def test_trace_takes_priority(self):
        """Trace-based key detection takes priority over entry stub recovery."""
        match = {
            "decode_transforms": ["xor ecx, edx"],
            "fetch_register": "edx",
            "entry_address": 0x1000,
            "context_registers": {"ecx": "vKey"},
            "entry_instructions": [
                {"address": 0x1000, "size": 5, "mnemonic": "mov",
                 "operands": "ecx, 0x11111111"},
            ],
        }
        # Trace record that sets ecx = 0x22222222 at entry
        trace = [
            {"address": 0x1000, "registers": {"ecx": 0x22222222}},
        ]
        decryptor = make_decryptor_from_dispatcher(match, trace_records=trace)
        assert decryptor is not None
        assert decryptor.initial_key == 0x22222222  # from trace, not entry stub


# ---------------------------------------------------------------------------
# 5. End-to-end: entry → key → decrypt → verify
# ---------------------------------------------------------------------------

class TestEndToEndDecrypt:
    """Simulate the full pipeline: entry stub → key → rolling decrypt."""

    def test_full_pipeline(self):
        """Build a synthetic encrypted bytecode stream and decrypt it."""
        # 1. Define rolling key scheme: xor key, opcode (key width 32)
        transforms = [KeyTransform(op=TransformOp.XOR, operand_source="opcode")]
        initial_key = 0xDEADBEEF

        # 2. Encrypt a known plaintext opcode sequence
        plain_opcodes = [0x01, 0x02, 0x03, 0x04, 0x05]
        encrypted = bytearray()
        key = initial_key
        for p in plain_opcodes:
            enc = (p ^ key) & 0xFF
            encrypted.append(enc)
            key = (key ^ p) & 0xFFFFFFFF  # apply XOR transform

        # 3. Recover key from entry stub
        entry_insns = [
            {"address": 0x1000, "size": 5, "mnemonic": "mov",
             "operands": "ecx, 0xDEADBEEF"},
        ]
        match = {
            "context_registers": {"ecx": "vKey"},
            "decode_transforms": ["xor ecx, edx"],
            "fetch_register": "edx",
        }
        recovered = recover_key_from_entry(entry_insns, match)
        assert recovered is not None
        assert recovered.key_value == initial_key

        # 4. Decrypt with the recovered key
        decryptor = BytecodeDecryptor(
            transforms=transforms,
            initial_key=recovered.key_value,
            key_width=32,
            opcode_width=1,
        )
        plaintext, keys = decryptor.decrypt(bytes(encrypted))

        # 5. Verify
        for i, p in enumerate(plain_opcodes):
            assert plaintext[i] == p, f"Mismatch at offset {i}: {plaintext[i]} != {p}"

    def test_multi_transform_pipeline(self):
        """XOR + ROL key scheme."""
        transforms = [
            KeyTransform(op=TransformOp.XOR, operand_source="opcode"),
            KeyTransform(op=TransformOp.ROL, operand_source="imm:3"),
        ]
        initial_key = 0x12345678

        # Encrypt
        plain_opcodes = [0xAA, 0xBB, 0xCC, 0xDD]
        encrypted = bytearray()
        key = initial_key
        mask = 0xFFFFFFFF
        for p in plain_opcodes:
            enc = (p ^ key) & 0xFF
            encrypted.append(enc)
            # Apply transforms
            key = (key ^ p) & mask
            shift = 3 % 32
            key = ((key << shift) | (key >> (32 - shift))) & mask

        # Recover key and decrypt
        entry_insns = [
            {"address": 0, "size": 5, "mnemonic": "mov",
             "operands": f"ecx, {hex(initial_key)}"},
        ]
        match = {
            "context_registers": {"ecx": "vKey"},
            "decode_transforms": ["xor ecx, edx", "rol ecx, 3"],
            "fetch_register": "edx",
        }
        recovered = recover_key_from_entry(entry_insns, match)
        assert recovered is not None

        decryptor = BytecodeDecryptor(
            transforms=transforms,
            initial_key=recovered.key_value,
            key_width=32,
            opcode_width=1,
        )
        plaintext, _ = decryptor.decrypt(bytes(encrypted))
        for i, p in enumerate(plain_opcodes):
            assert plaintext[i] == p


# ---------------------------------------------------------------------------
# 6. RecoveredKey dataclass
# ---------------------------------------------------------------------------

class TestRecoveredKey:
    def test_default_values(self):
        rk = RecoveredKey()
        assert rk.key_value == 0
        assert rk.confidence == 0.0
        assert rk.source == "unknown"

    def test_custom_values(self):
        rk = RecoveredKey(
            key_value=0xDEAD,
            key_register="ecx",
            vip_initial=0x1000,
            confidence=0.85,
            source="immediate",
        )
        assert rk.key_value == 0xDEAD
        assert rk.key_register == "ecx"
        assert rk.vip_initial == 0x1000
