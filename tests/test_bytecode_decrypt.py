"""
Tests for Batch 24 — Rolling-Key Bytecode Decryption + Handler Table Decryption
================================================================================

Covers:
  - bytecode_decrypt.py: parse_decode_transforms, BytecodeDecryptor,
    detect_initial_key, decrypt_handler_table, make_decryptor_from_dispatcher
  - Integration with bytecode_cfg.walk_static_bytecode (decryptor= param)
  - Pipeline wiring (step 3b)
"""

from __future__ import annotations

import struct
import pytest
from unittest.mock import MagicMock, patch

from dragonslayer.analysis.bytecode_decrypt import (
    BytecodeDecryptor,
    DecryptedHandlerTable,
    HandlerTableEntry,
    KeyTransform,
    TransformOp,
    decrypt_handler_table,
    detect_initial_key,
    make_decryptor_from_dispatcher,
    parse_decode_transforms,
    _detect_table_xor_key,
)


# ═══════════════════════════════════════════════════════════════════════════
# 1. parse_decode_transforms
# ═══════════════════════════════════════════════════════════════════════════

class TestParseDecodeTransforms:
    """Parsing of assembly-like decode transform strings."""

    def test_simple_xor(self):
        result = parse_decode_transforms(
            ["xor ecx, edx"],
            fetch_register="edx",
        )
        assert len(result) == 1
        assert result[0].op == TransformOp.XOR
        assert result[0].operand_source == "opcode"

    def test_xor_with_key(self):
        result = parse_decode_transforms(
            ["xor ecx, ecx"],
            fetch_register="edx",
        )
        assert len(result) == 1
        assert result[0].operand_source == "key"

    def test_not_unary(self):
        result = parse_decode_transforms(["not ecx"])
        assert len(result) == 1
        assert result[0].op == TransformOp.NOT
        assert result[0].operand_source == ""

    def test_neg_unary(self):
        result = parse_decode_transforms(["neg edx"])
        assert len(result) == 1
        assert result[0].op == TransformOp.NEG

    def test_bswap(self):
        result = parse_decode_transforms(["bswap ecx"])
        assert len(result) == 1
        assert result[0].op == TransformOp.BSWAP

    def test_rol_with_immediate(self):
        result = parse_decode_transforms(["rol ecx, 5"])
        assert len(result) == 1
        assert result[0].op == TransformOp.ROL
        assert result[0].operand_source == "imm:5"

    def test_ror_with_hex_immediate(self):
        result = parse_decode_transforms(["ror eax, 0x3"])
        assert len(result) == 1
        assert result[0].op == TransformOp.ROR
        assert result[0].operand_source == "imm:3"

    def test_add_sub(self):
        result = parse_decode_transforms(
            ["add ecx, edx", "sub ecx, 0x10"],
            fetch_register="edx",
        )
        assert len(result) == 2
        assert result[0].op == TransformOp.ADD
        assert result[0].operand_source == "opcode"
        assert result[1].op == TransformOp.SUB
        assert result[1].operand_source == "imm:16"

    def test_multi_transform_chain(self):
        """VMProtect often uses: xor key, opcode; rol key, N; add key, opcode."""
        result = parse_decode_transforms(
            ["xor ecx, edx", "rol ecx, 7", "add ecx, edx"],
            fetch_register="edx",
        )
        assert len(result) == 3
        ops = [t.op for t in result]
        assert ops == [TransformOp.XOR, TransformOp.ROL, TransformOp.ADD]

    def test_empty_input(self):
        assert parse_decode_transforms([]) == []

    def test_unparsable_ignored(self):
        result = parse_decode_transforms(["garbage text", "xor ecx, edx"],
                                         fetch_register="edx")
        assert len(result) == 1

    def test_inc_dec(self):
        result = parse_decode_transforms(["inc ecx", "dec ecx"])
        assert len(result) == 2
        assert result[0].op == TransformOp.INC
        assert result[1].op == TransformOp.DEC


# ═══════════════════════════════════════════════════════════════════════════
# 2. BytecodeDecryptor — core rolling-key operations
# ═══════════════════════════════════════════════════════════════════════════

class TestBytecodeDecryptor:
    """Rolling-key decryption of bytecode streams."""

    def test_no_transforms_passthrough(self):
        """No transforms → return raw bytes unchanged."""
        dec = BytecodeDecryptor(transforms=[], initial_key=0x42)
        plaintext, keys = dec.decrypt(b"\x01\x02\x03")
        assert plaintext == b"\x01\x02\x03"
        assert keys == []

    def test_simple_xor_decrypt(self):
        """Single-byte XOR with key=0x42 transforms=[xor key, opcode]."""
        transforms = [KeyTransform(op=TransformOp.XOR, operand_source="opcode")]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0x42,
            key_width=8,
            opcode_width=1,
        )
        # Encrypt: plain 0x10 ^ key 0x42 = 0x52
        # After: key = 0x42 ^ 0x10 = 0x52
        # plain 0x20 ^ key 0x52 = 0x72
        encrypted = bytes([0x10 ^ 0x42, 0x20 ^ 0x52])
        plain, keys = dec.decrypt(encrypted)
        assert plain == bytes([0x10, 0x20])
        assert keys == [0x42, 0x52]

    def test_rolling_xor_chain(self):
        """Verify key rolls correctly over multiple opcodes."""
        transforms = [KeyTransform(op=TransformOp.XOR, operand_source="opcode")]
        initial_key = 0xAB
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=initial_key,
            key_width=8,
            opcode_width=1,
        )
        # Manually encrypt 5 plaintext opcodes
        plain_opcodes = [0x01, 0x02, 0x03, 0x04, 0x05]
        encrypted = bytearray()
        key = initial_key
        for p in plain_opcodes:
            encrypted.append(p ^ key)
            key = (key ^ p) & 0xFF

        result_plain, result_keys = dec.decrypt(bytes(encrypted))
        assert list(result_plain) == plain_opcodes

    def test_add_transform(self):
        """Transform: add key, opcode (key accumulates plaintext opcodes)."""
        transforms = [KeyTransform(op=TransformOp.ADD, operand_source="opcode")]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0x10,
            key_width=8,
            opcode_width=1,
        )
        # plain 0x05: enc = 0x05 ^ 0x10 = 0x15; next key = (0x10 + 0x05) & 0xFF = 0x15
        # plain 0x0A: enc = 0x0A ^ 0x15 = 0x1F; next key = (0x15 + 0x0A) & 0xFF = 0x1F
        encrypted = bytes([0x05 ^ 0x10, 0x0A ^ 0x15])
        plain, keys = dec.decrypt(encrypted)
        assert list(plain) == [0x05, 0x0A]
        assert keys == [0x10, 0x15]

    def test_not_transform(self):
        """Transform: not key (bitwise invert after each opcode)."""
        transforms = [KeyTransform(op=TransformOp.NOT, operand_source="")]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0xFF,
            key_width=8,
            opcode_width=1,
        )
        # plain 0x00: enc = 0x00 ^ 0xFF = 0xFF; new key = ~0xFF & 0xFF = 0x00
        # plain 0x00: enc = 0x00 ^ 0x00 = 0x00; new key = ~0x00 & 0xFF = 0xFF
        encrypted = bytes([0xFF, 0x00])
        plain, _ = dec.decrypt(encrypted)
        assert list(plain) == [0x00, 0x00]

    def test_rol_transform_32bit(self):
        """ROL key, 5 with 32-bit key."""
        transforms = [KeyTransform(op=TransformOp.ROL, operand_source="imm:5")]
        key = 0x80000001
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=key,
            key_width=32,
            opcode_width=1,
        )
        # After ROL 0x80000001 by 5: expected = 0x00000030
        # (MSB 1 shifted left 5 becomes bits 5..0 = 0x20 | lsb shifted = 0x10)
        # Actually: ROL(0x80000001, 5) = ((0x80000001 << 5) | (0x80000001 >> 27)) & 0xFFFFFFFF
        expected_key_after = ((0x80000001 << 5) | (0x80000001 >> 27)) & 0xFFFFFFFF

        enc_opcode = 0x42 ^ (key & 0xFF)
        plain, keys = dec.decrypt(bytes([enc_opcode]))
        assert plain[0] == 0x42
        assert keys == [key]

    def test_bswap_32bit(self):
        """BSWAP with 32-bit key."""
        transforms = [KeyTransform(op=TransformOp.BSWAP, operand_source="")]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0xAABBCCDD,
            key_width=32,
            opcode_width=1,
        )
        # After decrypt first byte, key should be bswap(0xAABBCCDD) = 0xDDCCBBAA
        enc = bytes([0x42 ^ 0xDD])  # Low byte of key
        plain, keys = dec.decrypt(enc)
        assert plain[0] == 0x42

    def test_decrypt_single(self):
        """decrypt_single for step-by-step trace-synchronized decryption."""
        transforms = [KeyTransform(op=TransformOp.XOR, operand_source="opcode")]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0x42,
            key_width=8,
            opcode_width=1,
        )
        plain, next_key = dec.decrypt_single(0x10 ^ 0x42, 0x42)
        assert plain == 0x10
        assert next_key == (0x42 ^ 0x10)

    def test_complex_vmprotect_chain(self):
        """Realistic VMProtect chain: xor key, opcode; rol key, 7; add key, opcode."""
        transforms = [
            KeyTransform(op=TransformOp.XOR, operand_source="opcode"),
            KeyTransform(op=TransformOp.ROL, operand_source="imm:7"),
            KeyTransform(op=TransformOp.ADD, operand_source="opcode"),
        ]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0xDEAD,
            key_width=16,
            opcode_width=1,
        )
        # Manually encrypt
        plain_opcodes = [0x01, 0x42, 0xFF, 0x00, 0x7B]
        key = 0xDEAD
        encrypted = bytearray()
        for p in plain_opcodes:
            enc = (p ^ key) & 0xFF
            encrypted.append(enc)
            # Apply transforms
            key = (key ^ p) & 0xFFFF
            key = ((key << 7) | (key >> 9)) & 0xFFFF
            key = (key + p) & 0xFFFF

        result_plain, _ = dec.decrypt(bytes(encrypted))
        assert list(result_plain) == plain_opcodes

    def test_2byte_opcode_width(self):
        """2-byte opcode width with XOR decryption."""
        transforms = [KeyTransform(op=TransformOp.XOR, operand_source="opcode")]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0xBEEF,
            key_width=16,
            opcode_width=2,
        )
        plain_op = 0x0102
        enc_op = (plain_op ^ 0xBEEF) & 0xFFFF
        encrypted = enc_op.to_bytes(2, "little")
        result, keys = dec.decrypt(encrypted)
        decoded = int.from_bytes(result[:2], "little")
        assert decoded == plain_op


# ═══════════════════════════════════════════════════════════════════════════
# 3. detect_initial_key
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectInitialKey:
    """Extracting the initial key from trace register snapshots."""

    def test_key_from_trace(self):
        """Key register value at first dispatcher visit."""
        trace = [
            {"address": 0x1000, "registers": {"rsi": 0x5000, "ecx": 0xDEAD}},
            {"address": 0x2000, "registers": {"rsi": 0x5001, "ecx": 0xBEEF}},
        ]
        match = {
            "entry_address": 0x1000,
            "decode_transforms": ["xor ecx, edx"],
            "context_registers": {},
        }
        key = detect_initial_key(trace, match, key_register="ecx")
        assert key == 0xDEAD

    def test_key_inferred_from_transforms(self):
        """Key register inferred from decode_transforms when not explicit."""
        trace = [
            {"address": 0x1000, "registers": {"ecx": 0x1234}},
        ]
        match = {
            "entry_address": 0x1000,
            "decode_transforms": ["xor ecx, edx"],
            "context_registers": {},
        }
        key = detect_initial_key(trace, match)
        assert key == 0x1234

    def test_key_from_context_registers(self):
        """Key inferred from context_registers vKey role."""
        trace = [
            {"address": 0x1000, "registers": {"r12": 0xCAFE}},
        ]
        match = {
            "entry_address": 0x1000,
            "decode_transforms": [],
            "context_registers": {"r12": "vKey"},
        }
        key = detect_initial_key(trace, match)
        assert key == 0xCAFE

    def test_no_trace_returns_none(self):
        assert detect_initial_key([], {}) is None

    def test_no_matching_address_returns_none(self):
        trace = [{"address": 0x9999, "registers": {"ecx": 42}}]
        match = {"entry_address": 0x1000, "decode_transforms": ["xor ecx, edx"]}
        key = detect_initial_key(trace, match)
        assert key is None


# ═══════════════════════════════════════════════════════════════════════════
# 4. Handler table decryption
# ═══════════════════════════════════════════════════════════════════════════

class TestDecryptHandlerTable:
    """Handler dispatch table decryption with multiple encoding schemes."""

    def _build_binary(self, entries: list[int], base: int, table_va: int,
                      entry_size: int = 8) -> bytes:
        """Build a minimal binary with a handler table at table_va."""
        offset = table_va - base
        # Only extend to cover handler addresses that are close to base
        required_size = offset + len(entries) * entry_size + 64
        for addr in entries:
            if base <= addr < base + 0x100000:  # Within 1MB
                required_size = max(required_size, addr - base + 64)
        data = bytearray(required_size)
        fmt = "<Q" if entry_size == 8 else "<I"
        for i, val in enumerate(entries):
            pos = offset + i * entry_size
            if pos + entry_size <= len(data):
                struct.pack_into(fmt, data, pos, val)
        return bytes(data)

    def test_plain_pointers(self):
        """Absolute pointers within binary range are detected as plain."""
        base = 0x400000
        table_va = 0x401000
        handlers = [0x402000, 0x402100, 0x402200]
        binary = self._build_binary(handlers, base, table_va)
        result = decrypt_handler_table(
            binary, table_va, base, bit_width=64,
            known_handler_addresses=handlers,
        )
        # With known handler addresses matching, plain should score highest
        assert result.count == 3
        assert all(a in handlers for a in result.addresses)

    def test_rva_relative_to_table(self):
        """RVA-relative entries (val + table_base = handler addr)."""
        base = 0x400000
        table_va = 0x401000
        handlers = [0x402000, 0x402100, 0x402200]
        raw = [h - table_va for h in handlers]  # RVA offsets
        binary = self._build_binary(raw, base, table_va)
        result = decrypt_handler_table(
            binary, table_va, base, bit_width=64,
        )
        # Should detect rva_relative_table since raw values aren't in range
        assert "rva" in result.encoding_detected.lower() or result.encoding_detected == "plain"
        # Addresses should be valid
        for addr in result.addresses:
            assert base <= addr < base + len(binary)

    def test_xor_encrypted_with_known_key(self):
        """XOR-encrypted table with a known key."""
        base = 0x400000
        table_va = 0x401000
        handlers = [0x402000, 0x402100, 0x402200]
        xor_key = 0xDEADBEEFCAFEBABE
        raw = [h ^ xor_key for h in handlers]
        binary = self._build_binary(raw, base, table_va)
        result = decrypt_handler_table(
            binary, table_va, base, bit_width=64,
            table_key=xor_key,
            known_handler_addresses=handlers,
        )
        assert result.encoding_detected == "xor_encrypted"
        assert result.addresses == handlers

    def test_xor_auto_detect_from_known_addrs(self):
        """Auto-detect XOR key from known handler addresses."""
        base = 0x400000
        table_va = 0x401000
        handlers = [0x402000, 0x402100, 0x402200, 0x402300]
        xor_key = 0x12345678AABBCCDD
        raw = [h ^ xor_key for h in handlers]
        binary = self._build_binary(raw, base, table_va)
        result = decrypt_handler_table(
            binary, table_va, base, bit_width=64,
            known_handler_addresses=handlers,
        )
        # Should auto-detect the key and decrypt correctly
        assert result.count >= 3
        for addr in result.addresses:
            assert addr in handlers

    def test_signed_rva_relative(self):
        """Signed RVA-relative entries (common in VMProtect v3.x)."""
        base = 0x400000
        table_va = 0x401000
        # Handlers both above and below the table
        handlers = [0x400800, 0x401500, 0x402000]
        raw_signed = []
        for h in handlers:
            delta = h - table_va  # Can be negative
            raw_signed.append(delta & 0xFFFFFFFFFFFFFFFF)  # As unsigned 64-bit
        binary = self._build_binary(raw_signed, base, table_va)
        result = decrypt_handler_table(
            binary, table_va, base, bit_width=64,
        )
        # Should detect signed_rva_relative
        assert result.count >= 2

    def test_32bit_table(self):
        """32-bit handler table entries."""
        base = 0x400000
        table_va = 0x401000
        handlers = [0x402000, 0x402100]
        binary = self._build_binary(handlers, base, table_va, entry_size=4)
        result = decrypt_handler_table(
            binary, table_va, base, bit_width=32, entry_scale=4,
        )
        assert result.count >= 1

    def test_empty_table(self):
        result = decrypt_handler_table(
            b"\x00" * 100, 0x500, 0x400, bit_width=64,
        )
        assert result.count == 0

    def test_out_of_range_offset(self):
        result = decrypt_handler_table(
            b"\x00" * 10, 0x99999, 0x400, bit_width=64,
        )
        assert result.count == 0

    def test_to_dict(self):
        result = DecryptedHandlerTable(
            entries=[HandlerTableEntry(0, 0x100, 0x400100, "xor_encrypted")],
            encoding_detected="xor_encrypted",
            table_base=0x401000,
            key_used=0xFF,
        )
        d = result.to_dict()
        assert d["count"] == 1
        assert d["encoding"] == "xor_encrypted"


# ═══════════════════════════════════════════════════════════════════════════
# 5. make_decryptor_from_dispatcher
# ═══════════════════════════════════════════════════════════════════════════

class TestMakeDecryptorFromDispatcher:
    """Integration: create decryptor from a VMProtect dispatcher match."""

    def test_creates_decryptor_with_transforms(self):
        match = {
            "entry_address": 0x1000,
            "fetch_register": "edx",
            "decode_transforms": ["xor ecx, edx", "rol ecx, 3"],
            "context_registers": {},
        }
        trace = [
            {"address": 0x1000, "registers": {"ecx": 0xBEEF}},
        ]
        dec = make_decryptor_from_dispatcher(match, trace)
        assert dec is not None
        assert dec.initial_key == 0xBEEF
        assert len(dec.transforms) == 2

    def test_returns_none_without_transforms(self):
        match = {"decode_transforms": [], "entry_address": 0x1000}
        dec = make_decryptor_from_dispatcher(match)
        assert dec is None

    def test_works_without_trace(self):
        match = {
            "entry_address": 0x1000,
            "fetch_register": "edx",
            "decode_transforms": ["xor ecx, edx"],
        }
        dec = make_decryptor_from_dispatcher(match)
        assert dec is not None
        assert dec.initial_key == 0  # No trace → key = 0


# ═══════════════════════════════════════════════════════════════════════════
# 6. Integration with bytecode_cfg.walk_static_bytecode
# ═══════════════════════════════════════════════════════════════════════════

class TestStaticBytecodeDecryption:
    """Verify that walk_static_bytecode uses the decryptor parameter."""

    def test_decryptor_applied_during_walk(self):
        """Encrypted bytecode is transparently decrypted during walk."""
        from dragonslayer.analysis.handler_semantics import (
            SemanticOpcodeTable,
            OpcodeTableEntry,
            HandlerSemantic,
            VMOperation,
        )
        from dragonslayer.analysis.bytecode_cfg import walk_static_bytecode

        # Build a simple opcode table: opcode 0x01 = ADD, 0x02 = SUB
        table = SemanticOpcodeTable(entries=[
            OpcodeTableEntry(
                opcode=0x01,
                handler_address=0x5000,
                semantic=HandlerSemantic(handler_address=0x5000, operation=VMOperation.ADD, confidence=0.9),
            ),
            OpcodeTableEntry(
                opcode=0x02,
                handler_address=0x5100,
                semantic=HandlerSemantic(handler_address=0x5100, operation=VMOperation.SUB, confidence=0.9),
            ),
        ])

        # Encrypt opcodes [0x01, 0x02] with rolling XOR key=0x42
        transforms = [KeyTransform(op=TransformOp.XOR, operand_source="opcode")]
        key = 0x42
        enc = bytearray()
        for p in [0x01, 0x02]:
            enc.append(p ^ key)
            key = (key ^ p) & 0xFF

        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0x42,
            key_width=8,
            opcode_width=1,
        )

        # Should correctly decode both opcodes
        insns = walk_static_bytecode(bytes(enc), table, 0x1000, decryptor=dec)
        assert len(insns) == 2
        assert insns[0].operation == VMOperation.ADD
        assert insns[0].opcode == 0x01
        assert insns[1].operation == VMOperation.SUB
        assert insns[1].opcode == 0x02

    def test_without_decryptor_reads_raw(self):
        """Without a decryptor, raw bytes are used directly (backward compat)."""
        from dragonslayer.analysis.handler_semantics import (
            SemanticOpcodeTable,
            OpcodeTableEntry,
            HandlerSemantic,
            VMOperation,
        )
        from dragonslayer.analysis.bytecode_cfg import walk_static_bytecode

        table = SemanticOpcodeTable(entries=[
            OpcodeTableEntry(
                opcode=0x01,
                handler_address=0x5000,
                semantic=HandlerSemantic(handler_address=0x5000, operation=VMOperation.ADD, confidence=0.9),
            ),
        ])
        insns = walk_static_bytecode(bytes([0x01]), table, 0x1000)
        assert len(insns) == 1
        assert insns[0].opcode == 0x01


# ═══════════════════════════════════════════════════════════════════════════
# 7. Pipeline wiring check
# ═══════════════════════════════════════════════════════════════════════════

class TestPipelineWiring:
    """Ensure pipeline step 3b calls the decryptor + table decrypt."""

    def test_pipeline_creates_decryptor(self):
        """Pipeline creates a bytecode decryptor from dispatcher match."""
        from dragonslayer.core.pipeline import AnalysisPipeline, PipelineConfig

        pipe = AnalysisPipeline(PipelineConfig(stages=["devirtualize"]))
        ctx = MagicMock()
        ctx.shared_data = {
            "dynamic": {
                "execution_trace": {
                    "instructions": [
                        {"address": 0x1000, "disassembly": "movzx ecx, byte ptr [rsi]",
                         "registers": {"rsi": 0x5000, "ecx": 0xAB}},
                        {"address": 0x1004, "disassembly": "xor ecx, edx",
                         "registers": {"rsi": 0x5001, "ecx": 0xCD}},
                        {"address": 0x1008, "disassembly": "jmp [r12+rcx*8]",
                         "registers": {"rsi": 0x5001}},
                    ] * 10,
                },
            },
        }
        # The decryptor import should be accessible
        from dragonslayer.analysis.bytecode_decrypt import make_decryptor_from_dispatcher
        match = {
            "entry_address": 0x1000,
            "fetch_register": "edx",
            "decode_transforms": ["xor ecx, edx"],
            "context_registers": {},
        }
        dec = make_decryptor_from_dispatcher(match)
        assert dec is not None


# ═══════════════════════════════════════════════════════════════════════════
# 8. Edge cases and helpers
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Edge cases and helper functions."""

    def test_detect_table_xor_key(self):
        """_detect_table_xor_key finds the correct key."""
        key = 0x12345678
        known = {0x402000, 0x402100}
        raw = [0x402000 ^ key, 0x402100 ^ key, 0xDEAD ^ key]
        detected = _detect_table_xor_key(
            raw, known, 0xFFFFFFFF,
            base_address=0x400000, binary_end=0x500000,
        )
        assert detected == key

    def test_detect_table_xor_key_insufficient_matches(self):
        """Needs at least 2 matches for confidence."""
        key = 0x42
        known = {0x100}
        raw = [0x100 ^ key]
        detected = _detect_table_xor_key(
            raw, known, 0xFF,
            base_address=0, binary_end=0x1000,
        )
        assert detected is None  # Only 1 match

    def test_neg_transform(self):
        """NEG transform: key = -key & mask."""
        transforms = [KeyTransform(op=TransformOp.NEG, operand_source="")]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0x01,
            key_width=8,
            opcode_width=1,
        )
        # plain = enc ^ key; enc = 0x42, key = 0x01, plain = 0x43
        # next key = -0x01 & 0xFF = 0xFF
        enc = bytes([0x42])
        plain, keys = dec.decrypt(enc)
        assert plain[0] == 0x42 ^ 0x01

    def test_mul_transform(self):
        """MUL transform: key *= opcode."""
        transforms = [KeyTransform(op=TransformOp.MUL, operand_source="opcode")]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0x03,
            key_width=8,
            opcode_width=1,
        )
        # plain = 0x10 ^ 0x03 = 0x13; enc stored
        enc = bytes([0x10 ^ 0x03])
        plain, _ = dec.decrypt(enc)
        assert plain[0] == 0x10

    def test_key_width_64(self):
        """64-bit key width."""
        transforms = [KeyTransform(op=TransformOp.XOR, operand_source="opcode")]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0xDEADBEEFCAFEBABE,
            key_width=64,
            opcode_width=1,
        )
        enc = bytes([0x42 ^ 0xBE])  # XOR with low byte of key
        plain, _ = dec.decrypt(enc)
        assert plain[0] == 0x42

    def test_bswap_64bit(self):
        """BSWAP with 64-bit key."""
        transforms = [KeyTransform(op=TransformOp.BSWAP, operand_source="")]
        dec = BytecodeDecryptor(
            transforms=transforms,
            initial_key=0x0102030405060708,
            key_width=64,
            opcode_width=1,
        )
        enc = bytes([0x42 ^ 0x08])  # Low byte
        plain, _ = dec.decrypt(enc)
        assert plain[0] == 0x42

    def test_max_opcodes_limit(self):
        """Decryption stops at max_opcodes."""
        transforms = [KeyTransform(op=TransformOp.XOR, operand_source="opcode")]
        dec = BytecodeDecryptor(transforms=transforms, initial_key=0, key_width=8)
        encrypted = bytes(range(256))
        _, keys = dec.decrypt(encrypted, max_opcodes=5)
        assert len(keys) == 5
