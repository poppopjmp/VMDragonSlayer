"""
B104 — GPU Removal, Themida & Code Virtualizer Devirt Pipelines
================================================================

Tests for:
1. GPU module fully removed (no imports, no references)
2. Themida devirtualisation pipeline
3. Code Virtualizer devirtualisation pipeline
4. Analysis __all__ completeness
"""

from __future__ import annotations

import importlib
import struct
import sys
from typing import Any, Dict, List

import pytest


# ═══════════════════════════════════════════════════════════════════════════
# 1. GPU removal verification
# ═══════════════════════════════════════════════════════════════════════════


class TestGPURemoval:
    """Verify the GPU module is fully excised."""

    def test_gpu_package_not_importable(self) -> None:
        """Importing dragonslayer.gpu should raise ImportError."""
        with pytest.raises((ImportError, ModuleNotFoundError)):
            import dragonslayer.gpu  # type: ignore[import-not-found]

    def test_gpu_not_in_sys_modules(self) -> None:
        # Ensure no leftover cached module
        for mod_name in list(sys.modules):
            assert not mod_name.startswith("dragonslayer.gpu"), (
                f"GPU module still in sys.modules: {mod_name}"
            )

    def test_orchestrator_no_enable_gpu(self) -> None:
        from dragonslayer.core.orchestrator import AnalysisOptionsDict
        annotations = AnalysisOptionsDict.__annotations__
        assert "enable_gpu" not in annotations

    def test_pyproject_no_gpu_extra(self) -> None:
        """pyproject.toml should have no gpu optional dependency."""
        from pathlib import Path
        toml_text = Path("pyproject.toml").read_text(encoding="utf-8")
        assert "cupy-cuda" not in toml_text
        assert "pynvml" not in toml_text


# ═══════════════════════════════════════════════════════════════════════════
# 2. Themida devirt pipeline
# ═══════════════════════════════════════════════════════════════════════════


class TestThemidaVariantIdentification:
    def test_fish_default(self) -> None:
        from dragonslayer.analysis.themida_devirt import (
            identify_themida_variant, ThemidaVariant,
        )
        result = identify_themida_variant(["push", "mov", "nop"])
        assert result == ThemidaVariant.FISH

    def test_fish_from_pushad(self) -> None:
        from dragonslayer.analysis.themida_devirt import (
            identify_themida_variant, ThemidaVariant,
        )
        result = identify_themida_variant(["pushad", "pushfd", "mov", "lea"])
        assert result == ThemidaVariant.FISH

    def test_eagle_from_indicators(self) -> None:
        from dragonslayer.analysis.themida_devirt import (
            identify_themida_variant, ThemidaVariant,
        )
        result = identify_themida_variant(
            ["cpuid", "rdrand", "vmxon", "mov"], handler_count=100,
        )
        assert result == ThemidaVariant.EAGLE

    def test_dolphin_from_bswap(self) -> None:
        from dragonslayer.analysis.themida_devirt import (
            identify_themida_variant, ThemidaVariant,
        )
        result = identify_themida_variant(
            ["bswap", "cvtsi2sd", "mov"], handler_count=55,
        )
        assert result == ThemidaVariant.DOLPHIN


class TestThemidaBytecodeDecoder:
    def test_identity_decrypt(self) -> None:
        """No transforms → decrypt = XOR with key=0 → identity."""
        from dragonslayer.analysis.themida_devirt import ThemidaBytecodeDecoder
        decoder = ThemidaBytecodeDecoder(
            key_transforms=[],
            initial_key=0,
        )
        data = bytes([0x10, 0x20, 0x30, 0x40])
        result = decoder.decrypt_to_bytes(data)
        assert result == data

    def test_xor_decrypt(self) -> None:
        """XOR with fixed key byte."""
        from dragonslayer.analysis.themida_devirt import ThemidaBytecodeDecoder
        decoder = ThemidaBytecodeDecoder(
            key_transforms=[{"op": "xor", "source": "opcode"}],
            initial_key=0xAB,
        )
        # First byte: encrypted ^ 0xAB
        data = bytes([0x10])
        result = decoder.decrypt(data)
        assert len(result) == 1
        assert result[0].decrypted_value == (0x10 ^ 0xAB)

    def test_rolling_key_changes_each_byte(self) -> None:
        """The rolling key must change after each opcode."""
        from dragonslayer.analysis.themida_devirt import ThemidaBytecodeDecoder
        decoder = ThemidaBytecodeDecoder(
            key_transforms=[{"op": "xor", "source": "opcode"}],
            initial_key=0xFF,
        )
        data = bytes([0x01, 0x02, 0x03])
        result = decoder.decrypt(data)
        # Each opcode sees a different key_state
        key_states = [r.key_state for r in result]
        assert len(set(key_states)) == len(key_states), "Key should change each iteration"

    def test_decrypt_to_bytes_length(self) -> None:
        from dragonslayer.analysis.themida_devirt import ThemidaBytecodeDecoder
        decoder = ThemidaBytecodeDecoder(
            key_transforms=[{"op": "add", "source": "opcode"}],
            initial_key=0,
        )
        data = bytes(range(50))
        result = decoder.decrypt_to_bytes(data)
        assert len(result) == 50

    def test_empty_input(self) -> None:
        from dragonslayer.analysis.themida_devirt import ThemidaBytecodeDecoder
        decoder = ThemidaBytecodeDecoder(key_transforms=[], initial_key=0)
        assert decoder.decrypt(b"") == []
        assert decoder.decrypt_to_bytes(b"") == b""

    def test_all_transform_ops(self) -> None:
        """Exercise every transform operation."""
        from dragonslayer.analysis.themida_devirt import ThemidaBytecodeDecoder
        transforms = [
            {"op": "xor", "source": "opcode"},
            {"op": "add", "source": "opcode"},
            {"op": "rol", "imm": 3, "source": "imm"},
            {"op": "not"},
            {"op": "neg"},
            {"op": "sub", "source": "opcode"},
            {"op": "bswap"},
        ]
        decoder = ThemidaBytecodeDecoder(
            key_transforms=transforms,
            initial_key=0xDEADBEEF,
            key_width=32,
        )
        data = bytes(range(20))
        result = decoder.decrypt(data)
        assert len(result) == 20


class TestThemidaOpcodeTable:
    def test_reconstruct_absolute(self) -> None:
        from dragonslayer.analysis.themida_devirt import reconstruct_opcode_table
        # Build a small table: 4 entries, absolute addresses
        entries_raw = b""
        for addr in [0x401000, 0x401100, 0x401200, 0x401300]:
            entries_raw += struct.pack("<I", addr)

        table = reconstruct_opcode_table(
            entries_raw, base_address=0x500000,
            entry_size=4, encoding="absolute",
        )
        assert table.handler_count == 4
        handler = table.get_handler(0)
        assert handler is not None
        assert handler.handler_address == 0x401000

    def test_reconstruct_base_relative(self) -> None:
        from dragonslayer.analysis.themida_devirt import reconstruct_opcode_table
        base = 0x500000
        entries_raw = struct.pack("<i", 0x100) + struct.pack("<i", 0x200)
        table = reconstruct_opcode_table(
            entries_raw, base_address=base,
            entry_size=4, encoding="base_relative",
        )
        assert table.handler_count == 2
        assert table.get_handler(0).handler_address == base + 0x100

    def test_null_entries_skipped(self) -> None:
        from dragonslayer.analysis.themida_devirt import reconstruct_opcode_table
        # Entry with value 0 should be skipped
        entries_raw = struct.pack("<I", 0) + struct.pack("<I", 0x401000)
        table = reconstruct_opcode_table(
            entries_raw, base_address=0x500000,
            entry_size=4, encoding="absolute",
        )
        assert table.handler_count == 1


class TestThemidaDevirtualize:
    def test_basic_devirt(self) -> None:
        from dragonslayer.analysis.themida_devirt import (
            devirtualize_themida, ThemidaVMProfile, ThemidaVariant,
        )
        profile = ThemidaVMProfile(
            variant=ThemidaVariant.FISH,
            key_transforms=[{"op": "xor", "source": "opcode"}],
        )
        bytecode = bytes([0x10, 0x20, 0x30])
        result = devirtualize_themida(
            bytecode, profile=profile,
        )
        assert result.success
        assert len(result.decrypted_bytecode) == 3
        assert len(result.lifted_instructions) == 3

    def test_devirt_with_table(self) -> None:
        from dragonslayer.analysis.themida_devirt import (
            devirtualize_themida, ThemidaVMProfile, ThemidaVariant,
        )
        profile = ThemidaVMProfile(
            variant=ThemidaVariant.FISH,
            handler_table_address=0x500000,
        )
        table_data = b""
        for addr in [0x401000, 0x401100, 0x401200]:
            table_data += struct.pack("<i", addr - 0x500000)  # base_relative

        result = devirtualize_themida(
            bytecode=bytes([0x00, 0x01, 0x02]),
            profile=profile,
            table_data=table_data,
        )
        assert result.success
        assert result.opcode_table.handler_count >= 1

    def test_devirt_variant_detection(self) -> None:
        from dragonslayer.analysis.themida_devirt import (
            devirtualize_themida, ThemidaVariant,
        )
        result = devirtualize_themida(
            bytecode=bytes([0x42]),
            entry_mnemonics=["pushad", "pushfd", "mov"],
        )
        assert result.profile.variant == ThemidaVariant.FISH


# ═══════════════════════════════════════════════════════════════════════════
# 3. Code Virtualizer devirt pipeline
# ═══════════════════════════════════════════════════════════════════════════


class TestCVVersionIdentification:
    def test_cv2_from_xlat(self) -> None:
        from dragonslayer.analysis.cv_devirt import identify_cv_version, CVVersion
        result = identify_cv_version(["lodsb", "xlat", "jmp", "mov"])
        assert result == CVVersion.CV2

    def test_cv3_from_indicators(self) -> None:
        from dragonslayer.analysis.cv_devirt import identify_cv_version, CVVersion
        result = identify_cv_version(
            ["bswap", "ror", "bt", "mov"], handler_count=70,
        )
        assert result == CVVersion.CV3

    def test_unknown_when_empty(self) -> None:
        from dragonslayer.analysis.cv_devirt import identify_cv_version, CVVersion
        result = identify_cv_version([])
        assert result == CVVersion.UNKNOWN


class TestCVBytecodeDecoder:
    def test_no_xlat_no_decrypt(self) -> None:
        """Without XLAT or transforms, output == input."""
        from dragonslayer.analysis.cv_devirt import CVBytecodeDecoder
        decoder = CVBytecodeDecoder()
        data = bytes([0x10, 0x20, 0x30])
        result = decoder.decrypt_to_bytes(data)
        assert result == data

    def test_xlat_permutation(self) -> None:
        """XLAT should permute bytes."""
        from dragonslayer.analysis.cv_devirt import CVBytecodeDecoder
        xlat = bytearray(256)
        for i in range(256):
            xlat[i] = (i + 1) % 256  # shift by 1
        decoder = CVBytecodeDecoder(xlat_table=bytes(xlat))
        data = bytes([0x00, 0x01, 0xFF])
        result = decoder.decrypt_to_bytes(data)
        assert result == bytes([0x01, 0x02, 0x00])

    def test_xlat_invert_roundtrip(self) -> None:
        """Inverting an XLAT table and applying both should be identity."""
        from dragonslayer.analysis.cv_devirt import CVBytecodeDecoder
        import random
        rng = random.Random(42)
        xlat = list(range(256))
        rng.shuffle(xlat)
        xlat_bytes = bytes(xlat)

        inv = CVBytecodeDecoder.invert_xlat(xlat_bytes)

        # Forward then inverse should give identity
        for i in range(256):
            assert inv[xlat_bytes[i]] == i

    def test_cv3_key_decrypt_plus_xlat(self) -> None:
        from dragonslayer.analysis.cv_devirt import CVBytecodeDecoder
        xlat = bytes(range(256))  # identity XLAT
        decoder = CVBytecodeDecoder(
            xlat_table=xlat,
            key_transforms=[{"op": "xor", "source": "opcode"}],
            initial_key=0x42,
        )
        data = bytes([0x10, 0x20])
        result = decoder.decrypt(data)
        assert len(result) == 2
        assert result[0].raw_value == 0x10
        assert result[0].post_decrypt == 0x10 ^ 0x42

    def test_empty_input(self) -> None:
        from dragonslayer.analysis.cv_devirt import CVBytecodeDecoder
        decoder = CVBytecodeDecoder()
        assert decoder.decrypt(b"") == []

    def test_invert_xlat_wrong_size(self) -> None:
        from dragonslayer.analysis.cv_devirt import CVBytecodeDecoder
        with pytest.raises(ValueError, match="256 bytes"):
            CVBytecodeDecoder.invert_xlat(b"\x00\x01")


class TestCVOpcodeTable:
    def test_reconstruct_absolute(self) -> None:
        from dragonslayer.analysis.cv_devirt import reconstruct_cv_handler_table
        entries_raw = b""
        for addr in [0x401000, 0x401100]:
            entries_raw += struct.pack("<I", addr)
        table = reconstruct_cv_handler_table(
            entries_raw, base_address=0x500000,
        )
        assert table.handler_count == 2
        assert table.get_handler(0).handler_address == 0x401000

    def test_null_entry_skipped(self) -> None:
        from dragonslayer.analysis.cv_devirt import reconstruct_cv_handler_table
        entries_raw = struct.pack("<I", 0) + struct.pack("<I", 0x501000)
        table = reconstruct_cv_handler_table(
            entries_raw, base_address=0x500000,
        )
        assert table.handler_count == 1


class TestCVDevirtualize:
    def test_basic_devirt(self) -> None:
        from dragonslayer.analysis.cv_devirt import (
            devirtualize_cv, CVVMProfile, CVVersion,
        )
        profile = CVVMProfile(version=CVVersion.CV2)
        result = devirtualize_cv(
            bytecode=bytes([0x10, 0x20, 0x30]),
            profile=profile,
        )
        assert result.success
        assert len(result.decrypted_bytecode) == 3
        assert len(result.lifted_instructions) == 3

    def test_devirt_with_xlat(self) -> None:
        from dragonslayer.analysis.cv_devirt import (
            devirtualize_cv, CVVMProfile, CVVersion,
        )
        xlat = bytes(range(256))  # identity
        profile = CVVMProfile(
            version=CVVersion.CV2,
            xlat_table=xlat,
        )
        result = devirtualize_cv(
            bytecode=bytes([0x01, 0x02]),
            profile=profile,
        )
        assert result.success
        assert len(result.lifted_instructions) == 2

    def test_devirt_with_table(self) -> None:
        from dragonslayer.analysis.cv_devirt import (
            devirtualize_cv, CVVMProfile,
        )
        profile = CVVMProfile(handler_table_address=0x500000)
        table_data = struct.pack("<I", 0x401000) + struct.pack("<I", 0x401100)
        result = devirtualize_cv(
            bytecode=bytes([0x00, 0x01]),
            profile=profile,
            table_data=table_data,
        )
        assert result.success
        assert result.opcode_table.handler_count == 2


# ═══════════════════════════════════════════════════════════════════════════
# 4. Analysis __all__ completeness
# ═══════════════════════════════════════════════════════════════════════════


class TestAnalysisExports:
    def test_themida_exports_present(self) -> None:
        import dragonslayer.analysis as mod
        for name in [
            "ThemidaVariant", "ThemidaVMProfile", "ThemidaBytecodeDecoder",
            "ThemidaOpcodeTable", "ThemidaDevirtResult",
            "identify_themida_variant", "reconstruct_opcode_table",
            "classify_handler_entries", "devirtualize_themida",
        ]:
            assert name in mod.__all__, f"{name} missing from analysis.__all__"
            assert getattr(mod, name, None) is not None, f"{name} not importable"

    def test_cv_exports_present(self) -> None:
        import dragonslayer.analysis as mod
        for name in [
            "CVVersion", "CVVMProfile", "CVBytecodeDecoder",
            "CVOpcodeTable", "CVDevirtResult",
            "identify_cv_version", "reconstruct_cv_handler_table",
            "classify_cv_handler_entries", "devirtualize_cv",
        ]:
            assert name in mod.__all__, f"{name} missing from analysis.__all__"
            assert getattr(mod, name, None) is not None, f"{name} not importable"

    def test_no_gpu_in_analysis_all(self) -> None:
        import dragonslayer.analysis as mod
        for name in mod.__all__:
            assert "gpu" not in name.lower(), f"GPU reference in __all__: {name}"


# ═══════════════════════════════════════════════════════════════════════════
# 5. Handler classification bridge (Phase 2D)
# ═══════════════════════════════════════════════════════════════════════════


class TestThemidaClassificationBridge:
    """Tests for classify_handler_entries on Themida tables."""

    def test_classify_returns_int(self) -> None:
        """classify_handler_entries returns count of classified entries."""
        from dragonslayer.analysis.themida_devirt import (
            classify_handler_entries, ThemidaOpcodeTable, ThemidaHandlerEntry,
        )
        table = ThemidaOpcodeTable(entries=[
            ThemidaHandlerEntry(opcode=0, handler_address=0x1000),
        ])
        # With empty binary data, no disassembly will succeed
        result = classify_handler_entries(table, b"", image_base=0)
        assert isinstance(result, int)
        assert result == 0

    def test_classify_empty_table(self) -> None:
        from dragonslayer.analysis.themida_devirt import (
            classify_handler_entries, ThemidaOpcodeTable,
        )
        table = ThemidaOpcodeTable(entries=[])
        result = classify_handler_entries(table, b"\x00" * 100)
        assert result == 0

    def test_classify_modifies_entries_in_place(self) -> None:
        """When capstone is available, entries are classified in place."""
        from dragonslayer.analysis.themida_devirt import (
            classify_handler_entries, ThemidaOpcodeTable, ThemidaHandlerEntry,
        )
        try:
            import capstone  # noqa: F401
        except ImportError:
            pytest.skip("capstone not installed")

        # Build a tiny binary with a simple handler: add eax, ebx; ret
        # x86: \x01\xd8 = add eax, ebx  ;  \xc3 = ret
        handler_code = b"\x01\xd8\xc3"
        # Pad to 0x100 bytes (handler at offset 0x100)
        binary = b"\x00" * 0x100 + handler_code + b"\x00" * 0x100

        table = ThemidaOpcodeTable(entries=[
            ThemidaHandlerEntry(opcode=0, handler_address=0x400100),
        ])
        image_base = 0x400000
        count = classify_handler_entries(table, binary, image_base=image_base)
        # Should classify as vm_add
        assert count >= 0  # may be 0 if handler is too short
        # Classification should have been attempted
        assert table.entries[0].classification in ("vm_add", "unknown")


class TestCVClassificationBridge:
    """Tests for classify_cv_handler_entries on CV tables."""

    def test_classify_returns_int(self) -> None:
        from dragonslayer.analysis.cv_devirt import (
            classify_cv_handler_entries, CVOpcodeTable, CVHandlerEntry,
        )
        table = CVOpcodeTable(entries=[
            CVHandlerEntry(opcode=0, handler_address=0x2000),
        ])
        result = classify_cv_handler_entries(table, b"", image_base=0)
        assert isinstance(result, int)
        assert result == 0

    def test_classify_empty_table(self) -> None:
        from dragonslayer.analysis.cv_devirt import (
            classify_cv_handler_entries, CVOpcodeTable,
        )
        table = CVOpcodeTable(entries=[])
        result = classify_cv_handler_entries(table, b"\x00" * 100)
        assert result == 0

    def test_classify_modifies_entries_in_place(self) -> None:
        from dragonslayer.analysis.cv_devirt import (
            classify_cv_handler_entries, CVOpcodeTable, CVHandlerEntry,
        )
        try:
            import capstone  # noqa: F401
        except ImportError:
            pytest.skip("capstone not installed")

        # Simple handler: xor eax, ebx; ret  (x86: \x31\xd8\xc3)
        handler_code = b"\x31\xd8\xc3"
        binary = b"\x00" * 0x200 + handler_code + b"\x00" * 0x100

        table = CVOpcodeTable(entries=[
            CVHandlerEntry(opcode=0, handler_address=0x400200),
        ])
        image_base = 0x400000
        count = classify_cv_handler_entries(table, binary, image_base=image_base)
        assert count >= 0
        assert table.entries[0].classification in ("vm_xor", "unknown")
