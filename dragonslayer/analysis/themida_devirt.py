"""
Themida / WinLicense Devirtualisation Pipeline
================================================

Protector-specific decoder for **Themida 3.x / WinLicense** virtual machines.

Unlike VMProtect (rolling-key XOR), Themida uses a different bytecode
encoding scheme:

1. **PUSHAD-style VM entry** — saves all general-purpose registers, loads
   the VM context pointer from a hard-coded address.
2. **Bytecode fetch** — reads opcodes through a register-indirect fetch,
   typically ``MOV AL, [ESI]`` / ``INC ESI``.
3. **Multi-layer key transform** — opcodes may be encrypted with one or
   more transforms (XOR/ADD/SUB/ROL) applied in sequence.
4. **Handler dispatch** — handler table indexed by opcode, typically via
   ``JMP [TABLE + opcode*4]`` or an equivalent sequence.
5. **Fish / Dolphin / Eagle variants** — different internal VM engines
   within Themida, each with distinct handler layouts.

This module provides:

* :class:`ThemidaVMProfile`     — describes the variant / parameters
* :class:`ThemidaBytecodeDecoder` — decrypts Themida bytecode
* :func:`identify_themida_variant` — determines Fish/Dolphin/Eagle
* :func:`reconstruct_opcode_table` — builds virtual-to-native mapping
* :func:`devirtualize_themida`     — end-to-end Themida lifting

Integration
-----------
Called from :func:`~dragonslayer.analysis.pipeline.Pipeline._run_devirtualize`
when ``detected_protector == "themida"``.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Themida VM variant identification
# ---------------------------------------------------------------------------


class ThemidaVariant(str, Enum):
    """Known Themida virtual-machine engines."""

    FISH = "fish"          # Oldest engine — simple bytecode, small handler set
    DOLPHIN = "dolphin"    # Medium complexity — compressed handler table
    EAGLE = "eagle"        # Newest engine — multi-layer encryption, larger opcode set
    UNKNOWN = "unknown"


@dataclass
class ThemidaVMProfile:
    """Describes a Themida VM instance's parameters.

    Attributes
    ----------
    variant : ThemidaVariant
        Identified Themida engine (Fish/Dolphin/Eagle).
    vip_register : str
        Register used as virtual instruction pointer.
    vsp_register : str
        Register used as virtual stack pointer.
    context_base : str
        Register holding pointer to VM context save area.
    handler_table_address : int
        RVA or VA of the handler dispatch table.
    opcode_width : int
        Opcode size in bytes (1 or 2, Fish uses 1, Eagle may use 2).
    key_transforms : List[Dict[str, Any]]
        Ordered list of bytecode decryption transforms.
    handler_count : int
        Estimated number of handlers in the dispatch table.
    """

    variant: ThemidaVariant = ThemidaVariant.UNKNOWN
    vip_register: str = "esi"
    vsp_register: str = "ebp"
    context_base: str = "edi"
    handler_table_address: int = 0
    opcode_width: int = 1
    key_transforms: List[Dict[str, Any]] = field(default_factory=list)
    handler_count: int = 0


# Heuristic patterns for variant identification
_FISH_INDICATORS = frozenset({
    "pushad", "pushfd",  # Classic x86 context save
})
_DOLPHIN_INDICATORS = frozenset({
    "cvtsi2sd",  # Dolphin occasionally uses FPU instructions
    "bswap",     # Handler table address obfuscation
})
_EAGLE_INDICATORS = frozenset({
    "vmxon", "cpuid",  # Anti-analysis checks in Eagle
    "rdrand",           # Hardware RNG for key diversification
})


def identify_themida_variant(
    entry_mnemonics: Sequence[str],
    handler_count: int = 0,
) -> ThemidaVariant:
    """Identify the Themida engine variant from VM entry/dispatch code.

    Parameters
    ----------
    entry_mnemonics : Sequence[str]
        First ~50 mnemonics from the VM entry point.
    handler_count : int
        Number of handler addresses in the dispatch table (if known).

    Returns
    -------
    ThemidaVariant
        Best-guess variant.
    """
    mnem_set = frozenset(m.lower() for m in entry_mnemonics)

    eagle_score = len(mnem_set & _EAGLE_INDICATORS)
    dolphin_score = len(mnem_set & _DOLPHIN_INDICATORS)
    fish_score = len(mnem_set & _FISH_INDICATORS)

    # Eagle has more handlers (typically 80+)
    if handler_count >= 80:
        eagle_score += 2
    elif handler_count >= 50:
        dolphin_score += 1

    # Eagle uses 2-byte opcodes
    if handler_count > 256:
        eagle_score += 3

    scores = {
        ThemidaVariant.EAGLE: eagle_score,
        ThemidaVariant.DOLPHIN: dolphin_score,
        ThemidaVariant.FISH: fish_score,
    }

    best = max(scores, key=scores.get)  # type: ignore[arg-type]
    if scores[best] == 0:
        # Cannot distinguish — default to Fish (most common in the wild)
        return ThemidaVariant.FISH if fish_score == 0 and dolphin_score == 0 else best

    logger.debug(
        "Themida variant scores: fish=%d dolphin=%d eagle=%d → %s",
        fish_score, dolphin_score, eagle_score, best.value,
    )
    return best


# ---------------------------------------------------------------------------
# Bytecode decryption
# ---------------------------------------------------------------------------


@dataclass
class ThemidaDecryptedOpcode:
    """A single decrypted Themida opcode.

    Attributes
    ----------
    offset : int
        Byte offset in the bytecode stream.
    encrypted_value : int
        Raw value before decryption.
    decrypted_value : int
        Value after applying key transforms.
    key_state : int
        Rolling key value *before* this byte was processed.
    """

    offset: int = 0
    encrypted_value: int = 0
    decrypted_value: int = 0
    key_state: int = 0


class ThemidaBytecodeDecoder:
    """Decrypt Themida bytecode streams.

    Themida bytecode is encrypted with a rolling key similar to VMProtect
    but using potentially different transform sequences. The key is
    updated after each opcode fetch.

    Parameters
    ----------
    key_transforms : Sequence[Dict[str, Any]]
        Ordered transform list.  Each dict has ``op`` (str) and
        optionally ``imm`` (int) or ``source`` (str = "opcode"/"key").
    initial_key : int
        Starting key value.
    key_width : int
        Key register width in bits (default 32 for x86 Themida).
    opcode_width : int
        Opcode size in bytes (1 or 2).
    """

    def __init__(
        self,
        key_transforms: Sequence[Dict[str, Any]],
        initial_key: int = 0,
        key_width: int = 32,
        opcode_width: int = 1,
    ) -> None:
        self._transforms = list(key_transforms)
        self._initial_key = initial_key & self._mask(key_width)
        self._key_width = key_width
        self._mask_val = self._mask(key_width)
        self._opcode_width = opcode_width

    @staticmethod
    def _mask(bits: int) -> int:
        return (1 << bits) - 1

    def _apply_transform(self, key: int, opcode: int, transform: Dict[str, Any]) -> int:
        """Apply one key-transform step."""
        op = transform.get("op", "xor").lower()
        imm = transform.get("imm", 0)
        source = transform.get("source", "opcode")
        operand = opcode if source == "opcode" else (imm if source == "imm" else key)

        if op == "xor":
            key ^= operand
        elif op == "add":
            key = (key + operand) & self._mask_val
        elif op == "sub":
            key = (key - operand) & self._mask_val
        elif op == "rol":
            n = operand % self._key_width
            key = ((key << n) | (key >> (self._key_width - n))) & self._mask_val
        elif op == "ror":
            n = operand % self._key_width
            key = ((key >> n) | (key << (self._key_width - n))) & self._mask_val
        elif op == "not":
            key = (~key) & self._mask_val
        elif op == "neg":
            key = (-key) & self._mask_val
        elif op == "mul":
            key = (key * operand) & self._mask_val
        elif op == "bswap":
            if self._key_width == 32:
                key = struct.unpack("<I", struct.pack(">I", key & 0xFFFFFFFF))[0]
            elif self._key_width == 64:
                key = struct.unpack("<Q", struct.pack(">Q", key & 0xFFFFFFFFFFFFFFFF))[0]
        else:
            logger.warning("Unknown transform op: %s", op)

        return key & self._mask_val

    def decrypt(self, data: bytes) -> List[ThemidaDecryptedOpcode]:
        """Decrypt a Themida bytecode buffer.

        Parameters
        ----------
        data : bytes
            Raw (encrypted) bytecode stream.

        Returns
        -------
        List[ThemidaDecryptedOpcode]
            Decrypted opcodes in order.
        """
        result: List[ThemidaDecryptedOpcode] = []
        key = self._initial_key
        offset = 0

        while offset + self._opcode_width <= len(data):
            if self._opcode_width == 1:
                encrypted = data[offset]
            else:
                encrypted = int.from_bytes(
                    data[offset:offset + self._opcode_width], "little"
                )

            # Decrypt: XOR with current key (low byte(s))
            key_byte = key & ((1 << (self._opcode_width * 8)) - 1)
            decrypted = encrypted ^ key_byte

            result.append(ThemidaDecryptedOpcode(
                offset=offset,
                encrypted_value=encrypted,
                decrypted_value=decrypted,
                key_state=key,
            ))

            # Update key through transform chain
            for transform in self._transforms:
                key = self._apply_transform(key, decrypted, transform)

            offset += self._opcode_width

        logger.debug(
            "Decrypted %d Themida opcodes (%d bytes, key_width=%d)",
            len(result), len(data), self._key_width,
        )
        return result

    def decrypt_to_bytes(self, data: bytes) -> bytes:
        """Convenience: decrypt and return raw decrypted byte sequence."""
        opcodes = self.decrypt(data)
        if self._opcode_width == 1:
            return bytes(op.decrypted_value & 0xFF for op in opcodes)
        return b"".join(
            op.decrypted_value.to_bytes(self._opcode_width, "little")
            for op in opcodes
        )


# ---------------------------------------------------------------------------
# Handler table reconstruction
# ---------------------------------------------------------------------------


@dataclass
class ThemidaHandlerEntry:
    """One entry in the Themida handler dispatch table.

    Attributes
    ----------
    opcode : int
        Virtual opcode value.
    handler_address : int
        Address (RVA or VA) of the native handler code.
    handler_size : int
        Estimated size in bytes (0 if unknown).
    classification : str
        Handler category (from ML or heuristic classifier).
    """

    opcode: int = 0
    handler_address: int = 0
    handler_size: int = 0
    classification: str = "unknown"


@dataclass
class ThemidaOpcodeTable:
    """Reconstructed Themida opcode table.

    Attributes
    ----------
    entries : List[ThemidaHandlerEntry]
        All identified handler entries.
    base_address : int
        Base address of the handler table.
    entry_size : int
        Size of each table entry in bytes.
    encoding : str
        Encoding format: "absolute", "rva_relative", "base_relative".
    """

    entries: List[ThemidaHandlerEntry] = field(default_factory=list)
    base_address: int = 0
    entry_size: int = 4
    encoding: str = "absolute"

    @property
    def handler_count(self) -> int:
        return len(self.entries)

    def get_handler(self, opcode: int) -> Optional[ThemidaHandlerEntry]:
        """Look up a handler by virtual opcode."""
        for entry in self.entries:
            if entry.opcode == opcode:
                return entry
        return None


def reconstruct_opcode_table(
    table_data: bytes,
    base_address: int,
    *,
    entry_size: int = 4,
    encoding: str = "rva_relative",
    max_entries: int = 256,
    image_base: int = 0,
) -> ThemidaOpcodeTable:
    """Reconstruct a Themida handler dispatch table from raw bytes.

    Parameters
    ----------
    table_data : bytes
        Raw bytes of the handler table region.
    base_address : int
        Virtual address of the table start.
    entry_size : int
        Size of each pointer entry (4 for x86, 8 for x64).
    encoding : str
        ``"absolute"`` — entries are absolute VAs.
        ``"rva_relative"`` — entries are RVAs relative to image base.
        ``"base_relative"`` — entries are signed offsets from table base.
    max_entries : int
        Safety cap on number of entries to parse.
    image_base : int
        PE image base, needed for ``"rva_relative"`` encoding.

    Returns
    -------
    ThemidaOpcodeTable
        Reconstructed opcode table.
    """
    fmt = "<I" if entry_size == 4 else "<Q"
    entries: List[ThemidaHandlerEntry] = []

    n_entries = min(len(table_data) // entry_size, max_entries)

    for i in range(n_entries):
        raw = struct.unpack_from(fmt, table_data, i * entry_size)[0]

        if encoding == "rva_relative":
            handler_addr = image_base + raw
        elif encoding == "base_relative":
            # Signed offset from table base
            if entry_size == 4:
                signed = struct.unpack_from("<i", table_data, i * entry_size)[0]
            else:
                signed = struct.unpack_from("<q", table_data, i * entry_size)[0]
            handler_addr = base_address + signed
        else:  # absolute
            handler_addr = raw

        # Sanity check: skip null entries or obviously invalid addresses
        if handler_addr == 0 or handler_addr == image_base:
            continue

        entries.append(ThemidaHandlerEntry(
            opcode=i,
            handler_address=handler_addr,
        ))

    table = ThemidaOpcodeTable(
        entries=entries,
        base_address=base_address,
        entry_size=entry_size,
        encoding=encoding,
    )

    logger.info(
        "Reconstructed Themida handler table: %d entries at %#x (encoding=%s)",
        len(entries), base_address, encoding,
    )
    return table


# ---------------------------------------------------------------------------
# End-to-end devirtualisation
# ---------------------------------------------------------------------------


@dataclass
class ThemidaDevirtResult:
    """Result of Themida devirtualisation.

    Attributes
    ----------
    profile : ThemidaVMProfile
        Detected VM parameters.
    opcode_table : ThemidaOpcodeTable
        Reconstructed handler dispatch table.
    decrypted_bytecode : bytes
        Plaintext bytecode stream.
    handler_classifications : Dict[int, str]
        Opcode → category mapping.
    lifted_instructions : List[Dict[str, Any]]
        Lifted IR / pseudocode entries (one per virtual instruction).
    success : bool
        Whether devirtualisation completed without fatal errors.
    errors : List[str]
        Non-fatal error messages.
    """

    profile: ThemidaVMProfile = field(default_factory=ThemidaVMProfile)
    opcode_table: ThemidaOpcodeTable = field(default_factory=ThemidaOpcodeTable)
    decrypted_bytecode: bytes = b""
    handler_classifications: Dict[int, str] = field(default_factory=dict)
    lifted_instructions: List[Dict[str, Any]] = field(default_factory=list)
    success: bool = False
    errors: List[str] = field(default_factory=list)


def devirtualize_themida(
    bytecode: bytes,
    *,
    profile: Optional[ThemidaVMProfile] = None,
    table_data: Optional[bytes] = None,
    image_base: int = 0x400000,
    entry_mnemonics: Optional[Sequence[str]] = None,
) -> ThemidaDevirtResult:
    """End-to-end Themida devirtualisation.

    Steps:
    1. Identify Themida variant (Fish/Dolphin/Eagle)
    2. Decrypt bytecode stream
    3. Reconstruct opcode table
    4. Map opcodes to handler classifications
    5. Produce lifted instruction list

    Parameters
    ----------
    bytecode : bytes
        Encrypted bytecode stream.
    profile : ThemidaVMProfile, optional
        Pre-identified VM parameters. If ``None``, defaults are used.
    table_data : bytes, optional
        Raw handler table bytes. If ``None``, opcode table is not built.
    image_base : int
        PE image base address.
    entry_mnemonics : Sequence[str], optional
        VM entry mnemonics for variant identification.

    Returns
    -------
    ThemidaDevirtResult
    """
    result = ThemidaDevirtResult()

    # Step 1: Variant identification
    if profile is None:
        profile = ThemidaVMProfile()
    if entry_mnemonics:
        profile.variant = identify_themida_variant(
            entry_mnemonics,
            handler_count=profile.handler_count,
        )
    result.profile = profile

    # Step 2: Decrypt bytecode
    try:
        decoder = ThemidaBytecodeDecoder(
            key_transforms=profile.key_transforms or [{"op": "xor", "source": "opcode"}],
            initial_key=0,
            key_width=32,
            opcode_width=profile.opcode_width,
        )
        result.decrypted_bytecode = decoder.decrypt_to_bytes(bytecode)
    except Exception as exc:
        result.errors.append(f"Bytecode decryption failed: {exc}")
        logger.warning("Themida bytecode decryption failed: %s", exc)

    # Step 3: Reconstruct opcode table
    if table_data is not None:
        try:
            result.opcode_table = reconstruct_opcode_table(
                table_data,
                base_address=profile.handler_table_address,
                entry_size=4 if profile.opcode_width == 1 else 8,
                encoding="base_relative",
                image_base=image_base,
            )
        except Exception as exc:
            result.errors.append(f"Opcode table reconstruction failed: {exc}")
            logger.warning("Themida opcode table reconstruction failed: %s", exc)

    # Step 4: Map opcodes → classifications (using table if available)
    for entry in result.opcode_table.entries:
        result.handler_classifications[entry.opcode] = entry.classification

    # Step 5: Lift decrypted bytecode into instructions
    if result.decrypted_bytecode:
        offset = 0
        bc = result.decrypted_bytecode
        while offset < len(bc):
            opcode = bc[offset] if profile.opcode_width == 1 else int.from_bytes(
                bc[offset:offset + profile.opcode_width], "little"
            )
            category = result.handler_classifications.get(opcode, "unknown")
            result.lifted_instructions.append({
                "offset": offset,
                "opcode": opcode,
                "category": category,
                "handler_address": (
                    result.opcode_table.get_handler(opcode).handler_address
                    if result.opcode_table.get_handler(opcode) else 0
                ),
            })
            offset += profile.opcode_width

    result.success = len(result.errors) == 0
    logger.info(
        "Themida devirtualisation: variant=%s, %d opcodes, %d handlers, success=%s",
        profile.variant.value,
        len(result.lifted_instructions),
        result.opcode_table.handler_count,
        result.success,
    )
    return result
