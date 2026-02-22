"""
Code Virtualizer / Oreans Devirtualisation Pipeline
=====================================================

Protector-specific decoder for **Code Virtualizer 2.x / 3.x** (Oreans
Technologies).  Code Virtualizer is related to Themida (same vendor)
but uses a distinct bytecode VM architecture.

Key differences from VMProtect / Themida:

1. **LODSB / XLAT fetch** — CV's classic fetch loop reads an opcode via
   ``LODSB`` (load string byte) and may decode through ``XLAT``
   (translate table lookup) before dispatching.
2. **Handler table with XLAT translation** — opcodes are first mapped
   through a permutation table (XLAT) before indexing the handler table.
3. **CISC-style handlers** — CV handlers tend to be longer, performing
   the full operation (operand fetch + compute + result store) in one
   handler.
4. **Context in register block** — CV stores the VM context as a
   contiguous array indexed by register number.

This module provides:

* :class:`CVVMProfile`     — describes the CV instance parameters
* :class:`CVBytecodeDecoder` — decrypts and de-permutes CV bytecode
* :func:`identify_cv_version` — detects CV 2.x vs 3.x
* :func:`reconstruct_cv_handler_table` — builds opcode → handler map
* :func:`devirtualize_cv`    — end-to-end CV lifting

Integration
-----------
Called from :func:`~dragonslayer.analysis.pipeline.Pipeline._run_devirtualize`
when ``detected_protector == "cv"`` or ``detected_protector == "code_virtualizer"``.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CV version identification
# ---------------------------------------------------------------------------


class CVVersion(str, Enum):
    """Code Virtualizer version family."""

    CV2 = "cv2"      # Older — simpler handler table, 1-byte opcodes
    CV3 = "cv3"      # Newer — encrypted permutation table, wider opcodes
    UNKNOWN = "unknown"


@dataclass
class CVVMProfile:
    """Describes a Code Virtualizer VM instance.

    Attributes
    ----------
    version : CVVersion
        Detected CV version family.
    vip_register : str
        Register used as virtual IP (typically ESI/RSI).
    vsp_register : str
        Register used as virtual stack pointer.
    context_register : str
        Base register for VM context array.
    handler_table_address : int
        Address of the handler dispatch table.
    xlat_table_address : int
        Address of the XLAT permutation table (0 if not used).
    opcode_width : int
        Opcode size in bytes.
    xlat_table : bytes
        The XLAT permutation table (256 bytes for 1-byte opcodes).
    key_transforms : List[Dict[str, Any]]
        Bytecode decryption transforms (CV3).
    handler_count : int
        Number of handlers.
    """

    version: CVVersion = CVVersion.UNKNOWN
    vip_register: str = "esi"
    vsp_register: str = "ebp"
    context_register: str = "edi"
    handler_table_address: int = 0
    xlat_table_address: int = 0
    opcode_width: int = 1
    xlat_table: bytes = b""
    key_transforms: List[Dict[str, Any]] = field(default_factory=list)
    handler_count: int = 0


# Heuristic indicators for CV version detection
_CV2_INDICATORS = frozenset({"lodsb", "xlat", "xlatb"})
_CV3_INDICATORS = frozenset({"bswap", "ror", "bt"})


def identify_cv_version(
    entry_mnemonics: Sequence[str],
    handler_count: int = 0,
) -> CVVersion:
    """Identify the Code Virtualizer version from VM entry code.

    Parameters
    ----------
    entry_mnemonics : Sequence[str]
        First ~50 mnemonics from the VM entry point.
    handler_count : int
        Number of handlers (CV3 typically has more).

    Returns
    -------
    CVVersion
    """
    mnem_set = frozenset(m.lower() for m in entry_mnemonics)

    cv2_score = len(mnem_set & _CV2_INDICATORS)
    cv3_score = len(mnem_set & _CV3_INDICATORS)

    # CV3 uses more handlers (typically 60+)
    if handler_count >= 60:
        cv3_score += 1
    elif handler_count > 0:
        cv2_score += 1

    # XLAT is the hallmark of CV2
    if "xlat" in mnem_set or "xlatb" in mnem_set:
        cv2_score += 3

    # LODSB is common to both but more CV2
    if "lodsb" in mnem_set:
        cv2_score += 1

    if cv3_score > cv2_score:
        return CVVersion.CV3
    if cv2_score > 0:
        return CVVersion.CV2
    return CVVersion.UNKNOWN


# ---------------------------------------------------------------------------
# Bytecode decryption and de-permutation
# ---------------------------------------------------------------------------


@dataclass
class CVDecryptedOpcode:
    """A single decrypted CV opcode.

    Attributes
    ----------
    offset : int
        Byte offset in the bytecode stream.
    raw_value : int
        Value before any decryption.
    post_decrypt : int
        Value after key-transform decryption (CV3).
    post_xlat : int
        Value after XLAT de-permutation (final opcode).
    key_state : int
        Rolling key before this byte.
    """

    offset: int = 0
    raw_value: int = 0
    post_decrypt: int = 0
    post_xlat: int = 0
    key_state: int = 0


class CVBytecodeDecoder:
    """Decrypt and de-permute Code Virtualizer bytecode.

    CV2: bytecode is XLAT-permuted (no encryption).
    CV3: bytecode is first key-decrypted, then XLAT-permuted.

    Parameters
    ----------
    xlat_table : bytes
        256-byte permutation table.  ``decoded = xlat[encrypted]``.
        If empty, no permutation is applied.
    key_transforms : Sequence[Dict[str, Any]]
        Key-transform chain for CV3 (empty for CV2).
    initial_key : int
        Starting key value (CV3 only).
    key_width : int
        Key register width in bits.
    """

    def __init__(
        self,
        xlat_table: bytes = b"",
        key_transforms: Sequence[Dict[str, Any]] | None = None,
        initial_key: int = 0,
        key_width: int = 32,
    ) -> None:
        self._xlat = xlat_table
        self._transforms = list(key_transforms or [])
        self._initial_key = initial_key & ((1 << key_width) - 1)
        self._key_width = key_width
        self._mask = (1 << key_width) - 1

    def _apply_transform(self, key: int, opcode: int, t: Dict[str, Any]) -> int:
        op = t.get("op", "xor").lower()
        imm = t.get("imm", 0)
        src = t.get("source", "opcode")
        operand = opcode if src == "opcode" else (imm if src == "imm" else key)

        if op == "xor":
            key ^= operand
        elif op == "add":
            key = (key + operand) & self._mask
        elif op == "sub":
            key = (key - operand) & self._mask
        elif op == "rol":
            n = operand % self._key_width
            key = ((key << n) | (key >> (self._key_width - n))) & self._mask
        elif op == "ror":
            n = operand % self._key_width
            key = ((key >> n) | (key << (self._key_width - n))) & self._mask
        elif op == "not":
            key = (~key) & self._mask
        elif op == "neg":
            key = (-key) & self._mask
        elif op == "mul":
            key = (key * operand) & self._mask
        elif op == "bswap":
            if self._key_width == 32:
                key = struct.unpack("<I", struct.pack(">I", key & 0xFFFFFFFF))[0]
            elif self._key_width == 64:
                key = struct.unpack("<Q", struct.pack(">Q", key & 0xFFFFFFFFFFFFFFFF))[0]
        else:
            logger.warning("Unknown CV transform op: %s", op)

        return key & self._mask

    def _xlat_lookup(self, value: int) -> int:
        """Apply XLAT permutation."""
        if self._xlat and len(self._xlat) > value:
            return self._xlat[value]
        return value

    def decrypt(self, data: bytes) -> List[CVDecryptedOpcode]:
        """Decrypt a CV bytecode buffer.

        Returns list of decrypted opcodes.
        """
        result: List[CVDecryptedOpcode] = []
        key = self._initial_key
        offset = 0

        while offset < len(data):
            raw = data[offset]

            # CV3: decrypt with rolling key first
            if self._transforms:
                key_byte = key & 0xFF
                post_decrypt = raw ^ key_byte
            else:
                post_decrypt = raw

            # XLAT de-permutation
            post_xlat = self._xlat_lookup(post_decrypt)

            result.append(CVDecryptedOpcode(
                offset=offset,
                raw_value=raw,
                post_decrypt=post_decrypt,
                post_xlat=post_xlat,
                key_state=key,
            ))

            # Update rolling key (CV3)
            for transform in self._transforms:
                key = self._apply_transform(key, post_xlat, transform)

            offset += 1

        logger.debug("Decrypted %d CV opcodes (%d bytes)", len(result), len(data))
        return result

    def decrypt_to_bytes(self, data: bytes) -> bytes:
        """Convenience: return decoded opcodes as bytes."""
        opcodes = self.decrypt(data)
        return bytes(op.post_xlat & 0xFF for op in opcodes)

    @staticmethod
    def invert_xlat(xlat_table: bytes) -> bytes:
        """Compute the inverse permutation of an XLAT table.

        Given ``xlat[x] = y``, returns ``inv[y] = x``.
        Useful for re-encoding bytecode.
        """
        if len(xlat_table) != 256:
            raise ValueError(f"XLAT table must be 256 bytes, got {len(xlat_table)}")
        inv = bytearray(256)
        for i, v in enumerate(xlat_table):
            inv[v] = i
        return bytes(inv)


# ---------------------------------------------------------------------------
# Handler table reconstruction
# ---------------------------------------------------------------------------


@dataclass
class CVHandlerEntry:
    """One entry in the CV handler dispatch table."""

    opcode: int = 0
    handler_address: int = 0
    handler_size: int = 0
    classification: str = "unknown"


@dataclass
class CVOpcodeTable:
    """Reconstructed Code Virtualizer opcode table."""

    entries: List[CVHandlerEntry] = field(default_factory=list)
    base_address: int = 0
    entry_size: int = 4
    encoding: str = "absolute"

    @property
    def handler_count(self) -> int:
        return len(self.entries)

    def get_handler(self, opcode: int) -> Optional[CVHandlerEntry]:
        for entry in self.entries:
            if entry.opcode == opcode:
                return entry
        return None


def reconstruct_cv_handler_table(
    table_data: bytes,
    base_address: int,
    *,
    entry_size: int = 4,
    encoding: str = "absolute",
    max_entries: int = 256,
    image_base: int = 0,
) -> CVOpcodeTable:
    """Reconstruct a Code Virtualizer handler table.

    Parameters
    ----------
    table_data : bytes
        Raw bytes of the handler dispatch table.
    base_address : int
        Virtual address of the table start.
    entry_size : int
        4 for x86, 8 for x64.
    encoding : str
        ``"absolute"`` or ``"base_relative"``.
    max_entries : int
        Safety cap.
    image_base : int
        PE image base (for RVA calculations).

    Returns
    -------
    CVOpcodeTable
    """
    fmt = "<I" if entry_size == 4 else "<Q"
    entries: List[CVHandlerEntry] = []
    n_entries = min(len(table_data) // entry_size, max_entries)

    for i in range(n_entries):
        raw = struct.unpack_from(fmt, table_data, i * entry_size)[0]

        if encoding == "base_relative":
            if entry_size == 4:
                signed = struct.unpack_from("<i", table_data, i * entry_size)[0]
            else:
                signed = struct.unpack_from("<q", table_data, i * entry_size)[0]
            handler_addr = base_address + signed
        elif encoding == "rva_relative":
            handler_addr = image_base + raw
        else:
            handler_addr = raw

        if handler_addr == 0 or handler_addr == image_base:
            continue

        entries.append(CVHandlerEntry(opcode=i, handler_address=handler_addr))

    table = CVOpcodeTable(
        entries=entries,
        base_address=base_address,
        entry_size=entry_size,
        encoding=encoding,
    )

    logger.info(
        "Reconstructed CV handler table: %d entries at %#x",
        len(entries), base_address,
    )
    return table


# ---------------------------------------------------------------------------
# Handler classification bridge
# ---------------------------------------------------------------------------


def classify_cv_handler_entries(
    table: CVOpcodeTable,
    binary_data: bytes,
    image_base: int = 0,
    *,
    max_insns: int = 32,
    mode_64: bool = False,
) -> int:
    """Classify CV handler entries using the semantic heuristic.

    Attempts to disassemble the native code at each handler address and
    classify it via :func:`handler_semantics._classify_handler`.

    Falls back gracefully when ``capstone`` is not installed or when
    disassembly produces no valid instructions.

    Parameters
    ----------
    table : CVOpcodeTable
        Opcode table whose entries will be classified *in place*.
    binary_data : bytes
        Raw binary image data.
    image_base : int
        Base address used to compute file offsets from RVAs.
    max_insns : int
        Maximum number of instructions to disassemble per handler.
    mode_64 : bool
        If ``True`` use 64-bit disassembly mode; otherwise 32-bit.

    Returns
    -------
    int
        Number of entries successfully classified (classification != "unknown").
    """
    try:
        import capstone
        from dragonslayer.analysis.handler_semantics import _classify_handler
        from dragonslayer.analysis.trace_ingestion import TraceInstruction
    except ImportError:
        logger.debug(
            "Capstone or handler_semantics not available — "
            "skipping CV handler classification"
        )
        return 0

    cs_mode = capstone.CS_MODE_64 if mode_64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, cs_mode)
    md.detail = False

    classified = 0

    for entry in table.entries:
        offset = entry.handler_address - image_base
        if offset < 0 or offset >= len(binary_data):
            continue

        code = binary_data[offset : offset + max_insns * 15]
        insns = []
        for addr, size, mnem, op_str in md.disasm_lite(code, entry.handler_address):
            insns.append(TraceInstruction(
                address=addr,
                size=size,
                raw_bytes=binary_data[addr - image_base : addr - image_base + size],
                disassembly=f"{mnem} {op_str}".strip(),
            ))
            if len(insns) >= max_insns:
                break

        if not insns:
            continue

        sem = _classify_handler(entry.handler_address, insns)
        if sem.operation != "vm_unknown":
            entry.classification = sem.operation
            classified += 1

    if classified:
        logger.info(
            "Classified %d / %d CV handler entries",
            classified, len(table.entries),
        )
    return classified


# ---------------------------------------------------------------------------
# End-to-end devirtualisation
# ---------------------------------------------------------------------------


@dataclass
class CVDevirtResult:
    """Result of Code Virtualizer devirtualisation.

    Attributes
    ----------
    profile : CVVMProfile
        Detected CV parameters.
    opcode_table : CVOpcodeTable
        Reconstructed handler table.
    decrypted_bytecode : bytes
        Plaintext bytecode stream.
    handler_classifications : Dict[int, str]
        Opcode → category mapping.
    lifted_instructions : List[Dict[str, Any]]
        Lifted virtual instructions.
    success : bool
        Whether devirtualisation completed.
    errors : List[str]
        Non-fatal errors.
    """

    profile: CVVMProfile = field(default_factory=CVVMProfile)
    opcode_table: CVOpcodeTable = field(default_factory=CVOpcodeTable)
    decrypted_bytecode: bytes = b""
    handler_classifications: Dict[int, str] = field(default_factory=dict)
    lifted_instructions: List[Dict[str, Any]] = field(default_factory=list)
    success: bool = False
    errors: List[str] = field(default_factory=list)


def devirtualize_cv(
    bytecode: bytes,
    *,
    profile: Optional[CVVMProfile] = None,
    table_data: Optional[bytes] = None,
    image_base: int = 0x400000,
    entry_mnemonics: Optional[Sequence[str]] = None,
    binary_data: Optional[bytes] = None,
) -> CVDevirtResult:
    """End-to-end Code Virtualizer devirtualisation.

    Steps:
    1. Identify CV version (2.x / 3.x)
    2. Decrypt/de-permute bytecode stream
    3. Reconstruct handler table
    4. Map opcodes to handler classifications
    5. Produce lifted instruction list

    Parameters
    ----------
    bytecode : bytes
        Encrypted/permuted bytecode stream.
    profile : CVVMProfile, optional
        Pre-identified parameters (if ``None``, defaults used).
    table_data : bytes, optional
        Raw handler table bytes.
    image_base : int
        PE image base.
    entry_mnemonics : Sequence[str], optional
        VM entry mnemonics for version detection.
    binary_data : bytes, optional
        Full PE image for handler disassembly/classification.

    Returns
    -------
    CVDevirtResult
    """
    result = CVDevirtResult()

    # Step 1: Version identification
    if profile is None:
        profile = CVVMProfile()
    if entry_mnemonics:
        profile.version = identify_cv_version(
            entry_mnemonics,
            handler_count=profile.handler_count,
        )
    result.profile = profile

    # Step 2: Decrypt/de-permute bytecode
    try:
        decoder = CVBytecodeDecoder(
            xlat_table=profile.xlat_table,
            key_transforms=profile.key_transforms if profile.key_transforms else None,
            initial_key=0,
            key_width=32,
        )
        result.decrypted_bytecode = decoder.decrypt_to_bytes(bytecode)
    except (struct.error, ValueError, IndexError, OverflowError) as exc:
        result.errors.append(f"CV bytecode decryption failed: {exc}")
        logger.warning("CV bytecode decryption failed: %s", exc)

    # Step 3: Reconstruct handler table
    if table_data is not None:
        try:
            result.opcode_table = reconstruct_cv_handler_table(
                table_data,
                base_address=profile.handler_table_address,
                entry_size=4 if profile.opcode_width == 1 else 8,
                encoding="absolute",
                image_base=image_base,
            )
        except (struct.error, ValueError, IndexError, OverflowError) as exc:
            result.errors.append(f"CV handler table reconstruction failed: {exc}")
            logger.warning("CV handler table reconstruction failed: %s", exc)

    # Step 4: Classify handlers + map opcodes
    if result.opcode_table.entries and binary_data:
        classify_cv_handler_entries(
            result.opcode_table,
            binary_data,
            image_base=image_base,
        )
    for entry in result.opcode_table.entries:
        result.handler_classifications[entry.opcode] = entry.classification

    # Step 5: Lift bytecode
    if result.decrypted_bytecode:
        bc = result.decrypted_bytecode
        offset = 0
        while offset < len(bc):
            opcode = bc[offset]
            category = result.handler_classifications.get(opcode, "unknown")
            handler = result.opcode_table.get_handler(opcode)
            result.lifted_instructions.append({
                "offset": offset,
                "opcode": opcode,
                "category": category,
                "handler_address": handler.handler_address if handler else 0,
            })
            offset += 1

    result.success = len(result.errors) == 0
    logger.info(
        "CV devirtualisation: version=%s, %d opcodes, %d handlers, success=%s",
        profile.version.value,
        len(result.lifted_instructions),
        result.opcode_table.handler_count,
        result.success,
    )
    return result
