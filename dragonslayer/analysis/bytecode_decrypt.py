"""
Rolling-Key Bytecode Decryption for VMProtect
==============================================

VMProtect encrypts its bytecode stream using a rolling XOR key.  The
dispatcher loop fetches an opcode byte, XORs it with a key register,
then *transforms* the key register (e.g.,  ``xor key, opcode``,
``add key, opcode``, ``rol key, N``, ``not key``, ``bswap key``) before
advancing the vIP.

Without applying these transforms during static bytecode disassembly,
every opcode after the first one is garbage.  This module:

1. **Parses** the ``decode_transforms`` list from a
   :class:`VMProtectDispatcherMatch` into an executable transform
   sequence.
2. **Applies** the rolling-key decryption to a raw bytecode buffer,
   yielding the plaintext opcode stream.
3. **Detects** the initial key value from a trace (first dispatcher
   visit's register snapshot).
4. Provides a **handler-table decryption** helper for encrypted /
   RVA-relative dispatch tables.

Integration
-----------

* Called by :func:`~dragonslayer.analysis.bytecode_cfg.walk_static_bytecode`
  when a ``dispatcher_match`` with ``decode_transforms`` is supplied.
* Called by pipeline step 7b to decrypt bytecode before CFG construction.

Usage::

    from dragonslayer.analysis.bytecode_decrypt import (
        BytecodeDecryptor,
        parse_decode_transforms,
        decrypt_handler_table,
    )

    transforms = parse_decode_transforms(dispatcher_match.decode_transforms)
    decryptor = BytecodeDecryptor(
        transforms=transforms,
        initial_key=0xDEADBEEF,
        key_width=32,
    )
    plaintext = decryptor.decrypt(encrypted_bytecode)
"""

from __future__ import annotations

import logging
import re
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Transform operation types
# ---------------------------------------------------------------------------


class TransformOp(str, Enum):
    """Operations that can be applied to the rolling key."""

    XOR = "xor"
    ADD = "add"
    SUB = "sub"
    NOT = "not"
    NEG = "neg"
    ROL = "rol"
    ROR = "ror"
    BSWAP = "bswap"
    MUL = "mul"
    INC = "inc"
    DEC = "dec"


@dataclass
class KeyTransform:
    """One step in the rolling-key transform sequence.

    Attributes
    ----------
    op : TransformOp
        Operation to perform (xor, add, sub, rol, …).
    operand_source : str
        What the second operand is:
        - ``"opcode"`` — the just-fetched opcode byte / word
        - ``"key"``    — the key itself (self-transform)
        - ``"imm:N"``  — an immediate constant N (decimal)
        - ``""``        — no operand (NOT, NEG, BSWAP, INC, DEC)
    """

    op: TransformOp
    operand_source: str = ""


# ---------------------------------------------------------------------------
# B81: Cipher-chain operations — multi-round decryption
# ---------------------------------------------------------------------------


class CipherOp(str, Enum):
    """Operations used in the decryption cipher chain.

    VMProtect 3.5+ may use 2-4 chained cipher operations per opcode
    (e.g., XOR → ROL → SUB → XOR with a per-round key update).
    """

    XOR = "xor"
    ADD = "add"
    SUB = "sub"
    ROL = "rol"
    ROR = "ror"
    NOT = "not"
    BSWAP = "bswap"


@dataclass
class CipherStep:
    """One step in a multi-round cipher chain.

    Attributes
    ----------
    op : CipherOp
        The cipher operation for this round.
    operand_source : str
        ``"key"`` — use current rolling key, ``"imm:N"`` — immediate,
        ``""`` — unary (NOT, BSWAP).
    """

    op: CipherOp
    operand_source: str = "key"


def _apply_cipher_step(value: int, step: CipherStep, key: int, width: int) -> int:
    """Apply a single cipher step to *value*."""
    mask = (1 << width) - 1
    operand = key
    if step.operand_source.startswith("imm:"):
        try:
            operand = int(step.operand_source[4:])
        except ValueError:
            operand = 0
    elif step.operand_source == "":
        operand = 0

    if step.op == CipherOp.XOR:
        return (value ^ operand) & mask
    if step.op == CipherOp.ADD:
        return (value + operand) & mask
    if step.op == CipherOp.SUB:
        return (value - operand) & mask
    if step.op == CipherOp.ROL:
        shift = operand % width
        return ((value << shift) | (value >> (width - shift))) & mask
    if step.op == CipherOp.ROR:
        shift = operand % width
        return ((value >> shift) | (value << (width - shift))) & mask
    if step.op == CipherOp.NOT:
        return (~value) & mask
    if step.op == CipherOp.BSWAP:
        byte_count = width // 8
        return int.from_bytes(value.to_bytes(byte_count, "little"), "big")
    return value


def auto_detect_cipher_chain(
    decode_transforms: List[KeyTransform],
) -> List[CipherStep]:
    """Infer a cipher chain from existing decode transforms.

    Simple heuristic: the first transform that operates on the opcode
    is the primary cipher step.  Any additional opcode-sourced transforms
    form extra rounds.  Falls back to a single XOR step (standard VMP).
    """
    chain: List[CipherStep] = []
    for t in decode_transforms:
        if t.operand_source == "opcode":
            try:
                chain.append(CipherStep(op=CipherOp(t.op.value), operand_source="key"))
            except ValueError:
                pass
    if not chain:
        chain.append(CipherStep(op=CipherOp.XOR, operand_source="key"))
    return chain


# ---------------------------------------------------------------------------
# B82: Cipher chain verification & inverse computation
# ---------------------------------------------------------------------------

# Inverse operations — used to derive a re-encryption (inverse) chain.
_CIPHER_INVERSE: Dict[CipherOp, CipherOp] = {
    CipherOp.XOR: CipherOp.XOR,     # XOR is self-inverse
    CipherOp.ADD: CipherOp.SUB,
    CipherOp.SUB: CipherOp.ADD,
    CipherOp.ROL: CipherOp.ROR,
    CipherOp.ROR: CipherOp.ROL,
    CipherOp.NOT: CipherOp.NOT,     # NOT is self-inverse
    CipherOp.BSWAP: CipherOp.BSWAP, # BSWAP is self-inverse
}


def inverse_cipher_chain(chain: List[CipherStep]) -> List[CipherStep]:
    """Derive the inverse cipher chain (for re-encryption / patching).

    The inverse chain applies the inverse operation of each step in
    **reverse order**, so ``encrypt(decrypt(x)) == x``.

    Returns
    -------
    list[CipherStep]
        The inverted chain.  Raises ``ValueError`` if any step has no
        known inverse.
    """
    inv: List[CipherStep] = []
    for step in reversed(chain):
        inv_op = _CIPHER_INVERSE.get(step.op)
        if inv_op is None:
            raise ValueError(f"No known inverse for cipher op: {step.op}")
        inv.append(CipherStep(op=inv_op, operand_source=step.operand_source))
    return inv


def verify_cipher_chain(
    chain: List[CipherStep],
    *,
    width: int = 8,
    num_samples: int = 16,
    seed: int = 42,
) -> bool:
    """Verify that a cipher chain round-trips correctly.

    Applies ``encrypt(decrypt(value, key), key) == value`` for
    *num_samples* random (value, key) pairs.  Returns ``True`` iff
    all samples round-trip without error.

    Parameters
    ----------
    chain : list[CipherStep]
        The decryption (forward) chain.
    width : int
        Bit-width of the value being encrypted (8 or 16).
    num_samples : int
        Number of random test pairs.
    seed : int
        RNG seed for reproducibility.
    """
    import random as _rng
    inv = inverse_cipher_chain(chain)
    mask = (1 << width) - 1
    gen = _rng.Random(seed)

    for _ in range(num_samples):
        value = gen.randint(0, mask)
        key = gen.randint(0, mask)
        # Decrypt
        tmp = value
        for step in chain:
            tmp = _apply_cipher_step(tmp, step, key, width)
        plaintext = tmp
        # Re-encrypt with inverse chain
        tmp = plaintext
        for step in inv:
            tmp = _apply_cipher_step(tmp, step, key, width)
        if tmp != value:
            return False
    return True


def cipher_chain_entropy_drop(
    chain: List[CipherStep],
    encrypted: bytes,
    key: int,
    width: int = 8,
) -> float:
    """Measure the entropy drop after applying a cipher chain.

    A correct cipher chain should reduce the Shannon entropy of the
    plaintext versus the ciphertext.  Returns ``H(ciphertext) - H(plaintext)``
    (positive means entropy decreased = likely correct decryption).
    """
    import math

    def _shannon(data: bytes) -> float:
        if not data:
            return 0.0
        freq: Dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        total = len(data)
        return -sum((c / total) * math.log2(c / total) for c in freq.values())

    mask = (1 << width) - 1
    plain = bytearray(len(encrypted))
    for i, enc_byte in enumerate(encrypted):
        tmp = enc_byte & mask
        for step in chain:
            tmp = _apply_cipher_step(tmp, step, key, width)
        plain[i] = tmp & 0xFF

    return _shannon(encrypted) - _shannon(bytes(plain))


# ---------------------------------------------------------------------------
# Parse dispatcher decode_transforms strings
# ---------------------------------------------------------------------------

# Pattern: "xor ecx, edx" / "rol ecx, 5" / "not ecx" / "bswap ecx"
_TRANSFORM_RE = re.compile(
    r"(xor|add|sub|not|neg|rol|ror|bswap|mul|inc|dec)\s+(\w+)(?:\s*,\s*(.+))?",
    re.IGNORECASE,
)


def parse_decode_transforms(
    raw_transforms: Sequence[str],
    *,
    fetch_register: str = "",
    key_register: str = "",
) -> List[KeyTransform]:
    """Parse string transform descriptors into :class:`KeyTransform` objects.

    Parameters
    ----------
    raw_transforms
        List of assembly-like strings from
        ``VMProtectDispatcherMatch.decode_transforms``.
    fetch_register
        The register holding the fetched opcode (e.g. ``"ecx"``).
    key_register
        A known key register (if identified), else inferred from transforms.

    Returns
    -------
    list[KeyTransform]
        Ordered transform sequence.  Returns an empty list when no
        transforms are detected (implying no key encryption).
    """
    results: List[KeyTransform] = []

    for raw in raw_transforms:
        m = _TRANSFORM_RE.search(raw.strip())
        if not m:
            logger.debug("Could not parse transform: %r", raw)
            continue

        op_str = m.group(1).lower()
        dst_reg = m.group(2).lower()
        src_raw = (m.group(3) or "").strip().lower()

        try:
            op = TransformOp(op_str)
        except ValueError:
            logger.debug("Unknown transform op %r in %r", op_str, raw)
            continue

        # Determine operand source
        if op in (TransformOp.NOT, TransformOp.NEG,
                  TransformOp.BSWAP, TransformOp.INC, TransformOp.DEC):
            operand_source = ""
        elif not src_raw:
            operand_source = ""
        elif _is_register(src_raw):
            # If the source reg is the fetch register → "opcode"
            # If it's the same as dst → "key" (self-transform)
            # Otherwise, heuristically treat as opcode
            norm_src = _normalize_alias(src_raw)
            norm_fetch = _normalize_alias(fetch_register)
            norm_key = _normalize_alias(key_register)
            if norm_src == norm_fetch:
                operand_source = "opcode"
            elif norm_src == _normalize_alias(dst_reg):
                operand_source = "key"
            elif norm_key and norm_src == norm_key:
                operand_source = "key"
            else:
                # Could be an operand register aliased from the fetch
                operand_source = "opcode"
        else:
            # Immediate value
            imm = _parse_immediate(src_raw)
            if imm is not None:
                operand_source = f"imm:{imm}"
            else:
                operand_source = "opcode"

        results.append(KeyTransform(op=op, operand_source=operand_source))

    return results


# ---------------------------------------------------------------------------
# BytecodeDecryptor
# ---------------------------------------------------------------------------

_WIDTH_MASK = {8: 0xFF, 16: 0xFFFF, 32: 0xFFFFFFFF, 64: 0xFFFFFFFFFFFFFFFF}


@dataclass
class BytecodeDecryptor:
    """Applies VMProtect rolling-key decryption to a bytecode stream.

    Parameters
    ----------
    transforms : list[KeyTransform]
        Ordered transform sequence (from :func:`parse_decode_transforms`).
    initial_key : int
        Starting key value (from first dispatcher trace snapshot or brute-force).
    key_width : int
        Key register width in bits (32 or 64).
    opcode_width : int
        How many bytes each raw opcode occupies (1 or 2).
    """

    transforms: List[KeyTransform] = field(default_factory=list)
    initial_key: int = 0
    key_width: int = 32
    opcode_width: int = 1
    cipher_chain: List[CipherStep] = field(default_factory=list)  # B81: multi-round

    def __post_init__(self) -> None:
        self._mask = _WIDTH_MASK.get(self.key_width, 0xFFFFFFFF)

    # -- Core decryption ---------------------------------------------------

    def decrypt(
        self,
        encrypted: bytes,
        *,
        start_offset: int = 0,
        max_opcodes: int = 50000,
    ) -> Tuple[bytes, List[int]]:
        """Decrypt the bytecode stream, returning plaintext bytes and per-opcode keys.

        Returns
        -------
        (plaintext, keys)
            *plaintext* has the same length as *encrypted*.
            *keys* contains the rolling key value BEFORE each opcode decode.
        """
        if not self.transforms:
            # No encryption — return as-is.
            return bytes(encrypted), []

        key = self.initial_key & self._mask
        out = bytearray(len(encrypted))
        keys: List[int] = []
        offset = start_offset
        ow = self.opcode_width
        opcode_count = 0

        while offset + ow <= len(encrypted) and opcode_count < max_opcodes:
            keys.append(key)

            # Read encrypted opcode
            if ow == 1:
                enc_opcode = encrypted[offset]
            else:
                enc_opcode = int.from_bytes(
                    encrypted[offset:offset + ow], "little",
                )

            # Decrypt: plain = enc XOR key (truncated to opcode width)
            opcode_mask = (1 << (ow * 8)) - 1
            plain_opcode = (enc_opcode ^ key) & opcode_mask

            # Write plaintext opcode
            if ow == 1:
                out[offset] = plain_opcode & 0xFF
            else:
                out[offset:offset + ow] = plain_opcode.to_bytes(ow, "little")

            # Apply transform sequence to update the key
            key = self._apply_transforms(key, plain_opcode)

            offset += ow  # Advance past the opcode byte(s)
            opcode_count += 1

            # NOTE: Operand bytes after the opcode are NOT encrypted in
            # standard VMProtect — they are copied verbatim.  The caller
            # (walk_static_bytecode_decrypted) must skip operand bytes
            # using the opcode table's vip_delta.

        # Copy any remaining bytes (operand / padding) as-is
        for i in range(len(encrypted)):
            if out[i] == 0 and i >= start_offset:
                # Only overwrite if we didn't touch it above
                pass
            elif i < start_offset:
                out[i] = encrypted[i]

        return bytes(out), keys

    def decrypt_single(self, encrypted_opcode: int, current_key: int) -> Tuple[int, int]:
        """Decrypt one opcode and return (plaintext_opcode, next_key).

        Useful for trace-synchronized decryption where we advance
        step-by-step with the trace.
        """
        opcode_mask = (1 << (self.opcode_width * 8)) - 1
        plain = (encrypted_opcode ^ current_key) & opcode_mask
        next_key = self._apply_transforms(current_key, plain)
        return plain, next_key

    def decrypt_chained(
        self,
        encrypted: bytes,
        *,
        start_offset: int = 0,
        max_opcodes: int = 50000,
    ) -> Tuple[bytes, List[int]]:
        """Decrypt using a multi-round cipher chain.

        Like :meth:`decrypt`, but applies each :class:`CipherStep` in
        ``self.cipher_chain`` sequentially instead of a single XOR.
        Falls back to standard single-XOR if no cipher chain is set.

        Returns
        -------
        (plaintext, keys)
        """
        chain = self.cipher_chain
        if not chain:
            return self.decrypt(encrypted, start_offset=start_offset, max_opcodes=max_opcodes)

        key = self.initial_key & self._mask
        ow = self.opcode_width
        opcode_mask = (1 << (ow * 8)) - 1
        out = bytearray(len(encrypted))
        keys: List[int] = []
        offset = start_offset
        opcode_count = 0

        while offset + ow <= len(encrypted) and opcode_count < max_opcodes:
            keys.append(key)

            if ow == 1:
                enc_val = encrypted[offset]
            else:
                enc_val = int.from_bytes(encrypted[offset:offset + ow], "little")

            # Multi-round decrypt: apply cipher chain sequentially
            value = enc_val
            for step in chain:
                value = _apply_cipher_step(value, step, key, ow * 8)
            plain_opcode = value & opcode_mask

            if ow == 1:
                out[offset] = plain_opcode & 0xFF
            else:
                out[offset:offset + ow] = plain_opcode.to_bytes(ow, "little")

            key = self._apply_transforms(key, plain_opcode)
            offset += ow
            opcode_count += 1

        for i in range(start_offset):
            out[i] = encrypted[i]

        return bytes(out), keys

    def _apply_transforms(self, key: int, opcode: int) -> int:
        """Apply the transform sequence to the key register."""
        mask = self._mask

        for t in self.transforms:
            operand = self._resolve_operand(t, key, opcode)

            if t.op == TransformOp.XOR:
                key = (key ^ operand) & mask
            elif t.op == TransformOp.ADD:
                key = (key + operand) & mask
            elif t.op == TransformOp.SUB:
                key = (key - operand) & mask
            elif t.op == TransformOp.NOT:
                key = (~key) & mask
            elif t.op == TransformOp.NEG:
                key = (-key) & mask
            elif t.op == TransformOp.ROL:
                shift = operand % self.key_width
                key = ((key << shift) | (key >> (self.key_width - shift))) & mask
            elif t.op == TransformOp.ROR:
                shift = operand % self.key_width
                key = ((key >> shift) | (key << (self.key_width - shift))) & mask
            elif t.op == TransformOp.BSWAP:
                if self.key_width == 32:
                    key = struct.unpack(">I", struct.pack("<I", key & 0xFFFFFFFF))[0]
                elif self.key_width == 64:
                    key = struct.unpack(">Q", struct.pack("<Q", key & 0xFFFFFFFFFFFFFFFF))[0]
            elif t.op == TransformOp.MUL:
                key = (key * operand) & mask
            elif t.op == TransformOp.INC:
                key = (key + 1) & mask
            elif t.op == TransformOp.DEC:
                key = (key - 1) & mask

        return key

    @staticmethod
    def _resolve_operand(t: KeyTransform, key: int, opcode: int) -> int:
        """Resolve the transform's operand to a concrete integer."""
        src = t.operand_source
        if not src:
            return 0
        if src == "opcode":
            return opcode
        if src == "key":
            return key
        if src.startswith("imm:"):
            try:
                return int(src[4:])
            except ValueError:
                return 0
        return 0


# ---------------------------------------------------------------------------
# Initial key detection from trace
# ---------------------------------------------------------------------------


def detect_initial_key(
    trace_records: Sequence[Any],
    dispatcher_match: Any,
    *,
    key_register: str = "",
) -> Optional[int]:
    """Extract the initial rolling-key value from the first dispatcher visit.

    Parameters
    ----------
    trace_records
        Execution trace (list of dicts with ``"address"`` and ``"registers"``).
    dispatcher_match
        A ``VMProtectDispatcherMatch`` (or dict with ``entry_address``,
        ``decode_transforms``, ``context_registers``).
    key_register
        Explicit key register name.  If empty, inferred from the
        dispatcher match's context_registers or decode_transforms.

    Returns
    -------
    int | None
        Key value at the first opcode fetch, or ``None`` if not found.
    """
    if not trace_records:
        return None

    # Determine key register
    if not key_register:
        key_register = _infer_key_register(dispatcher_match)
    if not key_register:
        return None

    # Find the entry address
    entry_addr = _get_attr_or_key(dispatcher_match, "entry_address", 0)
    if not entry_addr:
        entry_addr = _get_attr_or_key(dispatcher_match, "indirect_jump_address", 0)

    if not entry_addr:
        return None

    # Search for the first trace record at the dispatcher entry
    for rec in trace_records:
        addr = rec.get("address", 0) if isinstance(rec, dict) else getattr(rec, "address", 0)
        if addr == entry_addr:
            regs = rec.get("registers", {}) if isinstance(rec, dict) else getattr(rec, "registers", {})
            if not isinstance(regs, dict):
                continue
            # Try various register name formats
            for name in _register_aliases(key_register):
                if name in regs:
                    val = regs[name]
                    if isinstance(val, int):
                        return val
            break  # Only check first visit

    return None


def _infer_key_register(dispatcher_match: Any) -> str:
    """Infer which register holds the rolling key."""
    # Check context_registers for a "vKey" role
    ctx = _get_attr_or_key(dispatcher_match, "context_registers", {})
    if isinstance(ctx, dict):
        for reg, role in ctx.items():
            if isinstance(role, str) and "key" in role.lower():
                return reg

    # Parse decode_transforms to find which register is XORed
    transforms = _get_attr_or_key(dispatcher_match, "decode_transforms", [])
    if transforms:
        for t_str in transforms:
            m = _TRANSFORM_RE.search(str(t_str))
            if m:
                return m.group(2).lower()

    return ""


# ---------------------------------------------------------------------------
# Handler table decryption
# ---------------------------------------------------------------------------


@dataclass
class HandlerTableEntry:
    """One entry in a decrypted handler dispatch table."""

    index: int
    raw_value: int
    decrypted_address: int
    encoding: str = "plain"  # plain, rva_relative, xor_encrypted, add_encrypted


@dataclass
class DecryptedHandlerTable:
    """Complete decrypted handler dispatch table."""

    entries: List[HandlerTableEntry] = field(default_factory=list)
    encoding_detected: str = "plain"
    table_base: int = 0
    key_used: int = 0

    @property
    def count(self) -> int:
        return len(self.entries)

    @property
    def addresses(self) -> List[int]:
        return [e.decrypted_address for e in self.entries]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "count": self.count,
            "encoding": self.encoding_detected,
            "table_base": hex(self.table_base),
            "entries": [
                {
                    "index": e.index,
                    "raw": hex(e.raw_value),
                    "address": hex(e.decrypted_address),
                    "encoding": e.encoding,
                }
                for e in self.entries
            ],
        }


def decrypt_handler_table(
    binary_data: bytes,
    table_base: int,
    base_address: int,
    *,
    bit_width: int = 64,
    entry_scale: int = 0,
    max_entries: int = 256,
    image_base: int = 0,
    table_key: int = 0,
    known_handler_addresses: Optional[List[int]] = None,
) -> DecryptedHandlerTable:
    """Decrypt VMProtect's encrypted handler dispatch table.

    VMProtect uses several table encoding schemes:

    1. **Plain pointers** — raw absolute addresses (rare in v3.x).
    2. **RVA-relative** — ``table[i] + image_base`` or ``table[i] + table_base``.
    3. **XOR-encrypted** — ``table[i] ^ table_key``.
    4. **ADD-encrypted** — ``(table[i] + table_key) & mask``.

    The function tries each scheme and picks the one that produces the
    most valid addresses (within the binary's address range).

    Parameters
    ----------
    binary_data : bytes
        Raw PE/ELF binary.
    table_base : int
        Virtual address of the handler table start.
    base_address : int
        Virtual address of ``binary_data[0]``.
    bit_width : int
        32 or 64.
    entry_scale : int
        Size of each table entry in bytes.  0 = auto-detect from bit_width.
    max_entries : int
        Maximum table entries to read.
    image_base : int
        PE image base (for RVA-relative decoding).
    table_key : int
        XOR / ADD key if known.
    known_handler_addresses : list[int] | None
        Handler addresses from trace (for validation of decoded entries).
    """
    if entry_scale <= 0:
        entry_scale = 8 if bit_width == 64 else 4

    entry_fmt = "<Q" if entry_scale == 8 else "<I"
    entry_mask = 0xFFFFFFFFFFFFFFFF if entry_scale == 8 else 0xFFFFFFFF

    # Read raw table entries
    offset = table_base - base_address
    if offset < 0 or offset >= len(binary_data):
        return DecryptedHandlerTable(table_base=table_base)

    raw_entries: List[int] = []
    consecutive_zeros = 0
    for i in range(max_entries):
        pos = offset + i * entry_scale
        if pos + entry_scale > len(binary_data):
            break
        val = struct.unpack(entry_fmt, binary_data[pos:pos + entry_scale])[0]
        if val == 0:
            consecutive_zeros += 1
            if consecutive_zeros >= 2:
                # Stop after 2 consecutive zeros (end of table)
                break
        else:
            consecutive_zeros = 0
        raw_entries.append(val)

    if not raw_entries:
        return DecryptedHandlerTable(table_base=table_base)

    binary_end = base_address + len(binary_data)
    known_set = set(known_handler_addresses or [])

    # Try each decoding scheme and pick the best
    candidates: List[Tuple[str, List[int], int]] = []

    # Scheme 1: Plain absolute pointers
    plain = raw_entries[:]
    plain_valid = sum(1 for a in plain if base_address <= a < binary_end)
    if known_set:
        plain_match = sum(1 for a in plain if a in known_set)
        # Extra bonus: plain entries that exactly match known addresses
        # are very strong evidence for the plain encoding scheme.
        plain_valid += plain_match * 5  # Strong bonus for exact matches
    candidates.append(("plain", plain, plain_valid))

    # Scheme 2: RVA-relative to table_base
    rva_tb = [(v + table_base) & entry_mask for v in raw_entries]
    rva_tb_valid = sum(1 for a in rva_tb if base_address <= a < binary_end)
    if known_set:
        rva_tb_valid += sum(1 for a in rva_tb if a in known_set) * 3
    candidates.append(("rva_relative_table", rva_tb, rva_tb_valid))

    # Scheme 3: RVA-relative to image_base
    if image_base > 0:
        rva_ib = [(v + image_base) & entry_mask for v in raw_entries]
        rva_ib_valid = sum(1 for a in rva_ib if base_address <= a < binary_end)
        if known_set:
            rva_ib_valid += sum(1 for a in rva_ib if a in known_set) * 3
        candidates.append(("rva_relative_image", rva_ib, rva_ib_valid))

    # Scheme 4: Signed RVA-relative to table_base
    signed_rva: List[int] = []
    for v in raw_entries:
        if entry_scale == 4:
            sv = struct.unpack("<i", struct.pack("<I", v & 0xFFFFFFFF))[0]
        else:
            sv = struct.unpack("<q", struct.pack("<Q", v & 0xFFFFFFFFFFFFFFFF))[0]
        signed_rva.append((table_base + sv) & entry_mask)
    signed_valid = sum(1 for a in signed_rva if base_address <= a < binary_end)
    if known_set:
        signed_valid += sum(1 for a in signed_rva if a in known_set) * 3
    candidates.append(("signed_rva_relative", signed_rva, signed_valid))

    # Scheme 5: XOR with known key
    if table_key:
        xor_dec = [(v ^ table_key) & entry_mask for v in raw_entries]
        xor_valid = sum(1 for a in xor_dec if base_address <= a < binary_end)
        if known_set:
            xor_valid += sum(1 for a in xor_dec if a in known_set) * 3
        candidates.append(("xor_encrypted", xor_dec, xor_valid))

        # ADD decryption
        add_dec = [(v + table_key) & entry_mask for v in raw_entries]
        add_valid = sum(1 for a in add_dec if base_address <= a < binary_end)
        if known_set:
            add_valid += sum(1 for a in add_dec if a in known_set) * 3
        candidates.append(("add_encrypted", add_dec, add_valid))

    # Scheme 6: Auto-detect XOR key from known addresses
    if known_set and not table_key and len(raw_entries) >= 2:
        detected_key = _detect_table_xor_key(
            raw_entries, known_set, entry_mask, base_address, binary_end,
        )
        if detected_key is not None:
            auto_xor = [(v ^ detected_key) & entry_mask for v in raw_entries]
            auto_valid = sum(1 for a in auto_xor if base_address <= a < binary_end)
            auto_valid += sum(1 for a in auto_xor if a in known_set) * 3
            candidates.append(("xor_encrypted", auto_xor, auto_valid))
            if auto_valid > 0:
                table_key = detected_key

    # Pick best scheme
    best_name, best_decoded, best_score = max(
        candidates, key=lambda c: c[2],
    )

    # Filter to valid entries (stop at first invalid gap)
    result_entries: List[HandlerTableEntry] = []
    for i, (raw, dec) in enumerate(zip(raw_entries, best_decoded)):
        if dec == 0:
            break
        if not (base_address <= dec < binary_end) and not (dec in known_set):
            # Allow a few invalid entries (VMProtect sometimes has gaps)
            if len(result_entries) > 3:
                break
            continue
        result_entries.append(HandlerTableEntry(
            index=i,
            raw_value=raw,
            decrypted_address=dec,
            encoding=best_name,
        ))

    return DecryptedHandlerTable(
        entries=result_entries,
        encoding_detected=best_name,
        table_base=table_base,
        key_used=table_key,
    )


def _detect_table_xor_key(
    raw_entries: List[int],
    known_addresses: set,
    mask: int,
    base_address: int = 0,
    binary_end: int = 0,
) -> Optional[int]:
    """Try to detect the XOR key by matching raw entries against known addresses.

    If ``raw[i] ^ key == known_addr``, then ``key = raw[i] ^ known_addr``.
    We try all combinations and pick the key that produces the most
    *positional* matches (raw[i] ^ key must equal SOME known addr, but
    we also require the result to be within the binary range).
    """
    key_votes: Dict[int, int] = {}
    for raw in raw_entries:
        for known in known_addresses:
            candidate_key = (raw ^ known) & mask
            if candidate_key == 0:
                continue
            key_votes[candidate_key] = key_votes.get(candidate_key, 0) + 1

    if not key_votes:
        return None

    best_key, best_count = max(key_votes.items(), key=lambda kv: kv[1])

    # Validate: at least 2 positional matches AND all decoded results
    # should be within binary bounds (or match known).
    if best_count >= 2:
        # Verify the decoded addresses are reasonable
        decoded = [(v ^ best_key) & mask for v in raw_entries]
        valid = sum(
            1 for a in decoded
            if a in known_addresses or (base_address <= a < binary_end)
        )
        # If the key produces fewer valid addresses than just using plain,
        # it's a false positive.
        plain_valid = sum(
            1 for a in raw_entries
            if a in known_addresses or (base_address <= a < binary_end)
        )
        if valid > plain_valid:
            return best_key

    return None


# ---------------------------------------------------------------------------
# Convenience: decrypt bytecode with dispatcher match
# ---------------------------------------------------------------------------


def make_decryptor_from_dispatcher(
    dispatcher_match: Any,
    trace_records: Optional[Sequence[Any]] = None,
    *,
    key_width: int = 0,
    opcode_width: int = 0,
) -> Optional[BytecodeDecryptor]:
    """Create a :class:`BytecodeDecryptor` from a dispatcher match.

    This is the primary integration point:

    1. Parses ``decode_transforms`` from the dispatcher match.
    2. Detects the initial key from the trace.
    3. Returns a ready-to-use decryptor, or ``None`` if no encryption.

    Parameters
    ----------
    dispatcher_match
        ``VMProtectDispatcherMatch`` object or dict.
    trace_records
        Execution trace for key detection.
    key_width
        Key register bit-width (0 = auto from bit_width).
    opcode_width
        Opcode byte width (0 = auto from fetch_width).
    """
    transforms_raw = _get_attr_or_key(dispatcher_match, "decode_transforms", [])
    if not transforms_raw:
        return None

    fetch_reg = _get_attr_or_key(dispatcher_match, "fetch_register", "")
    key_reg = _infer_key_register(dispatcher_match)

    transforms = parse_decode_transforms(
        transforms_raw,
        fetch_register=fetch_reg,
        key_register=key_reg,
    )
    if not transforms:
        return None

    # Determine widths
    if opcode_width <= 0:
        opcode_width = _get_attr_or_key(dispatcher_match, "fetch_width", 1)
    if key_width <= 0:
        # Infer from architecture (64-bit VM typically uses 32-bit keys
        # for opcode XOR, but 64-bit for full key register)
        key_width = 32  # Default for VMProtect opcode key

    # Detect initial key from trace
    initial_key = 0
    if trace_records:
        detected = detect_initial_key(trace_records, dispatcher_match, key_register=key_reg)
        if detected is not None:
            initial_key = detected

    # Fallback: symbolic key recovery from VM entry stub
    if initial_key == 0:
        try:
            from dragonslayer.analysis.key_recovery import recover_key_from_entry
            entry_insns = _get_attr_or_key(dispatcher_match, "entry_instructions", [])
            if entry_insns:
                recovered = recover_key_from_entry(
                    entry_insns, dispatcher_match, bit_width=key_width,
                )
                if recovered is not None:
                    initial_key = recovered.key_value
                    logger.info(
                        "Recovered initial key 0x%x from entry stub (%s)",
                        initial_key, recovered.source,
                    )
        except (ValueError, TypeError, KeyError, RuntimeError, AttributeError) as exc:
            logger.debug("Symbolic key recovery fallback failed: %s", exc)

    return BytecodeDecryptor(
        transforms=transforms,
        initial_key=initial_key,
        key_width=key_width,
        opcode_width=opcode_width,
    )


def make_generic_decryptor(
    dispatcher_match: Any,
    trace_records: Optional[Sequence[Any]] = None,
    *,
    max_key_bytes: int = 4,
) -> Optional[BytecodeDecryptor]:
    """Create a decryptor for non-VMProtect protectors via XOR key search.

    Performs frequency analysis on the bytecode region referenced by
    *dispatcher_match* to brute-force 1–*max_key_bytes* byte XOR keys.
    Falls back to single-byte XOR with the most-common byte value
    (assumed to be encrypted NOP / 0x00).

    Parameters
    ----------
    dispatcher_match
        Generic dispatcher match (dict or dataclass).
    trace_records
        Execution trace (used for entropy analysis, optional).
    max_key_bytes
        Maximum key length to brute-force (default 4).

    Returns
    -------
    BytecodeDecryptor or None
        Ready-to-use decryptor, or ``None`` if no encryption detected.
    """
    # Try to get decode_transforms first — some protectors have them.
    transforms_raw = _get_attr_or_key(dispatcher_match, "decode_transforms", [])
    if transforms_raw:
        return make_decryptor_from_dispatcher(dispatcher_match, trace_records)

    # Otherwise, attempt generic XOR key search.
    handler_addrs: list = _get_attr_or_key(
        dispatcher_match, "handler_addresses", [],
    )
    if not handler_addrs:
        return None

    # Collect bytecode bytes from trace around handler regions.
    handler_set = set(handler_addrs)
    raw_bytes: list[int] = []
    if trace_records:
        for rec in trace_records:
            addr = getattr(rec, "address", None) or (
                rec.get("address") if isinstance(rec, dict) else None
            )
            if addr in handler_set:
                opcode = getattr(rec, "raw_bytes", None) or (
                    rec.get("raw_bytes") if isinstance(rec, dict) else None
                )
                if isinstance(opcode, (bytes, bytearray)):
                    raw_bytes.extend(opcode)
                elif isinstance(opcode, int):
                    raw_bytes.append(opcode & 0xFF)

    if len(raw_bytes) < 16:
        return None

    # Frequency analysis: most common byte is likely encrypted 0x00 or NOP.
    from collections import Counter

    freq = Counter(raw_bytes)
    most_common_byte, _count = freq.most_common(1)[0]

    # Calculate entropy to decide if decryption is needed.
    total = len(raw_bytes)
    entropy = 0.0
    for cnt in freq.values():
        p = cnt / total
        if p > 0:
            import math
            entropy -= p * math.log2(p)

    if entropy < 3.0:
        # Low entropy — likely not encrypted.
        return None

    # Build single-byte XOR transform.
    xor_key = most_common_byte  # XOR with most-common → 0x00
    transforms = [
        KeyTransform(
            op=TransformOp.XOR,
            operand_source=f"imm:{xor_key}",
        ),
    ]

    return BytecodeDecryptor(
        transforms=transforms,
        initial_key=xor_key,
        key_width=8,
        opcode_width=1,
    )


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


_REG_NAMES = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
}

_REG_CANONICAL = {
    "al": "rax", "ah": "rax", "ax": "rax", "eax": "rax", "rax": "rax",
    "bl": "rbx", "bh": "rbx", "bx": "rbx", "ebx": "rbx", "rbx": "rbx",
    "cl": "rcx", "ch": "rcx", "cx": "rcx", "ecx": "rcx", "rcx": "rcx",
    "dl": "rdx", "dh": "rdx", "dx": "rdx", "edx": "rdx", "rdx": "rdx",
    "sil": "rsi", "si": "rsi", "esi": "rsi", "rsi": "rsi",
    "dil": "rdi", "di": "rdi", "edi": "rdi", "rdi": "rdi",
    "bpl": "rbp", "bp": "rbp", "ebp": "rbp", "rbp": "rbp",
    "spl": "rsp", "sp": "rsp", "esp": "rsp", "rsp": "rsp",
    "r8b": "r8", "r8w": "r8", "r8d": "r8", "r8": "r8",
    "r9b": "r9", "r9w": "r9", "r9d": "r9", "r9": "r9",
    "r10b": "r10", "r10w": "r10", "r10d": "r10", "r10": "r10",
    "r11b": "r11", "r11w": "r11", "r11d": "r11", "r11": "r11",
    "r12b": "r12", "r12w": "r12", "r12d": "r12", "r12": "r12",
    "r13b": "r13", "r13w": "r13", "r13d": "r13", "r13": "r13",
    "r14b": "r14", "r14w": "r14", "r14d": "r14", "r14": "r14",
    "r15b": "r15", "r15w": "r15", "r15d": "r15", "r15": "r15",
}


def _is_register(s: str) -> bool:
    return s.lower().strip() in _REG_NAMES


def _normalize_alias(reg: str) -> str:
    """Normalize register name to canonical 64-bit form."""
    return _REG_CANONICAL.get(reg.lower().strip(), reg.lower().strip())


def _register_aliases(reg: str) -> List[str]:
    """Return all width-aliases of a register for dict lookup."""
    canon = _normalize_alias(reg)
    aliases = [reg.lower()]
    for k, v in _REG_CANONICAL.items():
        if v == canon and k != reg.lower():
            aliases.append(k)
    return aliases


def _parse_immediate(s: str) -> Optional[int]:
    """Parse an immediate value from a string."""
    s = s.strip().rstrip("h")
    try:
        if s.startswith("0x") or s.startswith("-0x"):
            return int(s, 16)
        return int(s)
    except ValueError:
        return None


def _get_attr_or_key(obj: Any, name: str, default: Any = None) -> Any:
    """Get attribute or dict key from an object."""
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)
