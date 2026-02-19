"""
VM Discovery — Dispatcher Identification & Handler Table Reconstruction
========================================================================

Identifies the VM dispatcher (central fetch-decode-execute loop) and
reconstructs the handler dispatch table by correlating:

* Raw byte-level dispatcher patterns from :mod:`detector`.
* Control-flow information from lifted instructions.
* Symbolic execution handler classifications from :mod:`symbolic_execution`.
* Signature database matches from :mod:`database`.

Usage::

    from dragonslayer.analysis.vm_discovery.dispatcher import DispatcherAnalyzer

    analyzer = DispatcherAnalyzer()
    result = analyzer.analyze(binary_data, shared_data=ctx.shared_data)
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class DispatcherInfo:
    """Information about a detected VM dispatcher."""
    address: int
    pattern: str          # e.g. "jmp eax", "jmp [ecx*4+disp32]"
    dispatch_type: str    # "register", "table", "computed"
    handler_count: int = 0
    loop_detected: bool = False
    confidence: float = 0.0
    table_entries: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "pattern": self.pattern,
            "dispatch_type": self.dispatch_type,
            "handler_count": self.handler_count,
            "loop_detected": self.loop_detected,
            "confidence": round(self.confidence, 4),
            "table_entries_count": len(self.table_entries),
        }


@dataclass
class HandlerEntry:
    """Entry in the reconstructed handler dispatch table."""
    opcode: int                      # VM opcode / index
    handler_address: int             # Address of the handler code
    category: str = "unknown"        # Handler semantic category
    size: int = 0                    # Approximate handler size in bytes
    returns_to_dispatcher: bool = False
    reads: List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "opcode": self.opcode,
            "handler_address": self.handler_address,
            "category": self.category,
            "size": self.size,
            "returns_to_dispatcher": self.returns_to_dispatcher,
            "reads": self.reads,
            "writes": self.writes,
        }


@dataclass
class DispatchTableResult:
    """Complete dispatcher analysis result."""
    success: bool
    dispatchers: List[DispatcherInfo] = field(default_factory=list)
    handler_table: List[HandlerEntry] = field(default_factory=list)
    total_handlers: int = 0
    opcode_range: Optional[tuple] = None
    protector: str = "unknown"
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "dispatchers": [d.to_dict() for d in self.dispatchers],
            "handler_table": [h.to_dict() for h in self.handler_table],
            "total_handlers": self.total_handlers,
            "opcode_range": list(self.opcode_range) if self.opcode_range else None,
            "protector": self.protector,
            "error": self.error,
        }


class DispatcherAnalyzer:
    """
    Identifies VM dispatchers and reconstructs handler dispatch tables.

    Combines structural analysis (byte patterns) with semantic analysis
    (from symbolic execution) to build a mapping of VM opcodes → handlers.
    """

    # Common VMProtect dispatch patterns
    VMPROTECT_DISPATCH_SIGS = [
        # push addr; ret  (VMProtect 3.x entry)
        (b"\x68", 5, "push_ret_entry"),
        # jmp [reg*4+table]  (dispatch via jump table)
        (b"\xff\x24\x85", 7, "jmp_table_eax"),
        (b"\xff\x24\x8d", 7, "jmp_table_ecx"),
        (b"\xff\x24\x95", 7, "jmp_table_edx"),
        (b"\xff\x24\x9d", 7, "jmp_table_ebx"),
    ]

    def analyze(
        self,
        binary_data: bytes,
        *,
        shared_data: Optional[Dict[str, Any]] = None,
    ) -> DispatchTableResult:
        """
        Analyse binary data with cross-stage context to identify
        dispatchers and reconstruct the handler table.

        Parameters
        ----------
        binary_data : bytes
            Raw binary data.
        shared_data : dict | None
            Pipeline shared data (vm_discovery, symbolic_execution, etc.).
        """
        shared = shared_data or {}

        try:
            # 1. Collect dispatcher candidates from VM discovery
            vm_info = shared.get("vm_discovery", {})
            raw_dispatchers = vm_info.get("dispatchers", [])
            protector = vm_info.get("protector", "unknown")

            dispatcher_infos: List[DispatcherInfo] = []
            for d in raw_dispatchers:
                if isinstance(d, dict):
                    dispatcher_infos.append(DispatcherInfo(
                        address=d.get("offset", 0),
                        pattern=d.get("mnemonic", "unknown"),
                        dispatch_type=self._classify_dispatch_type(d.get("mnemonic", "")),
                        confidence=0.5,
                    ))

            # 2. Scan for jump-table dispatchers (indirect jump with table)
            table_dispatchers = self._find_jump_tables(binary_data)
            for td in table_dispatchers:
                # Check for duplicates
                existing = any(
                    abs(d.address - td.address) < 16 for d in dispatcher_infos
                )
                if not existing:
                    dispatcher_infos.append(td)

            # 2b. Scan for push imm32; ret sequences (obfuscated jumps)
            push_ret_entries = self._find_push_ret_sequences(
                binary_data,
                image_base=vm_info.get("image_base", 0),
            )

            # 3. Merge with symbolic execution handler data
            sym_info = shared.get("symbolic_execution", {})
            sym_handlers = sym_info.get("handlers", [])
            sym_handler_table = sym_info.get("handler_table", {})

            # 4. Build handler table
            handler_table: List[HandlerEntry] = []
            seen_addrs: Set[int] = set()

            # From symbolic execution classified handlers
            for i, h in enumerate(sym_handlers):
                addr = h.get("address", 0) if isinstance(h, dict) else getattr(h, "address", 0)
                if addr in seen_addrs:
                    continue
                seen_addrs.add(addr)

                cat = h.get("category", "unknown") if isinstance(h, dict) else getattr(h, "category", "unknown")
                handler_table.append(HandlerEntry(
                    opcode=i,
                    handler_address=addr,
                    category=cat,
                    size=h.get("instruction_count", 0) if isinstance(h, dict) else 0,
                    reads=h.get("reads", []) if isinstance(h, dict) else [],
                    writes=h.get("writes", []) if isinstance(h, dict) else [],
                ))

            # From jump table extraction
            for td in table_dispatchers:
                for entry in td.table_entries:
                    if entry not in seen_addrs:
                        seen_addrs.add(entry)
                        handler_table.append(HandlerEntry(
                            opcode=len(handler_table),
                            handler_address=entry,
                            category="table_entry",
                        ))

            # From push/ret sequences — add targets as handler entry points
            for pr_addr, pr_target in push_ret_entries:
                if pr_target not in seen_addrs:
                    seen_addrs.add(pr_target)
                    handler_table.append(HandlerEntry(
                        opcode=len(handler_table),
                        handler_address=pr_target,
                        category="push_ret_target",
                    ))
                # Register the push/ret site as a dispatcher if enough
                # targets converge in a small region
            if push_ret_entries:
                pr_dispatcher = DispatcherInfo(
                    address=push_ret_entries[0][0],
                    pattern="push_ret",
                    dispatch_type="push_ret",
                    handler_count=len(push_ret_entries),
                    confidence=min(1.0, 0.4 + len(push_ret_entries) * 0.1),
                    table_entries=[t for _, t in push_ret_entries],
                )
                dispatcher_infos.append(pr_dispatcher)

            # 5. Detect dispatcher loops
            for di in dispatcher_infos:
                # push_ret dispatchers already have accurate counts
                if di.dispatch_type == "push_ret":
                    if di.handler_count > 3:
                        di.loop_detected = True
                    continue

                di.handler_count = len([
                    h for h in handler_table
                    if abs(h.handler_address - di.address) < 0x10000
                ])
                if di.handler_count > 3:
                    di.loop_detected = True
                    di.confidence = min(1.0, di.confidence + 0.3)

            # 6. Compute opcode range
            opcodes = [h.opcode for h in handler_table]
            opcode_range = (min(opcodes), max(opcodes)) if opcodes else None

            return DispatchTableResult(
                success=True,
                dispatchers=dispatcher_infos,
                handler_table=handler_table,
                total_handlers=len(handler_table),
                opcode_range=opcode_range,
                protector=protector,
            )

        except Exception as exc:
            logger.exception("Dispatcher analysis failed")
            return DispatchTableResult(success=False, error=str(exc))

    @staticmethod
    def _classify_dispatch_type(mnemonic: str) -> str:
        """Classify dispatch type from mnemonic pattern."""
        mn = mnemonic.lower()
        if "table" in mn or "*4" in mn or "*8" in mn:
            return "table"
        if "jmp" in mn and any(r in mn for r in ("eax", "ecx", "edx", "ebx", "rax", "rcx")):
            return "register"
        return "computed"

    def _find_jump_tables(self, data: bytes) -> List[DispatcherInfo]:
        """
        Scan for indirect jump instructions followed by potential jump tables.

        A jump table is typically: jmp [reg*4+base], where base points to
        an array of code addresses.
        """
        results: List[DispatcherInfo] = []

        for pattern, length, name in self.VMPROTECT_DISPATCH_SIGS:
            start = 0
            while True:
                idx = data.find(pattern, start)
                if idx == -1 or idx + length > len(data):
                    break
                start = idx + 1

                # For jmp [reg*4+disp32] patterns, extract table base
                if len(pattern) == 3 and idx + 7 <= len(data):
                    try:
                        disp = struct.unpack_from("<I", data, idx + 3)[0]
                        # Validate: table entries should be plausible addresses
                        table_entries = self._extract_table_entries(data, disp, max_entries=256)
                        if len(table_entries) >= 2:
                            di = DispatcherInfo(
                                address=idx,
                                pattern=name,
                                dispatch_type="table",
                                handler_count=len(table_entries),
                                confidence=min(1.0, 0.3 + len(table_entries) * 0.05),
                                table_entries=table_entries,
                            )
                            results.append(di)
                    except (struct.error, IndexError):
                        pass

                if len(results) >= 20:
                    break

        return results

    # ------------------------------------------------------------------
    # push imm32 ; ret  detection
    # ------------------------------------------------------------------

    @staticmethod
    def _find_push_ret_sequences(
        data: bytes,
        *,
        image_base: int = 0,
        max_sequences: int = 512,
    ) -> List[tuple]:
        """Scan for ``push imm32; ret`` (``\\x68 <4B> \\xC3``) obfuscated jumps.

        VMProtect (and similar protectors) replace direct ``jmp addr`` with a
        ``push addr; ret`` pair.  This method finds all such 6-byte sequences
        whose pushed value looks like a plausible code pointer.

        Parameters
        ----------
        data : bytes
            Raw binary data.
        image_base : int
            VA of the binary image base (used for pointer validation).
        max_sequences : int
            Cap on the number of returned results.

        Returns
        -------
        list[tuple[int, int]]
            ``(file_offset_of_push, pushed_address)`` pairs.
        """
        results: List[tuple] = []
        data_len = len(data)
        # Pattern: 0x68 <imm32 LE> 0xC3
        needle = b"\x68"
        start = 0

        while len(results) < max_sequences:
            idx = data.find(needle, start)
            if idx == -1 or idx + 6 > data_len:
                break
            start = idx + 1

            # Next byte after the 4-byte immediate must be 0xC3 (ret)
            if data[idx + 5] != 0xC3:
                continue

            pushed = struct.unpack_from("<I", data, idx + 1)[0]

            # Basic validation: pushed value should be a plausible code address
            if pushed == 0:
                continue

            # If we know image_base, target should be >= image_base
            if image_base and pushed < image_base:
                continue

            # For raw files without a known image_base, accept addresses that
            # fit within a 32-bit VA range and aren't tiny constants.
            if pushed < 0x1000:
                continue

            results.append((idx, pushed))

        logger.info("Found %d push/ret sequences", len(results))
        return results

    @staticmethod
    def _extract_table_entries(
        data: bytes,
        table_offset: int,
        max_entries: int = 256,
        entry_size: int = 4,
    ) -> List[int]:
        """
        Extract potential jump table entries starting at table_offset.

        Parameters
        ----------
        entry_size : int
            4 for 32-bit, 8 for 64-bit binaries.
        """
        entries: List[int] = []
        data_len = len(data)
        fmt = "<I" if entry_size == 4 else "<Q"
        max_addr = 0x7FFFFFFF if entry_size == 4 else 0x7FFFFFFFFFFF

        for i in range(max_entries):
            off = table_offset + i * entry_size
            if off + entry_size > data_len:
                break
            try:
                addr = struct.unpack_from(fmt, data, off)[0]
            except struct.error:
                break

            # Basic validation: address should be non-zero and within
            # a plausible code range
            if addr == 0 or addr > max_addr:
                break
            entries.append(addr)

        return entries
