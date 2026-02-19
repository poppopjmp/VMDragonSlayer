"""
Taint Tracking — Core Tracker
==============================

Implements a data-flow taint tracking engine for binary analysis.
Tracks how tainted inputs (e.g. user data, VM bytecode operands) flow
through registers and memory, enabling identification of:

* Which VM handlers consume / produce tainted data.
* Data dependencies between handlers (def-use chains).
* Implicit flows through conditional branches.

The tracker operates on :class:`LiftedInstruction` sequences from the
symbolic execution lifter, making it independent of any specific
disassembler.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntFlag
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class TaintTag(IntFlag):
    """Taint source categories (combinable via OR)."""
    CLEAN = 0
    INPUT = 1           # User / network input
    VM_OPERAND = 2      # VM bytecode operand
    VM_CONTEXT = 4      # VM context / virtual register
    MEMORY = 8          # Value read from memory
    COMPUTED = 16       # Result of tainted computation
    CONTROL = 32        # Affects control flow (implicit taint)
    CRYPTO = 64         # Involved in cryptographic operation


@dataclass
class TaintState:
    """Snapshot of taint status for registers and memory."""
    registers: Dict[str, TaintTag] = field(default_factory=dict)
    memory: Dict[int, TaintTag] = field(default_factory=dict)
    active_tags: Set[TaintTag] = field(default_factory=set)


@dataclass
class TaintEvent:
    """A single taint propagation event."""
    address: int
    instruction: str
    event_type: str      # "propagate", "taint", "untaint", "implicit"
    source: str          # register or memory address
    destination: str     # register or memory address
    tag: TaintTag = TaintTag.CLEAN
    detail: str = ""


@dataclass
class TaintResult:
    """Complete taint analysis result."""
    success: bool
    tainted_registers: Dict[str, str] = field(default_factory=dict)
    tainted_memory: Dict[str, str] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    taint_flow_graph: Dict[str, List[str]] = field(default_factory=dict)
    instructions_analyzed: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "tainted_registers": self.tainted_registers,
            "tainted_memory": self.tainted_memory,
            "events_count": len(self.events),
            "events": self.events[:100],  # cap for serialisation
            "taint_flow_graph": self.taint_flow_graph,
            "instructions_analyzed": self.instructions_analyzed,
            "error": self.error,
        }


class TaintTracker:
    """
    Data-flow taint tracker for lifted instruction sequences.

    Usage::

        tracker = TaintTracker()
        tracker.taint_register("rdi", TaintTag.INPUT)
        result = tracker.analyze(lifted_instructions)
    """

    def __init__(self) -> None:
        self._reg_taint: Dict[str, TaintTag] = {}
        self._mem_taint: Dict[int, TaintTag] = {}
        self._events: List[TaintEvent] = []
        self._flow_graph: Dict[str, Set[str]] = {}

    def taint_register(self, reg: str, tag: TaintTag = TaintTag.INPUT) -> None:
        """Mark a register as tainted with the given tag."""
        self._reg_taint[reg.lower()] = tag

    def taint_memory(self, address: int, tag: TaintTag = TaintTag.MEMORY) -> None:
        """Mark a memory address as tainted."""
        self._mem_taint[address] = tag

    def is_tainted(self, reg: str) -> bool:
        """Check if a register is tainted."""
        return self._reg_taint.get(reg.lower(), TaintTag.CLEAN) != TaintTag.CLEAN

    def get_taint(self, reg: str) -> TaintTag:
        """Get the taint tag for a register."""
        return self._reg_taint.get(reg.lower(), TaintTag.CLEAN)

    def analyze(self, instructions: list) -> TaintResult:
        """
        Propagate taint through a sequence of lifted instructions.

        Parameters
        ----------
        instructions : list[LiftedInstruction]
            Lifted instruction sequence from :class:`InstructionLifter`.

        Returns
        -------
        TaintResult
        """
        try:
            for insn in instructions:
                self._process_instruction(insn)

            # Build result
            tainted_regs = {
                reg: str(tag) for reg, tag in self._reg_taint.items()
                if tag != TaintTag.CLEAN
            }
            tainted_mem = {
                hex(addr): str(tag) for addr, tag in self._mem_taint.items()
                if tag != TaintTag.CLEAN
            }

            # Serialise flow graph
            flow_graph = {
                src: sorted(dsts) for src, dsts in self._flow_graph.items()
            }

            return TaintResult(
                success=True,
                tainted_registers=tainted_regs,
                tainted_memory=tainted_mem,
                events=[self._event_to_dict(e) for e in self._events],
                taint_flow_graph=flow_graph,
                instructions_analyzed=len(instructions),
            )

        except Exception as exc:
            logger.exception("Taint analysis failed")
            return TaintResult(success=False, error=str(exc))

    def _process_instruction(self, insn: Any) -> None:
        """Propagate taint for a single instruction, including memory ops."""
        reads = getattr(insn, "reads", [])
        writes = getattr(insn, "writes", [])
        address = getattr(insn, "address", 0)
        mnemonic = getattr(insn, "mnemonic", "")
        operands = getattr(insn, "operands", "")
        category = getattr(insn, "category", "unknown")

        # Collect taint from read operands (registers)
        combined_taint = TaintTag.CLEAN
        tainted_sources: List[str] = []

        for reg in reads:
            reg_lower = reg.lower()
            tag = self._reg_taint.get(reg_lower, TaintTag.CLEAN)
            if tag != TaintTag.CLEAN:
                combined_taint |= tag
                tainted_sources.append(reg_lower)

        # --- Memory taint propagation ---
        # Check if this is a memory read (load) that reads tainted memory
        if category in ("memory_read", "stack_pop") and not tainted_sources:
            # Parse memory operand to check for tainted memory address
            mem_addr = self._extract_memory_address(operands, reads)
            if mem_addr is not None:
                mem_tag = self._mem_taint.get(mem_addr, TaintTag.CLEAN)
                if mem_tag != TaintTag.CLEAN:
                    combined_taint |= mem_tag
                    tainted_sources.append(f"mem[{mem_addr:#x}]")

        # Taint from base register used as memory pointer
        for reg in reads:
            reg_lower = reg.lower()
            tag = self._reg_taint.get(reg_lower, TaintTag.CLEAN)
            if tag != TaintTag.CLEAN and category in ("memory_read", "memory_write"):
                combined_taint |= TaintTag.MEMORY
                if reg_lower not in tainted_sources:
                    tainted_sources.append(reg_lower)

        # Propagate to write operands
        if combined_taint != TaintTag.CLEAN:
            output_tag = combined_taint | TaintTag.COMPUTED

            for reg in writes:
                reg_lower = reg.lower()
                self._reg_taint[reg_lower] = output_tag

                for src in tainted_sources:
                    self._events.append(TaintEvent(
                        address=address,
                        instruction=f"{mnemonic} {operands}",
                        event_type="propagate",
                        source=src,
                        destination=reg_lower,
                        tag=output_tag,
                    ))
                    self._flow_graph.setdefault(src, set()).add(reg_lower)

            # Memory write with tainted data → taint the memory location
            if category in ("memory_write", "stack_push"):
                mem_addr = self._extract_memory_address(operands, reads)
                if mem_addr is not None:
                    self._mem_taint[mem_addr] = output_tag
                    for src in tainted_sources:
                        self._events.append(TaintEvent(
                            address=address,
                            instruction=f"{mnemonic} {operands}",
                            event_type="propagate",
                            source=src,
                            destination=f"mem[{mem_addr:#x}]",
                            tag=output_tag,
                        ))
                        self._flow_graph.setdefault(src, set()).add(f"mem[{mem_addr:#x}]")

            # Implicit taint for conditional branches
            if category == "branch_conditional":
                for src in tainted_sources:
                    self._events.append(TaintEvent(
                        address=address,
                        instruction=f"{mnemonic} {operands}",
                        event_type="implicit",
                        source=src,
                        destination="control_flow",
                        tag=TaintTag.CONTROL,
                    ))
        else:
            # Clean writes clear taint on destination
            for reg in writes:
                reg_lower = reg.lower()
                if self._reg_taint.get(reg_lower, TaintTag.CLEAN) != TaintTag.CLEAN:
                    self._events.append(TaintEvent(
                        address=address,
                        instruction=f"{mnemonic} {operands}",
                        event_type="untaint",
                        source="clean_value",
                        destination=reg_lower,
                        tag=TaintTag.CLEAN,
                    ))
                    self._reg_taint[reg_lower] = TaintTag.CLEAN

    @staticmethod
    def _extract_memory_address(operands: str, reads: List[str]) -> Optional[int]:
        """
        Try to extract a concrete memory address from operands.

        Only works for simple cases like ``[0x401000]`` or ``[rsp+0x8]``
        (if the register value is not available, returns None).
        """
        if "[" not in operands:
            return None

        import re
        # Match [hex_address]
        m = re.search(r"\[(?:0x)?([0-9a-fA-F]+)\]", operands)
        if m:
            try:
                return int(m.group(1), 16)
            except ValueError:
                pass
        return None

    @staticmethod
    def _event_to_dict(event: TaintEvent) -> Dict[str, Any]:
        return {
            "address": event.address,
            "instruction": event.instruction,
            "type": event.event_type,
            "source": event.source,
            "destination": event.destination,
            "tag": str(event.tag),
            "detail": event.detail,
        }

    def get_state(self) -> TaintState:
        """Return current taint state snapshot."""
        return TaintState(
            registers=dict(self._reg_taint),
            memory=dict(self._mem_taint),
            active_tags={t for t in self._reg_taint.values() if t != TaintTag.CLEAN},
        )

    def reset(self) -> None:
        """Clear all taint state."""
        self._reg_taint.clear()
        self._mem_taint.clear()
        self._events.clear()
        self._flow_graph.clear()
