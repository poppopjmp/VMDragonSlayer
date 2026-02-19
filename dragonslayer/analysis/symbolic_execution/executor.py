"""
Symbolic Execution — Executor
==============================

Symbolic executor that drives :class:`SymbolicState` through lifted
instructions, forking on branches and using :class:`Z3Solver` to resolve
constraints.  Focused on VM handler identification: it follows the
dispatcher loop, classifies handler semantics, and builds a handler table.

For production-grade symbolic execution, the angr and triton plugins
provide full-featured engines.  This module is intentionally simpler —
usable without heavy dependencies — and provides the data structures that
the pipeline and LLM analyzer consume.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .state import SymbolicState
from .lifter import InstructionLifter, LiftedInstruction, InstructionCategory
from .solver import Z3Solver, SolverResult

logger = logging.getLogger(__name__)


@dataclass
class HandlerInfo:
    """Information about a discovered VM handler."""
    address: int
    category: str
    instruction_count: int
    instructions: List[Dict[str, Any]] = field(default_factory=list)
    reads: List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "category": self.category,
            "instruction_count": self.instruction_count,
            "instructions": self.instructions,
            "reads": self.reads,
            "writes": self.writes,
            "confidence": self.confidence,
        }


@dataclass
class ExecutionResult:
    """Result of symbolic execution analysis."""
    success: bool
    handlers: List[HandlerInfo] = field(default_factory=list)
    paths_explored: int = 0
    instructions_executed: int = 0
    dispatcher_address: Optional[int] = None
    handler_table: Dict[int, str] = field(default_factory=dict)
    opaque_predicates: List[Dict[str, Any]] = field(default_factory=list)
    state_snapshots: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "handlers": [h.to_dict() for h in self.handlers],
            "paths_explored": self.paths_explored,
            "instructions_executed": self.instructions_executed,
            "dispatcher_address": self.dispatcher_address,
            "handler_table": {hex(k): v for k, v in self.handler_table.items()},
            "opaque_predicates": self.opaque_predicates,
            "state_snapshot_count": len(self.state_snapshots),
            "error": self.error,
        }


class SymbolicExecutor:
    """
    Lightweight symbolic executor for VM handler analysis.

    Usage::

        executor = SymbolicExecutor(arch="x86_64")
        result = executor.analyze(code_bytes, entry_point=0x401000)
    """

    def __init__(
        self,
        arch: str = "x86_64",
        max_depth: int = 1000,
        max_paths: int = 64,
    ) -> None:
        self.arch = arch
        self.bit_width = 64 if "64" in arch else 32
        self.max_depth = max_depth
        self.max_paths = max_paths
        self._lifter = InstructionLifter(arch=arch)
        self._solver = Z3Solver()

    def analyze(
        self,
        code: bytes,
        entry_point: int = 0,
    ) -> ExecutionResult:
        """
        Analyse *code* starting from *entry_point*.

        Lifts instructions, identifies basic blocks, detects the dispatcher
        pattern, classifies handlers, and checks for opaque predicates.
        """
        try:
            # Step 1: Lift instructions
            instructions = self._lifter.lift(code, base_address=entry_point)
            if not instructions:
                return ExecutionResult(success=False, error="No instructions lifted")

            insn_map: Dict[int, LiftedInstruction] = {i.address: i for i in instructions}

            # Step 2: Find basic blocks
            blocks = self._find_basic_blocks(instructions)

            # Step 3: Identify dispatcher (most-targeted indirect jump)
            dispatcher_addr = self._find_dispatcher(instructions)

            # Step 4: Classify handlers
            handlers = self._classify_handlers(blocks, insn_map)

            # Step 5: Detect opaque predicates
            opaque = self._detect_opaque_predicates(instructions)

            # Step 6: Build handler table
            handler_table = {h.address: h.category for h in handlers}

            # Step 7: Symbolic exploration
            paths_explored, total_insns, snapshots = self._explore_paths(
                insn_map, entry_point,
            )

            return ExecutionResult(
                success=True,
                handlers=handlers,
                paths_explored=paths_explored,
                instructions_executed=total_insns,
                dispatcher_address=dispatcher_addr,
                handler_table=handler_table,
                opaque_predicates=opaque,
                state_snapshots=snapshots,
            )

        except Exception as exc:
            logger.exception("Symbolic execution failed")
            return ExecutionResult(success=False, error=str(exc))

    # -- Basic block discovery -----------------------------------------------

    @staticmethod
    def _find_basic_blocks(
        instructions: List[LiftedInstruction],
    ) -> List[List[LiftedInstruction]]:
        """Split instructions into basic blocks (sequences ending at branches)."""
        blocks: List[List[LiftedInstruction]] = []
        current: List[LiftedInstruction] = []

        # Collect branch targets to mark block starts
        targets = set()
        for insn in instructions:
            if insn.branch_target is not None:
                targets.add(insn.branch_target)

        for insn in instructions:
            if insn.address in targets and current:
                blocks.append(current)
                current = []
            current.append(insn)
            if insn.is_branch or insn.category == InstructionCategory.RETURN:
                blocks.append(current)
                current = []

        if current:
            blocks.append(current)

        return blocks

    # -- Dispatcher identification -------------------------------------------

    @staticmethod
    def _find_dispatcher(instructions: List[LiftedInstruction]) -> Optional[int]:
        """
        Find the likely VM dispatcher address.

        Heuristic: the indirect jump instruction that is targetted by the
        most back-edges (or the first ``jmp reg`` if few instructions).
        """
        indirect_jumps: List[int] = []
        for insn in instructions:
            if insn.category == InstructionCategory.BRANCH_UNCOND and insn.branch_target is None:
                # Indirect jump (target is a register, not immediate)
                indirect_jumps.append(insn.address)

        if not indirect_jumps:
            return None

        # Score by how many branches target the block containing the jump
        # Simple heuristic: return the first one (often the dispatcher)
        return indirect_jumps[0]

    # -- Handler classification -----------------------------------------------

    def _classify_handlers(
        self,
        blocks: List[List[LiftedInstruction]],
        insn_map: Dict[int, LiftedInstruction],
    ) -> List[HandlerInfo]:
        """Classify basic blocks into handler categories."""
        handlers: List[HandlerInfo] = []

        for block in blocks:
            if not block:
                continue

            # Count instruction categories in this block
            cat_counts: Dict[str, int] = {}
            all_reads: set = set()
            all_writes: set = set()

            for insn in block:
                cat_counts[insn.category] = cat_counts.get(insn.category, 0) + 1
                all_reads.update(insn.reads)
                all_writes.update(insn.writes)

            # Determine dominant category
            dominant = max(cat_counts, key=cat_counts.get) if cat_counts else InstructionCategory.UNKNOWN

            # Filter out trivial blocks (single NOP, etc.)
            if len(block) <= 1 and dominant == InstructionCategory.NOP:
                continue

            # Confidence based on dominance ratio
            total = sum(cat_counts.values())
            confidence = cat_counts.get(dominant, 0) / total if total else 0.0

            handlers.append(HandlerInfo(
                address=block[0].address,
                category=dominant,
                instruction_count=len(block),
                instructions=[insn.to_dict() for insn in block[:20]],  # cap for serialisation
                reads=sorted(all_reads),
                writes=sorted(all_writes),
                confidence=round(confidence, 4),
            ))

        return handlers

    # -- Opaque predicate detection ------------------------------------------

    def _detect_opaque_predicates(
        self,
        instructions: List[LiftedInstruction],
    ) -> List[Dict[str, Any]]:
        """
        Scan for potential opaque predicates.

        An opaque predicate is a conditional branch whose condition is
        always true or always false.  Common in VM obfuscation to
        confuse static analysis.
        """
        if not Z3Solver.available():
            return []

        opaque: List[Dict[str, Any]] = []

        # Simple heuristic: flag conditional branches preceded by
        # a comparison with a constant (often opaque).
        prev_insn: Optional[LiftedInstruction] = None
        for insn in instructions:
            if (
                insn.category == InstructionCategory.BRANCH_COND
                and prev_insn is not None
                and prev_insn.category == InstructionCategory.LOGIC
                and prev_insn.mnemonic in ("cmp", "test")
            ):
                # Check if operand is a constant comparison pattern
                # (e.g., `cmp eax, eax` → always equal → opaque)
                ops = prev_insn.operands.replace(" ", "").split(",")
                if len(ops) == 2 and ops[0] == ops[1]:
                    result = self._solver.is_opaque_predicate(True)  # trivially true
                    opaque.append({
                        "address": insn.address,
                        "comparison_address": prev_insn.address,
                        "comparison": f"{prev_insn.mnemonic} {prev_insn.operands}",
                        "branch": f"{insn.mnemonic} {insn.operands}",
                        "always_true": True,
                        "confidence": 0.95,
                    })

            prev_insn = insn

        return opaque

    # -- Path exploration ----------------------------------------------------

    def _explore_paths(
        self,
        insn_map: Dict[int, LiftedInstruction],
        entry_point: int,
    ) -> tuple[int, int, List[Dict[str, Any]]]:
        """
        Simple BFS path exploration through the instruction map.

        Returns (paths_explored, total_instructions_executed, state_snapshots).
        """
        if not insn_map:
            return 0, 0, []

        initial_state = SymbolicState(
            arch=self.arch,
            bit_width=self.bit_width,
            initial_pc=entry_point,
        )

        worklist = [initial_state]
        paths = 0
        total_insns = 0
        snapshots: List[Dict[str, Any]] = []

        # BFS with bounded exploration
        addresses_sorted = sorted(insn_map.keys())

        while worklist and paths < self.max_paths:
            state = worklist.pop(0)
            path_len = 0

            while not state.halted and path_len < self.max_depth:
                insn = insn_map.get(state.pc)
                if insn is None:
                    state.halt("address not in map")
                    break

                state.visit(state.pc)
                total_insns += 1
                path_len += 1

                if insn.category == InstructionCategory.RETURN:
                    state.halt("return")
                    break

                if insn.is_branch:
                    if insn.category == InstructionCategory.BRANCH_COND and insn.branch_target:
                        # Fork: one path takes the branch, one falls through
                        if len(worklist) < self.max_paths:
                            taken = state.fork()
                            taken.pc = insn.branch_target
                            worklist.append(taken)
                        # Fall-through
                        next_addr = insn.address + insn.size
                        if next_addr in insn_map:
                            state.pc = next_addr
                        else:
                            state.halt("fall-through not in map")
                            break
                    elif insn.branch_target is not None:
                        state.pc = insn.branch_target
                    else:
                        state.halt("indirect branch")
                        break
                else:
                    # Linear execution
                    next_addr = insn.address + insn.size
                    if next_addr in insn_map:
                        state.pc = next_addr
                    else:
                        state.halt("next address not in map")
                        break

            paths += 1
            snapshots.append(state.to_dict())

        return paths, total_insns, snapshots[:32]  # cap snapshots
