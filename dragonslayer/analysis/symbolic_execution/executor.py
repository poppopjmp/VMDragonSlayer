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

import heapq
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

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
    vmprotect_dispatcher: Optional[Dict[str, Any]] = None
    loops_detected: List[Dict[str, Any]] = field(default_factory=list)
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
            "vmprotect_dispatcher": self.vmprotect_dispatcher,
            "loops_detected": self.loops_detected,
            "error": self.error,
        }


@dataclass
class HandlerSymbolicSummary:
    """Symbolic summary of a single handler after local execution."""
    address: int = 0
    instruction_count: int = 0
    final_registers: Dict[str, str] = field(default_factory=dict)
    simplified_registers: Dict[str, str] = field(default_factory=dict)
    memory_writes: List[Dict[str, Any]] = field(default_factory=list)
    constraints: List[str] = field(default_factory=list)
    input_symbols: Dict[str, str] = field(default_factory=dict)
    memory_effects: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "instruction_count": self.instruction_count,
            "final_registers": self.final_registers,
            "simplified_registers": self.simplified_registers,
            "memory_write_count": len(self.memory_writes),
            "memory_writes": self.memory_writes,
            "constraint_count": len(self.constraints),
            "constraints": self.constraints,
            "memory_effects": self.memory_effects,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Loop analysis data structures  (Batch 35)
# ---------------------------------------------------------------------------

@dataclass
class LoopInfo:
    """Information about a detected loop during symbolic execution."""
    header_address: int
    back_edge_sources: List[int] = field(default_factory=list)
    iteration_count: int = 0
    body_addresses: Set[int] = field(default_factory=set)
    widened: bool = False
    widened_registers: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header_address": hex(self.header_address),
            "back_edge_sources": [hex(a) for a in self.back_edge_sources],
            "iteration_count": self.iteration_count,
            "body_size": len(self.body_addresses),
            "widened": self.widened,
            "widened_registers": self.widened_registers,
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
        max_loop_iters: int = 3,
        solver_timeout_ms: int = 10000,
        memory_limit_mb: int = 0,
    ) -> None:
        self.arch = arch
        self.bit_width = 64 if "64" in arch else 32
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.max_loop_iters = max_loop_iters
        self._lifter = InstructionLifter(arch=arch)
        self._solver = Z3Solver(
            timeout_ms=solver_timeout_ms,
            memory_limit_mb=memory_limit_mb,
        )
        # Path constraints gathered during _explore_paths for opaque detection.
        self._collected_path_constraints: List[Any] = []
        # Loop analysis results gathered during exploration.
        self._detected_loops: Dict[int, LoopInfo] = {}
        # B54: monotonic counter for heapq tie-breaking
        self._state_seq: int = 0

    @classmethod
    def from_config(cls, config: Any = None) -> "SymbolicExecutor":
        """Create an executor from the global or provided config (B53).

        Reads ``symbolic_execution.*`` section for solver_timeout_ms,
        max_paths, max_depth, max_loop_iters, memory_limit_mb.
        """
        if config is None:
            try:
                from dragonslayer.core.config import get_config
                config = get_config()
            except Exception:
                return cls()

        return cls(
            max_depth=config.get("symbolic_execution.max_depth", 1000),
            max_paths=config.get("symbolic_execution.max_paths", 64),
            max_loop_iters=config.get("symbolic_execution.max_loop_iters", 3),
            solver_timeout_ms=config.get("symbolic_execution.solver_timeout_ms", 10000),
            memory_limit_mb=config.get("symbolic_execution.memory_limit_mb", 0),
        )

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

            # Step 3: Identify dispatcher using VMProtect pattern matching
            dispatcher_addr = self._find_dispatcher(instructions)
            # Also run the new VMProtect-specific dispatcher identification
            self._vmprotect_dispatcher = self._find_vmprotect_dispatcher(
                instructions, code, entry_point,
            )
            if self._vmprotect_dispatcher is not None and dispatcher_addr is None:
                dispatcher_addr = self._vmprotect_dispatcher.entry_address

            # Step 4: Classify handlers (uses VMProtect dispatcher context)
            handlers = self._classify_handlers(blocks, insn_map)

            # Step 5: Build handler table
            handler_table = {h.address: h.category for h in handlers}

            # Step 6: Symbolic exploration (must run before opaque detection
            # so path constraints are available).
            paths_explored, total_insns, snapshots = self._explore_paths(
                insn_map, entry_point,
            )

            # Step 7: Detect opaque predicates — now with path constraints
            # collected during exploration.
            opaque = self._detect_opaque_predicates(
                instructions,
                path_constraints=self._collected_path_constraints,
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
                vmprotect_dispatcher=(
                    self._vmprotect_dispatcher.to_dict()
                    if self._vmprotect_dispatcher else None
                ),
                loops_detected=[
                    li.to_dict() for li in self._detected_loops.values()
                ],
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

        Heuristic: score each indirect jump by how many *back-edges* (branches
        whose target is at or before the jump itself) exist in the instruction
        stream.  The indirect jump with the highest back-edge count is the most
        likely dispatcher loop head.  Falls back to the first indirect jump if
        no back-edge information is available.
        """
        indirect_jumps: List[int] = []
        for insn in instructions:
            if insn.category == InstructionCategory.BRANCH_UNCOND and insn.branch_target is None:
                indirect_jumps.append(insn.address)

        if not indirect_jumps:
            return None

        if len(indirect_jumps) == 1:
            return indirect_jumps[0]

        # Build a set of indirect-jump addresses for fast lookup
        ij_set = set(indirect_jumps)

        # Collect all branch targets in the instruction stream
        branch_targets: Dict[int, int] = {}  # target_addr -> count
        for insn in instructions:
            cat = insn.category
            if cat in (InstructionCategory.BRANCH_UNCOND, InstructionCategory.BRANCH_COND):
                tgt = insn.branch_target
                if tgt is not None:
                    branch_targets[tgt] = branch_targets.get(tgt, 0) + 1

        # Score each indirect jump by the number of back-edges that land in
        # the same basic-block neighbourhood (within ±64 bytes of the jump).
        best_addr = indirect_jumps[0]
        best_score = 0

        for ij_addr in indirect_jumps:
            score = 0
            for tgt, cnt in branch_targets.items():
                # A "back-edge" targets at or before the indirect jump
                if tgt <= ij_addr and abs(tgt - ij_addr) <= 64:
                    score += cnt
            if score > best_score:
                best_score = score
                best_addr = ij_addr

        return best_addr

    def _find_vmprotect_dispatcher(
        self,
        instructions: List[LiftedInstruction],
        code: bytes,
        entry_point: int,
    ) -> Optional[Any]:
        """Run VMProtect-specific dispatcher pattern matching.

        Uses :func:`~dragonslayer.analysis.vm_discovery.dispatcher.find_vmprotect_dispatcher`
        to identify the canonical fetch→decode→advance→dispatch cycle.
        Returns a :class:`VMProtectDispatcherMatch` or ``None``.
        """
        try:
            from dragonslayer.analysis.vm_discovery.dispatcher import (
                find_vmprotect_dispatcher,
            )
            return find_vmprotect_dispatcher(
                instructions,
                bit_width=self.bit_width,
                binary_data=code,
                base_address=entry_point,
            )
        except Exception as exc:
            logger.debug("VMProtect dispatcher analysis failed: %s", exc)
            return None

    # -- Handler classification -----------------------------------------------

    def _classify_handlers(
        self,
        blocks: List[List[LiftedInstruction]],
        insn_map: Dict[int, LiftedInstruction],
    ) -> List[HandlerInfo]:
        """Classify basic blocks into handler categories.

        When a VMProtect dispatcher has been identified, blocks that
        overlap with the dispatcher loop are marked as "dispatcher" and
        blocks that end with a jump back to the dispatcher are tagged as
        handler candidates with higher confidence.
        """
        handlers: List[HandlerInfo] = []

        # Determine dispatcher address range for overlap detection
        dispatcher_range: Optional[range] = None
        vmp_disp = getattr(self, "_vmprotect_dispatcher", None)
        if vmp_disp is not None:
            lo = vmp_disp.entry_address
            hi = vmp_disp.indirect_jump_address
            dispatcher_range = range(min(lo, hi), max(lo, hi) + 16)

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

            # ── VMProtect-aware adjustments ──
            block_start = block[0].address
            block_end = block[-1].address

            # Mark blocks overlapping the dispatcher loop
            if dispatcher_range is not None and block_start in dispatcher_range:
                dominant = "dispatcher"
                confidence = 0.9

            # Boost confidence for blocks ending with jmp back to dispatcher
            if dispatcher_range is not None:
                last = block[-1]
                if (last.is_branch
                        and last.branch_target is not None
                        and last.branch_target in dispatcher_range):
                    confidence = min(confidence + 0.2, 1.0)

            handlers.append(HandlerInfo(
                address=block_start,
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
        *,
        path_constraints: Optional[List[Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Scan for potential opaque predicates.

        An opaque predicate is a conditional branch whose condition is
        always true or always false.  Common in VM obfuscation to
        confuse static analysis.

        Enhancements over the naïve ``cmp reg, reg`` check:

        * **Path constraint context** — when *path_constraints* are
          supplied (from ``_explore_paths``), the solver checks
          satisfiability *under* the accumulated path condition.
          A branch that is non-trivially opaque (only always-true
          given prior constraints) is detected with confidence 0.85.
        * **``cmp reg, imm`` with z3** — unconstrained symbolic check
          (original).
        * **Arithmetic opaque predicates** — recognises patterns like
          ``x*(x-1) %% 2 == 0`` via z3 (always true for any integer).

        Parameters
        ----------
        instructions : list
            Lifted instruction stream.
        path_constraints : list or None
            Collected during ``_explore_paths``, each entry is a dict
            with ``address``, ``constraint``, ``state_constraints``.
        """
        if not Z3Solver.available():
            return []

        import z3 as _z3

        opaque: List[Dict[str, Any]] = []
        path_constraints = path_constraints or []

        # Index path constraints by branch address for fast lookup.
        pc_by_addr: Dict[int, List[Dict[str, Any]]] = {}
        for pc in path_constraints:
            addr = pc.get("address")
            if addr is not None:
                pc_by_addr.setdefault(addr, []).append(pc)

        # Phase 1: Path-constraint-aware opaque detection.
        # Uses constraints collected during symbolic path exploration.
        for addr, entries in pc_by_addr.items():
            for entry in entries:
                cond = entry.get("constraint")
                state_cs = entry.get("state_constraints", [])
                if cond is None:
                    continue
                try:
                    # Check if this branch is always-true/false under
                    # the accumulated path constraints.
                    result = self._solver.is_opaque_predicate_with_context(
                        cond, state_cs,
                    )
                    if result in (True, False):
                        opaque.append({
                            "address": addr,
                            "always_true": result,
                            "confidence": 0.85,
                            "source": "path_constraint",
                        })
                except Exception:
                    pass

        # Track which addresses already flagged via path constraints.
        flagged = {e["address"] for e in opaque}

        # Phase 2: Linear scan for syntactic cmp/test + jcc pairs.
        prev_insn: Optional[LiftedInstruction] = None
        for insn in instructions:
            if insn.address in flagged:
                prev_insn = insn
                continue

            if (
                insn.category == InstructionCategory.BRANCH_COND
                and prev_insn is not None
                and prev_insn.category == InstructionCategory.LOGIC
                and prev_insn.mnemonic in ("cmp", "test")
            ):
                ops = prev_insn.operands.replace(" ", "").split(",")
                if len(ops) == 2:
                    if ops[0] == ops[1]:
                        if prev_insn.mnemonic == "test":
                            opaque.append({
                                "address": insn.address,
                                "comparison_address": prev_insn.address,
                                "comparison": f"{prev_insn.mnemonic} {prev_insn.operands}",
                                "branch": f"{insn.mnemonic} {insn.operands}",
                                "always_true": None,
                                "confidence": 0.5,
                                "source": "syntactic",
                            })
                        else:
                            opaque.append({
                                "address": insn.address,
                                "comparison_address": prev_insn.address,
                                "comparison": f"{prev_insn.mnemonic} {prev_insn.operands}",
                                "branch": f"{insn.mnemonic} {insn.operands}",
                                "always_true": insn.mnemonic in ("je", "jz", "jle", "jge", "jbe", "jae"),
                                "confidence": 0.99,
                                "source": "syntactic",
                            })
                    else:
                        cond = self._build_opaque_condition(
                            _z3, insn.mnemonic, ops, prev_insn.mnemonic,
                        )
                        if cond is not None:
                            result = self._solver.is_opaque_predicate(cond)
                            if result in (True, False):
                                opaque.append({
                                    "address": insn.address,
                                    "comparison_address": prev_insn.address,
                                    "comparison": f"{prev_insn.mnemonic} {prev_insn.operands}",
                                    "branch": f"{insn.mnemonic} {insn.operands}",
                                    "always_true": result,
                                    "confidence": 0.90,
                                    "source": "z3_unconstrained",
                                })

            prev_insn = insn

        # Phase 2.5 (B45): Two-variable MBA opaque predicates.
        # Detect patterns like ``(x & y) | (~x & y) == y`` which are
        # Boolean-algebra tautologies VMProtect sometimes inserts.
        opaque.extend(self._detect_mba_opaques(_z3, instructions, flagged))

        # Phase 3: Detect common arithmetic opaque predicates.
        opaque.extend(self._detect_arithmetic_opaques(_z3, instructions, flagged))

        return opaque

    def _build_opaque_condition(
        self,
        _z3: Any,
        branch_mn: str,
        cmp_ops: List[str],
        cmp_mn: str,
    ) -> Any:
        """Build a z3 condition from a cmp/test + jcc pair.

        Handles both ``cmp reg, imm`` and ``cmp reg, reg`` with
        distinct symbolic variables.
        """
        def _parse_operand(name: str) -> Any:
            """Return z3 BitVec for registers, BitVecVal for immediates."""
            # Try integer literal.
            try:
                val = int(name, 0) if name.startswith("0x") else int(name) if name.lstrip("-").isdigit() else None
            except ValueError:
                val = None
            if val is not None:
                return _z3.BitVecVal(val, self.bit_width)
            # Otherwise symbolic register.
            return _z3.BitVec(f"op_{name}", self.bit_width)

        left = _parse_operand(cmp_ops[0])
        right = _parse_operand(cmp_ops[1])

        if cmp_mn == "test":
            # test performs AND; flags are set based on left & right
            result = left & right
            # For test, conditions reference the AND result
            mn = branch_mn
            if mn in ("je", "jz"):
                return result == 0
            elif mn in ("jne", "jnz"):
                return result != 0
            elif mn == "js":
                return result < 0  # signed
            elif mn == "jns":
                return result >= 0  # signed
            else:
                return None

        # cmp performs SUB; conditions reference left vs right
        mn = branch_mn
        if mn in ("je", "jz"):
            return left == right
        elif mn in ("jne", "jnz"):
            return left != right
        elif mn == "jg":
            return left > right
        elif mn == "jge":
            return left >= right
        elif mn == "jl":
            return left < right
        elif mn == "jle":
            return left <= right
        elif mn == "ja":
            return _z3.UGT(left, right)
        elif mn == "jae":
            return _z3.UGE(left, right)
        elif mn == "jb":
            return _z3.ULT(left, right)
        elif mn == "jbe":
            return _z3.ULE(left, right)
        return None

    @staticmethod
    def _detect_arithmetic_opaques(
        _z3: Any,
        instructions: List[LiftedInstruction],
        already_flagged: set,
    ) -> List[Dict[str, Any]]:
        """Detect arithmetic opaque predicates.

        Patterns:
        - ``x * (x - 1) % 2 == 0``  (product of consecutive ints is even)
        - ``x * x >= 0``             (unsigned square is non-negative)
        - ``x | (x - 1) >= x - 1``   (always true)
        """
        results: List[Dict[str, Any]] = []
        x = _z3.BitVec("arith_x", 64)

        # Pre-built tautologies to check against instruction patterns.
        _ARITH_PATTERNS = [
            ("x*(x-1)%2==0", (x * (x - 1)) % 2 == 0, 0.92),
            ("x|1 != 0", (x | 1) != 0, 0.95),
            # B45: additional arithmetic/bit-manipulation tautologies
            ("x^x==0", x ^ x == 0, 0.99),
            ("x&x==x", (x & x) == x, 0.98),
            ("(x|x)==x", (x | x) == x, 0.98),
            ("x-x==0", (x - x) == 0, 0.99),
            ("~~x==x", ~(~x) == x, 0.97),
            ("(x&1)|(x&~1)==x", ((x & 1) | (x & ~_z3.BitVecVal(1, 64))) == x, 0.94),
        ]

        # Scan for mul → and/test → jz sequences (3-instruction window).
        for i in range(len(instructions) - 2):
            if instructions[i + 2].address in already_flagged:
                continue

            i0, i1, i2 = instructions[i], instructions[i + 1], instructions[i + 2]

            if (
                i0.mnemonic in ("imul", "mul")
                and i1.mnemonic in ("and", "test")
                and i2.category == InstructionCategory.BRANCH_COND
            ):
                # Pattern: multiply → mask → branch  (likely x*(x-1)%2==0)
                for name, cond, conf in _ARITH_PATTERNS:
                    s = _z3.Solver()
                    s.set("timeout", 500)
                    s.add(_z3.Not(cond))
                    if s.check() == _z3.unsat:
                        results.append({
                            "address": i2.address,
                            "pattern": name,
                            "always_true": True,
                            "confidence": conf,
                            "source": "arithmetic",
                        })
                        break

        return results

    @staticmethod
    def _detect_mba_opaques(
        _z3: Any,
        instructions: List[LiftedInstruction],
        already_flagged: set,
    ) -> List[Dict[str, Any]]:
        """Detect mixed-boolean-arithmetic (MBA) opaque predicates (B45).

        Scans for instruction sequences that combine XOR/AND/OR/NOT
        followed by a conditional branch.  Builds symbolic models for
        two-variable tautologies such as ``(x & y) | (x & ~y) == x``.
        """
        results: List[Dict[str, Any]] = []
        x = _z3.BitVec("mba_x", 64)
        y = _z3.BitVec("mba_y", 64)

        _MBA_PATTERNS = [
            ("(x&y)|(x&~y)==x", ((x & y) | (x & ~y)) == x, 0.93),
            ("(x|y)&(x|~y)==x", ((x | y) & (x | ~y)) == x, 0.93),
            ("(x^y)^y==x", (x ^ y) ^ y == x, 0.96),
            ("(x+y)-(y)==x", (x + y) - y == x, 0.94),
            ("(x&y)|(~x&y)==y", ((x & y) | (~x & y)) == y, 0.93),
        ]

        # Scan 3-instruction windows: bitwise op → bitwise op → branch.
        _BITWISE = {"xor", "and", "or", "not", "andn"}
        for i in range(len(instructions) - 2):
            if instructions[i + 2].address in already_flagged:
                continue
            i0, i1, i2 = instructions[i], instructions[i + 1], instructions[i + 2]
            if (
                i0.mnemonic in _BITWISE
                and i1.mnemonic in _BITWISE | {"cmp", "test"}
                and i2.category == InstructionCategory.BRANCH_COND
            ):
                for name, cond, conf in _MBA_PATTERNS:
                    s = _z3.Solver()
                    s.set("timeout", 500)
                    s.add(_z3.Not(cond))
                    if s.check() == _z3.unsat:
                        results.append({
                            "address": i2.address,
                            "pattern": name,
                            "always_true": True,
                            "confidence": conf,
                            "source": "mba",
                        })
                        break
        return results

    # -- Path exploration with instruction semantics --------------------------

    def _explore_paths(
        self,
        insn_map: Dict[int, LiftedInstruction],
        entry_point: int,
    ) -> tuple[int, int, List[Dict[str, Any]]]:
        """
        Coverage-guided path exploration with symbolic state updates.

        Uses a **priority worklist** (B54): states that have explored more
        unique PCs are dequeued first, giving a coverage-guided strategy
        instead of plain BFS.

        Supports **symbolic call/return tracking** (B54): CALL instructions
        push the return address onto the state's ``call_stack`` so that
        RET can continue execution at the return site instead of halting.

        Includes **veritesting** (B54): when a conditional branch's
        fall-through and taken paths both immediately rejoin at a common
        merge point within a short window, both sides are executed inline
        on a single path using an ITE merge, avoiding a fork entirely.

        Returns (paths_explored, total_instructions_executed, state_snapshots).
        """
        if not insn_map:
            return 0, 0, []

        # Reset path constraints and loop info for this analysis run.
        self._collected_path_constraints = []
        self._detected_loops = {}

        initial_state = SymbolicState(
            arch=self.arch,
            bit_width=self.bit_width,
            initial_pc=entry_point,
        )
        initial_state._seq = self._state_seq
        self._state_seq += 1

        # B54: Priority-based worklist (heapq — min-heap on state.priority)
        worklist: List[SymbolicState] = [initial_state]
        heapq.heapify(worklist)

        paths = 0
        total_insns = 0
        snapshots: List[Dict[str, Any]] = []

        while worklist and paths < self.max_paths:
            state = heapq.heappop(worklist)

            # --- B52: Path merging at join points ---
            state = self._try_merge_worklist(state, worklist)

            path_len = 0

            while not state.halted and path_len < self.max_depth:
                insn = insn_map.get(state.pc)
                if insn is None:
                    state.halt("address not in map")
                    break

                pc = state.pc
                state.visit(pc)
                total_insns += 1
                path_len += 1

                # --- Loop detection & bounded execution (B35) ----
                vc = state.visit_count(pc)
                if vc > 1:
                    self._record_loop_header(pc, state)

                if vc > self.max_loop_iters:
                    self._widen_state(state, pc)
                    state.halt("loop_bound")
                    break

                # === Apply instruction semantics to state ===
                self._apply_instruction(state, insn)

                # B54: CALL handling — push return addr, jump to target
                if insn.category == InstructionCategory.CALL:
                    return_addr = insn.address + insn.size
                    if insn.branch_target is not None and insn.branch_target in insn_map:
                        state.push_call(return_addr)
                        state.pc = insn.branch_target
                        continue
                    # If target not in map, fall through normally

                if insn.category == InstructionCategory.RETURN:
                    # B54: Pop call stack first; only halt if stack empty
                    ret_addr = state.pop_call()
                    if ret_addr is not None and ret_addr in insn_map:
                        state.pc = ret_addr
                        continue
                    state.halt("return")
                    break

                if insn.is_branch:
                    if insn.category == InstructionCategory.BRANCH_COND and insn.branch_target:
                        # Build branch constraint if z3 available
                        branch_constraint = self._build_branch_constraint(state, insn)

                        # Collect constraint for opaque predicate analysis.
                        if branch_constraint is not None:
                            self._collected_path_constraints.append({
                                "address": insn.address,
                                "constraint": branch_constraint,
                                "state_constraints": list(state.constraints),
                            })

                        # --- B54: Veritesting — try inline merge -----------
                        if self._try_veritest(
                            state, insn, branch_constraint, insn_map
                        ):
                            # Veritesting succeeded: state.pc updated to merge
                            continue

                        if len(worklist) < self.max_paths:
                            # B59: Incremental feasibility check — prune
                            # the taken branch if it is provably infeasible
                            # under the current path constraints.
                            taken_feasible = True
                            if branch_constraint is not None:
                                try:
                                    self._solver.reset()
                                    for c in state.constraints:
                                        self._solver.add(c)
                                    taken_feasible = self._solver.check_feasibility(
                                        branch_constraint
                                    )
                                except Exception:
                                    taken_feasible = True  # conservative

                            if taken_feasible:
                                taken = state.fork()
                                taken.pc = insn.branch_target
                                if branch_constraint is not None:
                                    taken.add_constraint(branch_constraint)
                                # B54: assign priority and sequence
                                taken.compute_priority()
                                taken._seq = self._state_seq
                                self._state_seq += 1
                                heapq.heappush(worklist, taken)

                        # Fall-through with negated constraint
                        next_addr = insn.address + insn.size
                        if next_addr in insn_map:
                            state.pc = next_addr
                            if branch_constraint is not None and Z3Solver.available():
                                import z3 as _z3
                                # B59: Check fall-through feasibility before
                                # committing the negated constraint.
                                neg_constraint = _z3.Not(branch_constraint)
                                fall_feasible = True
                                try:
                                    self._solver.reset()
                                    for c in state.constraints:
                                        self._solver.add(c)
                                    fall_feasible = self._solver.check_feasibility(
                                        neg_constraint
                                    )
                                except Exception:
                                    fall_feasible = True
                                if fall_feasible:
                                    state.add_constraint(neg_constraint)
                                else:
                                    state.halt("fall-through infeasible")
                                    break
                        else:
                            state.halt("fall-through not in map")
                            break
                    elif insn.branch_target is not None:
                        state.pc = insn.branch_target
                    else:
                        # B45: Attempt Z3-based indirect dispatch resolution.
                        targets = self._resolve_indirect_branch(state, insn)
                        if targets:
                            for t in targets[1:]:
                                if len(worklist) < self.max_paths:
                                    fork = state.fork()
                                    fork.pc = t
                                    fork.compute_priority()
                                    fork._seq = self._state_seq
                                    self._state_seq += 1
                                    heapq.heappush(worklist, fork)
                            state.pc = targets[0]
                        else:
                            state.halt("indirect branch")
                            break
                else:
                    next_addr = insn.address + insn.size
                    if next_addr in insn_map:
                        state.pc = next_addr
                    else:
                        state.halt("next address not in map")
                        break

            paths += 1
            snapshots.append(state.to_dict())

        return paths, total_insns, snapshots[:32]

    # -- Veritesting (B54) ---------------------------------------------------

    def _try_veritest(
        self,
        state: SymbolicState,
        insn: LiftedInstruction,
        branch_constraint: Any,
        insn_map: Dict[int, LiftedInstruction],
        max_window: int = 6,
    ) -> bool:
        """Attempt veritesting: inline both sides if they merge quickly.

        Looks ahead up to *max_window* instructions on each branch side.
        If both sides reach the same merge PC via straight-line (no further
        branches), executes both paths on cloned states, then merges the
        results using ITE phi-nodes.

        Returns ``True`` if veritesting succeeded (state updated to merge
        point), ``False`` if the caller should fork normally.
        """
        if branch_constraint is None or not Z3Solver.available():
            return False

        taken_target = insn.branch_target
        fall_target = insn.address + insn.size
        if taken_target is None or fall_target not in insn_map or taken_target not in insn_map:
            return False

        # Trace each side for a short straight-line window
        taken_trace = self._trace_straight_line(insn_map, taken_target, max_window)
        fall_trace = self._trace_straight_line(insn_map, fall_target, max_window)

        if not taken_trace or not fall_trace:
            return False

        # Check for a common merge point at the end of the traces
        taken_end = taken_trace[-1].address + taken_trace[-1].size
        fall_end = fall_trace[-1].address + fall_trace[-1].size
        if taken_end != fall_end:
            return False

        merge_pc = taken_end

        # Both sides reach the same merge point — execute inline
        import z3 as _z3

        taken_state = state.fork()
        taken_state.add_constraint(branch_constraint)
        for ti in taken_trace:
            self._apply_instruction(taken_state, ti)

        fall_state = state.fork()
        fall_state.add_constraint(_z3.Not(branch_constraint))
        for fi in fall_trace:
            self._apply_instruction(fall_state, fi)

        # Merge taken_state into fall_state (ITE phi-nodes)
        merged = fall_state.merge(taken_state)
        # Copy merged result back into the original state
        state.registers = merged.registers
        state.memory = merged.memory
        state.flags = merged.flags
        state.constraints = merged.constraints
        state.depth = merged.depth
        state._visited_pcs = merged._visited_pcs
        state._visit_counts = merged._visit_counts
        state.pc = merge_pc
        return True

    def _trace_straight_line(
        self,
        insn_map: Dict[int, LiftedInstruction],
        start_pc: int,
        max_len: int,
    ) -> List[LiftedInstruction]:
        """Collect up to *max_len* straight-line instructions from *start_pc*.

        Returns empty list if a branch is encountered (veritesting bail-out).
        """
        trace: List[LiftedInstruction] = []
        pc = start_pc
        for _ in range(max_len):
            insn = insn_map.get(pc)
            if insn is None:
                break
            if insn.is_branch or insn.category in (
                InstructionCategory.CALL,
                InstructionCategory.RETURN,
            ):
                # Branch in both: bail if it's the very first instruction
                if not trace:
                    return []
                trace.append(insn)
                return trace  # include the branch as last insn
            trace.append(insn)
            pc = insn.address + insn.size
        return trace

    # -- Loop analysis helpers (Batch 35) ------------------------------------

    def _record_loop_header(self, pc: int, state: SymbolicState) -> None:
        """Record *pc* as a loop header detected during exploration."""
        if pc not in self._detected_loops:
            self._detected_loops[pc] = LoopInfo(header_address=pc)
        info = self._detected_loops[pc]
        info.iteration_count = max(info.iteration_count, state.visit_count(pc))
        # Collect body addresses: everything visited since last visit to this header
        info.body_addresses.update(state.visited_addresses)

    def _widen_state(self, state: SymbolicState, loop_header: int) -> None:
        """Widen symbolic state at a loop header.

        Replaces registers that were written inside the loop body with
        fresh unconstrained symbols.  This is conservative — it loses
        precision but guarantees termination.
        """
        info = self._detected_loops.get(loop_header)
        if info is None:
            return

        widened_regs: List[str] = []
        bw = self.bit_width
        try:
            if Z3Solver.available():
                import z3 as _z3
                # Widen general-purpose registers (they may have been loop-modified)
                gp_regs = (
                    SymbolicState.X86_64_REGISTERS[:16]
                    if bw == 64
                    else SymbolicState.X86_32_REGISTERS[:8]
                )
                for reg in gp_regs:
                    old_val = state.registers.get(reg)
                    if old_val is not None and hasattr(old_val, "sexpr"):
                        # Only widen if the register holds a complex expression
                        expr_str = str(old_val)
                        if "+" in expr_str or "-" in expr_str or "*" in expr_str:
                            fresh = _z3.BitVec(
                                f"wide_{reg}_{loop_header:#x}",
                                bw,
                            )
                            state.registers[reg] = fresh
                            widened_regs.append(reg)
        except Exception:
            pass

        info.widened = True
        info.widened_registers = widened_regs
        logger.debug(
            "Widened %d registers at loop header %#x after %d iterations",
            len(widened_regs), loop_header, info.iteration_count,
        )

    @property
    def detected_loops(self) -> Dict[int, LoopInfo]:
        """Return loop headers detected during the most recent analysis."""
        return dict(self._detected_loops)

    # -- Path merging (B52) --------------------------------------------------

    def _try_merge_worklist(
        self,
        state: SymbolicState,
        worklist: Any,
    ) -> SymbolicState:
        """Merge *state* with any worklist entry sharing the same PC.

        If a mergeable partner is found, removes it from the worklist
        and returns the merged state.  Otherwise returns *state* as-is.

        At most one merge per pop to keep complexity manageable.
        """
        try:
            for i, candidate in enumerate(worklist):
                if candidate.pc == state.pc and not candidate.halted:
                    # Remove the partner from the worklist
                    del worklist[i]
                    # B54: re-heapify after removal (worklist may be a heapq list)
                    heapq.heapify(worklist)
                    merged = state.merge(candidate)
                    logger.debug(
                        "Merged two paths at PC %#x (depths %d + %d → %d)",
                        state.pc, state.depth, candidate.depth, merged.depth,
                    )
                    return merged
        except Exception:
            pass  # any merge failure → continue with original state
        return state

    # -- Instruction semantics engine ----------------------------------------

    def _apply_instruction(self, state: SymbolicState, insn: LiftedInstruction) -> None:
        """
        Apply the effect of *insn* to *state* — updating registers,
        memory, and potentially adding constraints.

        This is a simplified semantic model sufficient for VM handler
        classification; it covers mov, arithmetic, logic, stack, and
        memory operations.
        """
        mnemonic = insn.mnemonic
        ops = [o.strip() for o in insn.operands.split(",")]  if insn.operands else []

        try:
            if mnemonic == "mov" and len(ops) == 2:
                val = self._resolve_operand(state, ops[1])
                self._write_operand(state, ops[0], val)

            elif mnemonic in ("add", "sub", "adc", "sbb") and len(ops) == 2:
                left = self._resolve_operand(state, ops[0])
                right = self._resolve_operand(state, ops[1])
                if Z3Solver.available() and (hasattr(left, "sort") or hasattr(right, "sort")):
                    import z3 as _z3
                    left = self._ensure_bv(left, state.bit_width)
                    right = self._ensure_bv(right, state.bit_width)
                    result = (left + right) if mnemonic in ("add", "adc") else (left - right)
                else:
                    result = (left + right) if mnemonic in ("add", "adc") else (left - right)
                self._write_operand(state, ops[0], result)
                _opsz = self._infer_operand_bits(ops[0], state.bit_width)
                state.update_flags_arith(result, left, right, is_sub=mnemonic in ("sub", "sbb"), operand_size=_opsz)

            elif mnemonic in ("and", "or", "xor") and len(ops) == 2:
                left = self._resolve_operand(state, ops[0])
                right = self._resolve_operand(state, ops[1])
                if Z3Solver.available() and (hasattr(left, "sort") or hasattr(right, "sort")):
                    import z3 as _z3
                    left = self._ensure_bv(left, state.bit_width)
                    right = self._ensure_bv(right, state.bit_width)
                    if mnemonic == "and":
                        result = left & right
                    elif mnemonic == "or":
                        result = left | right
                    else:
                        result = left ^ right
                else:
                    if mnemonic == "and":
                        result = left & right
                    elif mnemonic == "or":
                        result = left | right
                    else:
                        result = left ^ right
                self._write_operand(state, ops[0], result)
                _opsz = self._infer_operand_bits(ops[0], state.bit_width)
                state.update_flags_logic(result, operand_size=_opsz)

            elif mnemonic in ("shl", "shr", "sar", "rol", "ror") and len(ops) == 2:
                val = self._resolve_operand(state, ops[0])
                amount = self._resolve_operand(state, ops[1])
                if Z3Solver.available() and hasattr(val, "sort"):
                    import z3 as _z3
                    amount = self._ensure_bv(amount, state.bit_width)
                    if mnemonic == "shl":
                        result = val << amount
                    elif mnemonic == "shr":
                        result = _z3.LShR(val, amount)
                    elif mnemonic == "sar":
                        result = val >> amount
                    else:
                        result = _z3.RotateLeft(val, amount) if mnemonic == "rol" else _z3.RotateRight(val, amount)
                else:
                    sa = amount if isinstance(amount, int) else 0
                    if mnemonic == "shl":
                        result = val << sa
                    elif mnemonic in ("shr", "sar"):
                        result = val >> sa
                    else:
                        result = val  # skip rotation in concrete mode
                self._write_operand(state, ops[0], result)

            elif mnemonic in ("inc", "dec") and len(ops) == 1:
                val = self._resolve_operand(state, ops[0])
                if Z3Solver.available() and hasattr(val, "sort"):
                    import z3 as _z3
                    one = _z3.BitVecVal(1, state.bit_width)
                    result = val + one if mnemonic == "inc" else val - one
                else:
                    result = (val + 1) if mnemonic == "inc" else (val - 1)
                self._write_operand(state, ops[0], result)
                # update_flags_inc_dec properly saves/restores CF
                _opsz = self._infer_operand_bits(ops[0], state.bit_width)
                state.update_flags_inc_dec(result, val, is_dec=(mnemonic == "dec"), operand_size=_opsz)

            elif mnemonic == "neg" and len(ops) == 1:
                val = self._resolve_operand(state, ops[0])
                if Z3Solver.available() and hasattr(val, "sort"):
                    result = -val
                else:
                    result = -val
                self._write_operand(state, ops[0], result)
                # NEG sets CF = (val != 0), updates ZF/SF/OF for 0 - val
                zero: Any = 0
                if Z3Solver.available() and hasattr(val, "sort"):
                    zero = __import__('z3').BitVecVal(0, state.bit_width)
                _opsz = self._infer_operand_bits(ops[0], state.bit_width)
                state.update_flags_arith(result, zero, val, is_sub=True, operand_size=_opsz)

            elif mnemonic == "not" and len(ops) == 1:
                val = self._resolve_operand(state, ops[0])
                if Z3Solver.available() and hasattr(val, "sort"):
                    result = ~val
                else:
                    result = ~val
                self._write_operand(state, ops[0], result)

            elif mnemonic == "push" and len(ops) == 1:
                val = self._resolve_operand(state, ops[0])
                sp_reg = "rsp" if state.bit_width == 64 else "esp"
                sp = state.get_register(sp_reg)
                word_size = state.bit_width // 8
                if isinstance(sp, int):
                    sp -= word_size
                    state.set_register(sp_reg, sp)
                    state.write_memory(sp, val, word_size)
                elif Z3Solver.available() and hasattr(sp, "sort"):
                    import z3 as _z3
                    dec = _z3.BitVecVal(word_size, state.bit_width)
                    new_sp = sp - dec
                    state.set_register(sp_reg, new_sp)
                    # Try to concretise the address for the memory write
                    try:
                        solver = _z3.Solver()
                        solver.add(*state.constraints)
                        if solver.check() == _z3.sat:
                            addr_val = solver.model().eval(new_sp, model_completion=True)
                            state.write_memory(addr_val.as_long(), val, word_size)
                        else:
                            state.write_memory(0, val, word_size)
                    except Exception:
                        state.write_memory(0, val, word_size)

            elif mnemonic == "pop" and len(ops) == 1:
                sp_reg = "rsp" if state.bit_width == 64 else "esp"
                sp = state.get_register(sp_reg)
                word_size = state.bit_width // 8
                if isinstance(sp, int):
                    val = state.read_memory(sp, word_size)
                    self._write_operand(state, ops[0], val)
                    sp += word_size
                    state.set_register(sp_reg, sp)
                elif Z3Solver.available() and hasattr(sp, "sort"):
                    import z3 as _z3
                    # Can't read from symbolic address — create fresh symbolic
                    val = _z3.BitVec(f"pop_{state.depth}", state.bit_width)
                    self._write_operand(state, ops[0], val)
                    inc = _z3.BitVecVal(word_size, state.bit_width)
                    state.set_register(sp_reg, sp + inc)

            elif mnemonic == "lea" and len(ops) == 2:
                # LEA computes effective address WITHOUT dereferencing
                addr = self._resolve_effective_address(state, ops[1])
                self._write_operand(state, ops[0], addr)

            elif mnemonic in ("movzx", "movsx", "movsxd") and len(ops) == 2:
                val = self._resolve_operand(state, ops[1])
                self._write_operand(state, ops[0], val)

            elif mnemonic in ("cmp", "test") and len(ops) == 2:
                # These only set flags, not destination.
                left = self._resolve_operand(state, ops[0])
                right = self._resolve_operand(state, ops[1])
                if Z3Solver.available() and (hasattr(left, "sort") or hasattr(right, "sort")):
                    left = self._ensure_bv(left, state.bit_width)
                    right = self._ensure_bv(right, state.bit_width)
                _opsz = self._infer_operand_bits(ops[0], state.bit_width)
                if mnemonic == "cmp":
                    diff = left - right if hasattr(left, '__sub__') else 0
                    state.update_flags_arith(diff, left, right, is_sub=True, operand_size=_opsz)
                else:  # test
                    anded = left & right if hasattr(left, '__and__') else 0
                    state.update_flags_logic(anded, operand_size=_opsz)
                # Legacy compat: keep _last_cmp for callers
                state._last_cmp = (mnemonic, left, right)

            elif mnemonic == "xchg" and len(ops) == 2:
                a = self._resolve_operand(state, ops[0])
                b = self._resolve_operand(state, ops[1])
                self._write_operand(state, ops[0], b)
                self._write_operand(state, ops[1], a)

            # ── IMUL (signed multiply) ──────────────────────────────
            elif mnemonic == "imul":
                if len(ops) == 1:
                    # One-operand: RDX:RAX = RAX * ops[0]
                    src = self._resolve_operand(state, ops[0])
                    ax_reg = "rax" if state.bit_width == 64 else "eax"
                    dx_reg = "rdx" if state.bit_width == 64 else "edx"
                    ax_val = state.get_register(ax_reg)
                    if Z3Solver.available() and (hasattr(ax_val, "sort") or hasattr(src, "sort")):
                        import z3 as _z3
                        a = self._ensure_bv(ax_val, state.bit_width)
                        b = self._ensure_bv(src, state.bit_width)
                        full = _z3.SignExt(state.bit_width, a) * _z3.SignExt(state.bit_width, b)
                        state.set_register(ax_reg, _z3.Extract(state.bit_width - 1, 0, full))
                        state.set_register(dx_reg, _z3.Extract(2 * state.bit_width - 1, state.bit_width, full))
                    else:
                        product = ax_val * src
                        mask = (1 << state.bit_width) - 1
                        state.set_register(ax_reg, product & mask)
                        state.set_register(dx_reg, (product >> state.bit_width) & mask)
                elif len(ops) == 2:
                    # Two-operand: dst *= src
                    dst_val = self._resolve_operand(state, ops[0])
                    src = self._resolve_operand(state, ops[1])
                    if Z3Solver.available() and (hasattr(dst_val, "sort") or hasattr(src, "sort")):
                        result = self._ensure_bv(dst_val, state.bit_width) * self._ensure_bv(src, state.bit_width)
                    else:
                        result = dst_val * src
                    self._write_operand(state, ops[0], result)
                elif len(ops) == 3:
                    # Three-operand: dst = src1 * imm
                    src = self._resolve_operand(state, ops[1])
                    imm = self._resolve_operand(state, ops[2])
                    if Z3Solver.available() and (hasattr(src, "sort") or hasattr(imm, "sort")):
                        result = self._ensure_bv(src, state.bit_width) * self._ensure_bv(imm, state.bit_width)
                    else:
                        result = src * imm
                    self._write_operand(state, ops[0], result)

            elif mnemonic == "mul" and len(ops) == 1:
                # Unsigned multiply: RDX:RAX = RAX * src
                src = self._resolve_operand(state, ops[0])
                ax_reg = "rax" if state.bit_width == 64 else "eax"
                dx_reg = "rdx" if state.bit_width == 64 else "edx"
                ax_val = state.get_register(ax_reg)
                if Z3Solver.available() and (hasattr(ax_val, "sort") or hasattr(src, "sort")):
                    import z3 as _z3
                    a = self._ensure_bv(ax_val, state.bit_width)
                    b = self._ensure_bv(src, state.bit_width)
                    full = _z3.ZeroExt(state.bit_width, a) * _z3.ZeroExt(state.bit_width, b)
                    state.set_register(ax_reg, _z3.Extract(state.bit_width - 1, 0, full))
                    state.set_register(dx_reg, _z3.Extract(2 * state.bit_width - 1, state.bit_width, full))
                else:
                    product = ax_val * src
                    mask = (1 << state.bit_width) - 1
                    state.set_register(ax_reg, product & mask)
                    state.set_register(dx_reg, (product >> state.bit_width) & mask)

            # ── DIV / IDIV ──────────────────────────────────────────
            elif mnemonic in ("div", "idiv") and len(ops) == 1:
                divisor = self._resolve_operand(state, ops[0])
                ax_reg = "rax" if state.bit_width == 64 else "eax"
                dx_reg = "rdx" if state.bit_width == 64 else "edx"
                ax_val = state.get_register(ax_reg)
                dx_val = state.get_register(dx_reg)
                if Z3Solver.available() and (
                    hasattr(ax_val, "sort") or hasattr(dx_val, "sort") or hasattr(divisor, "sort")
                ):
                    import z3 as _z3
                    bw = state.bit_width
                    hi = _z3.ZeroExt(bw, self._ensure_bv(dx_val, bw))
                    lo = _z3.ZeroExt(bw, self._ensure_bv(ax_val, bw))
                    dividend = (hi << bw) | lo
                    d = _z3.ZeroExt(bw, self._ensure_bv(divisor, bw))
                    if mnemonic == "div":
                        quot = _z3.Extract(bw - 1, 0, _z3.UDiv(dividend, d))
                        rem = _z3.Extract(bw - 1, 0, _z3.URem(dividend, d))
                    else:
                        quot = _z3.Extract(bw - 1, 0, dividend / d)
                        rem = _z3.Extract(bw - 1, 0, _z3.SRem(dividend, d))
                    state.set_register(ax_reg, quot)
                    state.set_register(dx_reg, rem)
                else:
                    if isinstance(divisor, int) and divisor != 0:
                        mask = (1 << state.bit_width) - 1
                        hi = (dx_val if isinstance(dx_val, int) else 0) & mask
                        lo = (ax_val if isinstance(ax_val, int) else 0) & mask
                        dividend = (hi << state.bit_width) | lo
                        state.set_register(ax_reg, (dividend // divisor) & mask)
                        state.set_register(dx_reg, (dividend % divisor) & mask)

            # ── CMOVcc (conditional move) ───────────────────────────
            elif mnemonic.startswith("cmov") and len(ops) == 2:
                cond = self._evaluate_condition(state, mnemonic[4:])
                src = self._resolve_operand(state, ops[1])
                if cond is True:
                    self._write_operand(state, ops[0], src)
                elif Z3Solver.available() and hasattr(cond, '__bool__') is False or (
                    hasattr(cond, 'sort') if Z3Solver.available() else False
                ):
                    # Symbolic condition → use z3 If
                    import z3 as _z3
                    dst = self._resolve_operand(state, ops[0])
                    dst_bv = self._ensure_bv(dst, state.bit_width)
                    src_bv = self._ensure_bv(src, state.bit_width)
                    result = _z3.If(cond, src_bv, dst_bv)
                    self._write_operand(state, ops[0], result)
                # else cond is False → no-op (destination unchanged)

            # ── SETcc (set byte on condition) ───────────────────────
            elif mnemonic.startswith("set") and len(ops) == 1:
                cc = mnemonic[3:]
                cond = self._evaluate_condition(state, cc)
                if Z3Solver.available() and hasattr(cond, 'sort'):
                    import z3 as _z3
                    result = _z3.If(cond, _z3.BitVecVal(1, state.bit_width),
                                    _z3.BitVecVal(0, state.bit_width))
                else:
                    result = 1 if cond else 0
                self._write_operand(state, ops[0], result)

            # ── BSWAP ──────────────────────────────────────────────
            elif mnemonic == "bswap" and len(ops) == 1:
                val = self._resolve_operand(state, ops[0])
                if Z3Solver.available() and hasattr(val, "sort"):
                    import z3 as _z3
                    bw = val.sort().size()
                    byte_count = bw // 8
                    bytes_list = [_z3.Extract(i * 8 + 7, i * 8, val)
                                  for i in range(byte_count)]
                    result = _z3.Concat(*bytes_list)  # reversed order
                    self._write_operand(state, ops[0], result)
                else:
                    result = int.from_bytes(
                        val.to_bytes(state.bit_width // 8, "little"), "big"
                    ) if isinstance(val, int) else val
                    self._write_operand(state, ops[0], result)

            # ── PUSHF / POPF (save/restore EFLAGS) ─────────────────
            elif mnemonic in ("pushf", "pushfq", "pushfd"):
                # Build a symbolic EFLAGS value from individual flags
                if Z3Solver.available():
                    import z3 as _z3
                    bw = state.bit_width
                    eflags = _z3.BitVecVal(0x202, bw)  # reserved bits
                    for bit_pos, flag in ((0, "CF"), (6, "ZF"), (7, "SF"), (11, "OF")):
                        fv = state.flags.get(flag, False)
                        if hasattr(fv, "sort"):
                            eflags = eflags | _z3.If(fv, _z3.BitVecVal(1 << bit_pos, bw),
                                                     _z3.BitVecVal(0, bw))
                        elif fv:
                            eflags = eflags | _z3.BitVecVal(1 << bit_pos, bw)
                else:
                    eflags = 0x202
                    for bit_pos, flag in ((0, "CF"), (6, "ZF"), (7, "SF"), (11, "OF")):
                        if state.flags.get(flag, False):
                            eflags |= (1 << bit_pos)
                # Push EFLAGS onto stack
                sp_reg = "rsp" if state.bit_width == 64 else "esp"
                sp = state.get_register(sp_reg)
                word_size = state.bit_width // 8
                if isinstance(sp, int):
                    sp -= word_size
                    state.set_register(sp_reg, sp)
                    state.write_memory(sp, eflags, word_size)

            elif mnemonic in ("popf", "popfq", "popfd"):
                # Pop EFLAGS from stack and restore individual flags
                sp_reg = "rsp" if state.bit_width == 64 else "esp"
                sp = state.get_register(sp_reg)
                word_size = state.bit_width // 8
                if isinstance(sp, int):
                    eflags = state.read_memory(sp, word_size)
                    state.set_register(sp_reg, sp + word_size)
                    # Try to concretize z3 constants so flags stay plain bool
                    if Z3Solver.available() and hasattr(eflags, "sort"):
                        import z3 as _z3
                        try:
                            val = _z3.simplify(eflags)
                            if val.as_long is not None:
                                eflags = val.as_long()
                        except Exception:
                            pass
                    if Z3Solver.available() and hasattr(eflags, "sort"):
                        import z3 as _z3
                        one = _z3.BitVecVal(1, 1)
                        state.flags["CF"] = _z3.Extract(0, 0, eflags) == one
                        state.flags["ZF"] = _z3.Extract(6, 6, eflags) == one
                        state.flags["SF"] = _z3.Extract(7, 7, eflags) == one
                        state.flags["OF"] = _z3.Extract(11, 11, eflags) == one
                    elif isinstance(eflags, int):
                        state.flags["CF"] = bool(eflags & 1)
                        state.flags["ZF"] = bool(eflags & (1 << 6))
                        state.flags["SF"] = bool(eflags & (1 << 7))
                        state.flags["OF"] = bool(eflags & (1 << 11))

            # ── CDQ / CWD / CDQE / CWDE (sign-extend) ─────────────
            elif mnemonic == "cdq":
                # CDQ: sign-extend EAX (32-bit) into EDX:EAX
                eax_val = state.get_register("eax")  # lower 32 bits of rax
                dx_reg = "rdx" if state.bit_width == 64 else "edx"
                if Z3Solver.available() and hasattr(eax_val, "sort"):
                    import z3 as _z3
                    bw = eax_val.sort().size()
                    sign = _z3.Extract(31, 31, self._ensure_bv(eax_val, 32)) if bw >= 32 else _z3.Extract(bw - 1, bw - 1, eax_val)
                    allones = _z3.BitVecVal((1 << state.bit_width) - 1, state.bit_width)
                    zero = _z3.BitVecVal(0, state.bit_width)
                    state.set_register(dx_reg, _z3.If(sign == _z3.BitVecVal(1, 1), allones, zero))
                else:
                    eax = eax_val if isinstance(eax_val, int) else 0
                    sign = (eax >> 31) & 1
                    mask = (1 << state.bit_width) - 1
                    state.set_register(dx_reg, mask if sign else 0)

            elif mnemonic == "cqo":
                # CQO: sign-extend RAX (64-bit) into RDX:RAX
                ax_val = state.get_register("rax")
                if Z3Solver.available() and hasattr(ax_val, "sort"):
                    import z3 as _z3
                    sign = _z3.Extract(63, 63, self._ensure_bv(ax_val, 64))
                    allones = _z3.BitVecVal((1 << 64) - 1, 64)
                    zero = _z3.BitVecVal(0, 64)
                    state.set_register("rdx", _z3.If(sign == _z3.BitVecVal(1, 1), allones, zero))
                else:
                    ax_int = ax_val if isinstance(ax_val, int) else 0
                    sign = (ax_int >> 63) & 1
                    mask = (1 << 64) - 1
                    state.set_register("rdx", mask if sign else 0)

            elif mnemonic == "cdqe":
                # Sign-extend EAX into RAX (64-bit mode)
                if state.bit_width == 64:
                    eax_val = state.get_register("eax")
                    if Z3Solver.available() and hasattr(eax_val, "sort"):
                        import z3 as _z3
                        if eax_val.sort().size() == 32:
                            state.set_register("rax", _z3.SignExt(32, eax_val))
                        else:
                            state.set_register("rax", _z3.SignExt(32, _z3.Extract(31, 0, eax_val)))
                    elif isinstance(eax_val, int):
                        if eax_val & 0x80000000:
                            state.set_register("rax", eax_val | 0xFFFFFFFF00000000)
                        else:
                            state.set_register("rax", eax_val & 0xFFFFFFFF)

            elif mnemonic in ("cwde", "cwd"):
                if mnemonic == "cwde":
                    # Sign-extend AX into EAX
                    ax_val = state.get_register("ax") if "ax" in state.registers else state.get_register("eax")
                    if isinstance(ax_val, int):
                        if ax_val & 0x8000:
                            state.set_register("eax", ax_val | 0xFFFF0000)
                        else:
                            state.set_register("eax", ax_val & 0xFFFF)
                else:
                    # CWD: sign-extend AX into DX:AX
                    ax_val = state.get_register("ax") if "ax" in state.registers else state.get_register("eax")
                    if isinstance(ax_val, int):
                        state.set_register("edx" if state.bit_width == 32 else "rdx",
                                           0xFFFF if ax_val & 0x8000 else 0)

            # ── BT / BTS / BTR / BTC (bit test) ───────────────────
            elif mnemonic in ("bt", "bts", "btr", "btc") and len(ops) == 2:
                base = self._resolve_operand(state, ops[0])
                bit_pos = self._resolve_operand(state, ops[1])
                if Z3Solver.available() and (hasattr(base, "sort") or hasattr(bit_pos, "sort")):
                    import z3 as _z3
                    base_bv = self._ensure_bv(base, state.bit_width)
                    pos_bv = self._ensure_bv(bit_pos, state.bit_width)
                    tested = _z3.LShR(base_bv, pos_bv) & _z3.BitVecVal(1, state.bit_width)
                    state.flags["CF"] = tested == _z3.BitVecVal(1, state.bit_width)
                    if mnemonic == "bts":
                        self._write_operand(state, ops[0], base_bv | (_z3.BitVecVal(1, state.bit_width) << pos_bv))
                    elif mnemonic == "btr":
                        self._write_operand(state, ops[0], base_bv & ~(_z3.BitVecVal(1, state.bit_width) << pos_bv))
                    elif mnemonic == "btc":
                        self._write_operand(state, ops[0], base_bv ^ (_z3.BitVecVal(1, state.bit_width) << pos_bv))
                else:
                    b = base if isinstance(base, int) else 0
                    p = bit_pos if isinstance(bit_pos, int) else 0
                    state.flags["CF"] = bool((b >> p) & 1)
                    if mnemonic == "bts":
                        self._write_operand(state, ops[0], b | (1 << p))
                    elif mnemonic == "btr":
                        self._write_operand(state, ops[0], b & ~(1 << p))
                    elif mnemonic == "btc":
                        self._write_operand(state, ops[0], b ^ (1 << p))

            # ── NOP / ENDBR / PAUSE (no-ops) ──────────────────────
            elif mnemonic in ("nop", "endbr32", "endbr64", "pause",
                              "fnop", "fwait", "mfence", "lfence",
                              "sfence", "ud2"):
                pass  # no-op

            # ── CALL (model as push return address) ────────────────
            elif mnemonic == "call" and len(ops) == 1:
                sp_reg = "rsp" if state.bit_width == 64 else "esp"
                sp = state.get_register(sp_reg)
                word_size = state.bit_width // 8
                return_addr = insn.address + insn.size if hasattr(insn, 'size') else insn.address + 5
                if isinstance(sp, int):
                    sp -= word_size
                    state.set_register(sp_reg, sp)
                    state.write_memory(sp, return_addr, word_size)

            # ── RET (model as pop into PC) ─────────────────────────
            elif mnemonic in ("ret", "retn"):
                sp_reg = "rsp" if state.bit_width == 64 else "esp"
                sp = state.get_register(sp_reg)
                word_size = state.bit_width // 8
                if isinstance(sp, int):
                    ret_addr = state.read_memory(sp, word_size)
                    state.set_register(sp_reg, sp + word_size)
                    if isinstance(ret_addr, int):
                        state.pc = ret_addr

        except Exception as exc:
            # Non-fatal: log for debugging, but continue execution
            logger.debug("Could not model '%s %s': %s", mnemonic, insn.operands, exc)

    # ---- SIB address resolver ----
    _SIB_RE = None  # lazily compiled

    @classmethod
    def _sib_regex(cls):
        """Return compiled regex for SIB-style memory operands.

        Matches patterns like:
          reg, reg+disp, reg-disp, reg+reg*scale+disp, reg+reg*scale,
          reg+reg+disp, reg+reg, disp (absolute), etc.
        """
        if cls._SIB_RE is None:
            import re
            # Tokenize into identifiers, hex/dec numbers, +, -, *
            cls._SIB_RE = re.compile(
                r"([A-Za-z_]\w*|0[xX][0-9A-Fa-f]+|\d+|[+\-*])"
            )
        return cls._SIB_RE

    def _resolve_sib_address(self, state: SymbolicState, inner: str) -> Any:
        """Parse a general SIB-form address expression and compute the address.

        Handles: ``base``, ``base+disp``, ``base-disp``,
        ``base+index*scale``, ``base+index*scale+disp``,
        ``base+index*scale-disp``, ``base+index+disp``, and absolute ``disp``.
        Returns an *int* or a *z3.BitVec* expression.
        """
        tokens = self._sib_regex().findall(inner.strip())
        if not tokens:
            return 0

        # Classify tokens into additive terms.  Each term is (value, negate).
        # Multiplication binds tighter: if we see A * B, combine immediately.
        terms: list[tuple[Any, bool]] = []
        pending_negate = False
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok == "+":
                i += 1
                continue
            if tok == "-":
                pending_negate = not pending_negate
                i += 1
                continue

            # Resolve token value
            val = self._tok_value(state, tok)

            # Look ahead for '*'
            if i + 2 < len(tokens) and tokens[i + 1] == "*":
                scale_val = self._tok_value(state, tokens[i + 2])
                val = self._mul(val, scale_val, state.bit_width)
                i += 3
            else:
                i += 1

            terms.append((val, pending_negate))
            pending_negate = False

        if not terms:
            return 0

        # Sum all terms
        result = terms[0][0] if not terms[0][1] else self._negate(terms[0][0], state.bit_width)
        for val, neg in terms[1:]:
            if neg:
                result = self._sub(result, val, state.bit_width)
            else:
                result = self._add(result, val, state.bit_width)
        return result

    # ---- helpers for SIB arithmetic ----

    def _tok_value(self, state: SymbolicState, tok: str) -> Any:
        """Return the value of a single token (register name or number)."""
        low = tok.lower()
        if low in state.registers or state._subreg_info(low) is not None:
            return state.get_register(low)
        try:
            return int(tok, 0)
        except ValueError:
            return 0

    @staticmethod
    def _mul(a: Any, b: Any, bw: int) -> Any:
        a_sym = hasattr(a, "sort")
        b_sym = hasattr(b, "sort")
        if a_sym or b_sym:
            if Z3Solver.available():
                import z3 as _z3
                if not a_sym:
                    a = _z3.BitVecVal(a, bw)
                if not b_sym:
                    b = _z3.BitVecVal(b, bw)
                return a * b
        return (a if isinstance(a, int) else 0) * (b if isinstance(b, int) else 0)

    @staticmethod
    def _add(a: Any, b: Any, bw: int) -> Any:
        a_sym = hasattr(a, "sort")
        b_sym = hasattr(b, "sort")
        if a_sym or b_sym:
            if Z3Solver.available():
                import z3 as _z3
                if not a_sym:
                    a = _z3.BitVecVal(a, bw)
                if not b_sym:
                    b = _z3.BitVecVal(b, bw)
                return a + b
        return (a if isinstance(a, int) else 0) + (b if isinstance(b, int) else 0)

    @staticmethod
    def _sub(a: Any, b: Any, bw: int) -> Any:
        a_sym = hasattr(a, "sort")
        b_sym = hasattr(b, "sort")
        if a_sym or b_sym:
            if Z3Solver.available():
                import z3 as _z3
                if not a_sym:
                    a = _z3.BitVecVal(a, bw)
                if not b_sym:
                    b = _z3.BitVecVal(b, bw)
                return a - b
        return (a if isinstance(a, int) else 0) - (b if isinstance(b, int) else 0)

    @staticmethod
    def _negate(v: Any, bw: int) -> Any:
        if hasattr(v, "sort"):
            if Z3Solver.available():
                import z3 as _z3
                return -v
        return -(v if isinstance(v, int) else 0)

    # -- Operand-size inference -----------------------------------------------

    _REG_WIDTH: dict[str, int] = {}  # lazily populated

    @staticmethod
    def _infer_operand_bits(operand: str, default: int = 0) -> int:
        """Return the effective bit-width implied by *operand*.

        Recognises register names (``al`` → 8, ``ax`` → 16, ``eax`` → 32,
        ``rax`` → 64), size-prefix keywords (``byte ptr`` → 8 …), and
        returns *default* when the width cannot be determined.
        """
        op = operand.strip().lower()
        # Size-prefix keywords
        if op.startswith("byte ptr "):
            return 8
        if op.startswith("word ptr "):
            return 16
        if op.startswith("dword ptr "):
            return 32
        if op.startswith("qword ptr "):
            return 64
        # Register names
        # 8-bit
        if op in ("al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
                   "sil", "dil", "bpl", "spl",
                   "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"):
            return 8
        # 16-bit
        if op in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
                   "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"):
            return 16
        # 32-bit
        if op in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
                   "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"):
            return 32
        # 64-bit
        if op in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                   "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                   "rip"):
            return 64
        return default

    def _resolve_effective_address(self, state: SymbolicState, operand: str) -> Any:
        """Compute an effective address WITHOUT dereferencing memory.

        Used for LEA instructions: ``lea rax, [rbx+8]`` → computes
        ``rbx + 8`` and returns the *address*, not the value *at* the address.
        """
        operand = operand.strip()

        # Strip size prefixes
        for prefix in ("byte ptr ", "word ptr ", "dword ptr ", "qword ptr "):
            if operand.lower().startswith(prefix):
                operand = operand[len(prefix):]
                break

        if operand.startswith("[") and operand.endswith("]"):
            return self._resolve_sib_address(state, operand[1:-1].strip())

        # Fallback to _resolve_operand for non-memory operands
        return self._resolve_operand(state, operand)

    def _resolve_operand(self, state: SymbolicState, operand: str) -> Any:
        """Resolve an operand to a symbolic or concrete value."""
        operand = operand.strip()

        # Size prefixed operands (e.g., "dword ptr [rax]")
        _PREFIX_SIZES = {
            "byte ptr ": 1, "word ptr ": 2, "dword ptr ": 4, "qword ptr ": 8,
        }
        for prefix, sz in _PREFIX_SIZES.items():
            if operand.lower().startswith(prefix):
                return self._resolve_operand_sized(state, operand[len(prefix):], sz)

        # Register? (includes sub-registers via state.get_register)
        reg = operand.lower()
        if reg in state.registers or state._subreg_info(reg) is not None:
            return state.get_register(reg)

        # Immediate / hex constant?
        try:
            if operand.startswith("0x") or operand.startswith("-0x"):
                return int(operand, 16)
            if operand.lstrip("-").isdigit():
                return int(operand)
        except ValueError:
            pass

        # Memory dereference like [rax], [rsp+0x8], [rax+rbx*4+0x10], etc.
        if operand.startswith("[") and operand.endswith("]"):
            addr = self._resolve_sib_address(state, operand[1:-1].strip())
            # Use state.read_memory for BOTH concrete and symbolic
            # addresses — it handles store-forwarding, region naming,
            # and access logging internally.
            return state.read_memory(addr)

        return 0  # fallback

    def _resolve_operand_sized(self, state: SymbolicState, operand: str, size: int) -> Any:
        """Like _resolve_operand, but memory reads use an explicit byte *size*."""
        operand = operand.strip()
        reg = operand.lower()
        if reg in state.registers or state._subreg_info(reg) is not None:
            return state.get_register(reg)
        try:
            if operand.startswith("0x") or operand.startswith("-0x"):
                return int(operand, 16)
            if operand.lstrip("-").isdigit():
                return int(operand)
        except ValueError:
            pass
        if operand.startswith("[") and operand.endswith("]"):
            addr = self._resolve_sib_address(state, operand[1:-1].strip())
            # Route ALL addresses (concrete + symbolic) through
            # state.read_memory which handles forwarding and logging.
            return state.read_memory(addr, size)
        return self._resolve_operand(state, operand)

    def _write_operand(self, state: SymbolicState, operand: str, value: Any) -> None:
        """Write a value to the destination operand."""
        operand = operand.strip()

        # Size prefixed operands
        for prefix in ("byte ptr ", "word ptr ", "dword ptr ", "qword ptr "):
            if operand.lower().startswith(prefix):
                self._write_operand(state, operand[len(prefix):], value)
                return

        reg = operand.lower()
        if reg in state.registers or state._subreg_info(reg) is not None:
            state.set_register(reg, value)
            return

        # Memory dereference — route through state.write_memory for
        # both concrete and symbolic addresses (symbolic writes go
        # into the symbolic store for forwarding).
        if operand.startswith("[") and operand.endswith("]"):
            addr = self._resolve_sib_address(state, operand[1:-1].strip())
            state.write_memory(addr, value)
            return

    @staticmethod
    def _ensure_bv(val: Any, bit_width: int) -> Any:
        """Ensure *val* is a z3 BitVec of the correct width."""
        if hasattr(val, "sort"):
            return val
        import z3 as _z3
        return _z3.BitVecVal(int(val), bit_width)

    # -- Handler-local symbolic execution ------------------------------------

    def execute_handler(
        self,
        handler_bytes: bytes,
        handler_address: int = 0,
    ) -> HandlerSymbolicSummary:
        """Run symbolic execution over a single handler's instruction slice.

        Creates a fresh symbolic state, lifts the handler bytes, steps
        through each instruction collecting symbolic register effects,
        memory accesses, and constraints, then simplifies via
        :func:`~dragonslayer.analysis.mba_simplifier.simplify_expr`.

        Returns a :class:`HandlerSymbolicSummary` with the register map
        (symbolic expressions), memory writes, path constraints, and
        any MBA-simplified sub-expressions.

        The state is configured with named memory regions:

        * **stack** — rooted at a concrete SP so push/pop work correctly.
        * **vm_context** — a symbolic region for the VM's virtual
          register file, enabling loads/stores like ``[rbp+rcx*8]`` to
          produce structured symbolic names (e.g. ``vm_context_load_1``)
          rather than disconnected fresh variables.
        """
        instructions = self._lifter.lift(handler_bytes, base_address=handler_address)
        if not instructions:
            return HandlerSymbolicSummary(address=handler_address, error="no instructions lifted")

        state = SymbolicState(
            arch=self.arch,
            bit_width=self.bit_width,
            initial_pc=handler_address,
        )

        # Make input registers symbolic so we can track data-flow.
        import z3 as _z3
        sym_regs: Dict[str, _z3.BitVecRef] = {}

        # Initialise the stack pointer to a concrete address so that
        # push / pop can actually read / write concrete memory locations.
        _STACK_BASE = 0x7FFF_0000 if self.bit_width == 64 else 0x00FF_0000
        sp_reg = "rsp" if self.bit_width == 64 else "esp"
        state.set_register(sp_reg, _STACK_BASE)

        # Map named memory regions for structured symbolic summaries.
        # Stack region: concrete base, 64 KiB size.
        state.map_region("stack", _STACK_BASE - 0x10000, size=0x10000)

        # VM context region: symbolic base — VMProtect (and similar)
        # use a register like RBP/RSI as vm_context pointer.  We
        # create a symbolic base so that accesses like [rbp+rcx*8]
        # are attributed to the vm_context region.
        _ctx_base = _z3.BitVec("vm_context_base", self.bit_width)
        state.map_region("vm_context", _ctx_base, size=0)

        for rname in state.registers:
            if rname == sp_reg:
                continue
            sym = _z3.BitVec(f"in_{rname}", self.bit_width)
            state.set_register(rname, sym)
            sym_regs[rname] = sym

        insn_map = {i.address: i for i in instructions}
        mem_writes: List[Dict[str, Any]] = []
        stepped = 0

        for insn in instructions:
            if state.halted:
                break
            state.visit(state.pc)
            self._apply_instruction(state, insn)
            stepped += 1

            # Record memory writes produced by this instruction.
            if insn.mnemonic in ("mov", "push") and insn.operands:
                ops = [o.strip() for o in insn.operands.split(",")]
                if len(ops) >= 1 and "[" in ops[0]:
                    mem_writes.append({
                        "insn_address": insn.address,
                        "mnemonic": insn.mnemonic,
                        "destination": ops[0],
                    })

            if insn.category == InstructionCategory.RETURN:
                state.halt("return")
                break

        # Collect final symbolic values per register.
        final_regs: Dict[str, str] = {}
        simplified_regs: Dict[str, str] = {}
        for rname in state.registers:
            val = state.get_register(rname)
            final_regs[rname] = str(val)
            if hasattr(val, "sort"):
                try:
                    from ..mba_simplifier import simplify_expr as _mba_simplify
                    s_expr, rule = _mba_simplify(val, self.bit_width)
                    if rule is not None:
                        simplified_regs[rname] = str(s_expr)
                except Exception:
                    pass

        # Collect path constraints.
        constraints = [str(c) for c in state.constraints]

        # Collect structured memory effects (read/write with region annotations).
        memory_effects = state.summarize_memory_effects()

        summary = HandlerSymbolicSummary(
            address=handler_address,
            instruction_count=stepped,
            final_registers=final_regs,
            simplified_registers=simplified_regs,
            memory_writes=mem_writes,
            constraints=constraints,
            input_symbols={rname: str(sym) for rname, sym in sym_regs.items()},
        )
        # Attach memory effects as extra attribute for downstream consumers.
        summary.memory_effects = memory_effects  # type: ignore[attr-defined]
        return summary

    def execute_handler_from_trace(
        self,
        trace_instructions: List[Dict[str, Any]],
        handler_address: int = 0,
    ) -> HandlerSymbolicSummary:
        """Run handler-local symbolic execution from trace instruction dicts.

        Each dict in *trace_instructions* should contain at least
        ``raw_bytes`` (hex string) and ``address``.  The raw bytes are
        concatenated and fed to :meth:`execute_handler`.
        """
        code = b""
        base = handler_address
        for i, rec in enumerate(trace_instructions):
            raw = rec.get("raw_bytes", "")
            if raw:
                code += bytes.fromhex(raw)
            if i == 0 and rec.get("address"):
                base = rec["address"]
        if not code:
            return HandlerSymbolicSummary(address=handler_address, error="no code bytes")
        return self.execute_handler(code, base)

    def _evaluate_condition(self, state: SymbolicState, cc: str) -> Any:
        """Evaluate an x86 condition-code suffix against *state.flags*.

        Returns a z3 BoolRef (symbolic) or plain ``bool`` (concrete) that
        is ``True`` when the condition is satisfied.  This is shared by
        ``cmovCC``, ``setCC``, and ``jCC`` instruction handlers.
        """
        zf = state.flags.get("ZF")
        cf = state.flags.get("CF")
        sf = state.flags.get("SF")
        of = state.flags.get("OF")

        # Decide whether we need z3 mode: at least one flag is a z3 expression
        _symbolic = (
            Z3Solver.available()
            and any(hasattr(v, "sort") or hasattr(v, "sexpr") for v in (zf, cf, sf, of) if v is not None)
        )

        if _symbolic:
            import z3 as _z3

            def _to_bv(v: Any) -> Any:
                if isinstance(v, bool):
                    return _z3.BoolVal(v)
                if v is None:
                    return _z3.BoolVal(False)
                return v

            zf, cf, sf, of = _to_bv(zf), _to_bv(cf), _to_bv(sf), _to_bv(of)

        cc = cc.lower()
        # Canonical condition-code mapping
        if cc in ("e", "z"):
            return zf
        elif cc in ("ne", "nz"):
            if _symbolic:
                return _z3.Not(zf)
            return not zf
        elif cc in ("g", "nle"):
            if _symbolic:
                return _z3.And(_z3.Not(zf), sf == of)
            return (not zf) and (sf == of)
        elif cc in ("ge", "nl"):
            if _symbolic:
                return sf == of
            return sf == of
        elif cc in ("l", "nge"):
            if _symbolic:
                return sf != of
            return sf != of
        elif cc in ("le", "ng"):
            if _symbolic:
                return _z3.Or(zf, sf != of)
            return zf or (sf != of)
        elif cc in ("a", "nbe"):
            if _symbolic:
                return _z3.And(_z3.Not(cf), _z3.Not(zf))
            return (not cf) and (not zf)
        elif cc in ("ae", "nb", "nc"):
            if _symbolic:
                return _z3.Not(cf)
            return not cf
        elif cc in ("b", "nae", "c"):
            return cf
        elif cc in ("be", "na"):
            if _symbolic:
                return _z3.Or(cf, zf)
            return cf or zf
        elif cc == "s":
            return sf
        elif cc == "ns":
            if _symbolic:
                return _z3.Not(sf)
            return not sf
        elif cc == "o":
            return of
        elif cc == "no":
            if _symbolic:
                return _z3.Not(of)
            return not of
        elif cc == "p" or cc == "pe":
            return False
        elif cc == "np" or cc == "po":
            return True
        return False

    def _build_branch_constraint(self, state: SymbolicState, insn: LiftedInstruction) -> Any:
        """Build a z3 constraint for a conditional branch using state.flags.

        Uses the explicit ZF/CF/SF/OF flag model rather than stashed
        ``_last_cmp`` operands, so intervening instructions between the
        flag-setting instruction and the branch are handled correctly.
        """
        if not Z3Solver.available():
            return None

        mn = insn.mnemonic
        # Strip 'j' prefix to get condition-code suffix
        if mn.startswith("j"):
            cc = mn[1:]
            result = self._evaluate_condition(state, cc)
            if result is False:
                import z3 as _z3
                return _z3.BoolVal(False)
            if result is True:
                import z3 as _z3
                return _z3.BoolVal(True)
            return result

    # -- B45: Indirect dispatch resolution -----------------------------------

    def _resolve_indirect_branch(
        self,
        state: SymbolicState,
        insn: LiftedInstruction,
        max_targets: int = 256,
    ) -> List[int]:
        """Resolve an indirect jump/call to concrete target addresses via Z3.

        For VMProtect-style dispatch (``jmp [table + rax*8]``), the
        jump target is a symbolic expression over registers constrained
        by the prior path.  This method uses :meth:`Z3Solver.enumerate_values`
        to find *all* distinct concrete addresses the branch may reach.

        Parameters
        ----------
        state : SymbolicState
            Current executor state (with accumulated path constraints).
        insn : LiftedInstruction
            The indirect branch instruction.
        max_targets : int
            Upper bound on target enumeration (default 256).

        Returns
        -------
        list of int
            Sorted list of possible concrete target addresses.  Empty
            if the target cannot be resolved.
        """
        if not Z3Solver.available():
            return []

        # Determine the symbolic target expression.
        target_expr = self._extract_branch_target_expr(state, insn)
        if target_expr is None:
            return []

        # Enumerate all concrete values under accumulated path constraints.
        return self._solver.enumerate_values(
            target_expr,
            constraints=list(state.constraints),
            max_values=max_targets,
        )

    def _extract_branch_target_expr(
        self,
        state: SymbolicState,
        insn: LiftedInstruction,
    ) -> Any:
        """Extract the symbolic expression for an indirect jump target.

        Handles ``jmp reg``, ``jmp [mem]``, ``call reg``, ``call [mem]``
        by resolving the operand through the current state.
        """
        operands = insn.operands.strip()
        if not operands:
            return None

        try:
            # Memory-indirect jump: ``jmp [rax + rbx*8 + 0x10]``
            if "[" in operands:
                return self._resolve_effective_address(state, operands)
            # Register-indirect jump: ``jmp rax``
            val = state.get_register(operands)
            if val is not None:
                return val
        except Exception:
            pass
        return None
