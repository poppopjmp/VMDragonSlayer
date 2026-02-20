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
from collections import deque
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

        Enhanced: uses z3 solver to prove whether conditions are trivially
        satisfiable/unsatisfiable beyond simple `cmp reg, reg`.
        """
        if not Z3Solver.available():
            return []

        import z3 as _z3

        opaque: List[Dict[str, Any]] = []

        prev_insn: Optional[LiftedInstruction] = None
        for insn in instructions:
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
                            # test reg, reg — ZF=1 iff reg==0 (NOT opaque)
                            opaque.append({
                                "address": insn.address,
                                "comparison_address": prev_insn.address,
                                "comparison": f"{prev_insn.mnemonic} {prev_insn.operands}",
                                "branch": f"{insn.mnemonic} {insn.operands}",
                                "always_true": None,  # depends on register value
                                "confidence": 0.5,
                            })
                        else:
                            # cmp reg, reg — SUB always yields zero → ZF always 1
                            opaque.append({
                                "address": insn.address,
                                "comparison_address": prev_insn.address,
                                "comparison": f"{prev_insn.mnemonic} {prev_insn.operands}",
                                "branch": f"{insn.mnemonic} {insn.operands}",
                                "always_true": insn.mnemonic in ("je", "jz", "jle", "jge", "jbe", "jae"),
                                "confidence": 0.99,
                            })
                    else:
                        # Case 3: cmp with constant — check if always true/false
                        # e.g. cmp eax, 0 followed by jge  (always true if unsigned)
                        try:
                            imm = int(ops[1], 0) if ops[1].startswith("0x") else int(ops[1]) if ops[1].lstrip("-").isdigit() else None
                        except ValueError:
                            imm = None

                        if imm is not None:
                            x = _z3.BitVec("opaque_x", self.bit_width)
                            const = _z3.BitVecVal(imm, self.bit_width)

                            # Build the branch condition
                            mn = insn.mnemonic
                            if mn in ("je", "jz"):
                                cond = x == const
                            elif mn in ("jne", "jnz"):
                                cond = x != const
                            elif mn == "jg":
                                cond = x > const
                            elif mn == "jge":
                                cond = x >= const
                            elif mn == "jl":
                                cond = x < const
                            elif mn == "jle":
                                cond = x <= const
                            elif mn == "ja":
                                cond = _z3.UGT(x, const)
                            elif mn == "jae":
                                cond = _z3.UGE(x, const)
                            elif mn == "jb":
                                cond = _z3.ULT(x, const)
                            elif mn == "jbe":
                                cond = _z3.ULE(x, const)
                            else:
                                cond = None

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
                                    })

            prev_insn = insn

        return opaque

    # -- Path exploration with instruction semantics --------------------------

    def _explore_paths(
        self,
        insn_map: Dict[int, LiftedInstruction],
        entry_point: int,
    ) -> tuple[int, int, List[Dict[str, Any]]]:
        """
        BFS path exploration with real symbolic state updates.

        For each instruction, updates registers, memory, and constraints
        on the :class:`SymbolicState` so downstream consumers (taint,
        handler classification) see meaningful values.

        Returns (paths_explored, total_instructions_executed, state_snapshots).
        """
        if not insn_map:
            return 0, 0, []

        initial_state = SymbolicState(
            arch=self.arch,
            bit_width=self.bit_width,
            initial_pc=entry_point,
        )

        worklist: deque[SymbolicState] = deque([initial_state])
        paths = 0
        total_insns = 0
        snapshots: List[Dict[str, Any]] = []

        while worklist and paths < self.max_paths:
            state = worklist.popleft()
            path_len = 0

            while not state.halted and path_len < self.max_depth:
                insn = insn_map.get(state.pc)
                if insn is None:
                    state.halt("address not in map")
                    break

                state.visit(state.pc)
                total_insns += 1
                path_len += 1

                # === Apply instruction semantics to state ===
                self._apply_instruction(state, insn)

                if insn.category == InstructionCategory.RETURN:
                    state.halt("return")
                    break

                if insn.is_branch:
                    if insn.category == InstructionCategory.BRANCH_COND and insn.branch_target:
                        # Build branch constraint if z3 available
                        branch_constraint = self._build_branch_constraint(state, insn)

                        if len(worklist) < self.max_paths:
                            taken = state.fork()
                            taken.pc = insn.branch_target
                            if branch_constraint is not None:
                                taken.add_constraint(branch_constraint)
                            worklist.append(taken)

                        # Fall-through with negated constraint
                        next_addr = insn.address + insn.size
                        if next_addr in insn_map:
                            state.pc = next_addr
                            if branch_constraint is not None and Z3Solver.available():
                                import z3 as _z3
                                state.add_constraint(_z3.Not(branch_constraint))
                        else:
                            state.halt("fall-through not in map")
                            break
                    elif insn.branch_target is not None:
                        state.pc = insn.branch_target
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

            elif mnemonic == "neg" and len(ops) == 1:
                val = self._resolve_operand(state, ops[0])
                if Z3Solver.available() and hasattr(val, "sort"):
                    result = -val
                else:
                    result = -val
                self._write_operand(state, ops[0], result)

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
                    sp = sp - dec
                    state.set_register(sp_reg, sp)
                    # Write to symbolic address — store in memory log
                    state.write_memory(0, val, word_size)  # best-effort

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
                # Store comparison info for branch constraint building.
                left = self._resolve_operand(state, ops[0])
                right = self._resolve_operand(state, ops[1])
                state._last_cmp = (mnemonic, left, right)

            elif mnemonic == "xchg" and len(ops) == 2:
                a = self._resolve_operand(state, ops[0])
                b = self._resolve_operand(state, ops[1])
                self._write_operand(state, ops[0], b)
                self._write_operand(state, ops[1], a)

        except Exception as exc:
            # Non-fatal: log for debugging, but continue execution
            logger.debug("Could not model '%s %s': %s", mnemonic, insn.operands, exc)

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
            inner = operand[1:-1].strip()
            for sep in ("+", "-"):
                if sep in inner:
                    parts = inner.split(sep, 1)
                    base_reg = parts[0].strip().lower()
                    if base_reg in state.registers:
                        base_val = state.get_register(base_reg)
                        try:
                            offset_val = int(parts[1].strip(), 0)
                            if sep == "-":
                                offset_val = -offset_val
                        except ValueError:
                            offset_val = 0
                        if isinstance(base_val, int):
                            return base_val + offset_val
                        elif Z3Solver.available() and hasattr(base_val, "sort"):
                            import z3 as _z3
                            return base_val + _z3.BitVecVal(offset_val, state.bit_width)
                    break
            # Simple [reg]
            inner_lower = inner.lower()
            if inner_lower in state.registers:
                return state.get_register(inner_lower)

        # Fallback to _resolve_operand for non-memory operands
        return self._resolve_operand(state, operand)

    def _resolve_operand(self, state: SymbolicState, operand: str) -> Any:
        """Resolve an operand to a symbolic or concrete value."""
        operand = operand.strip()

        # Register?
        reg = operand.lower()
        if reg in state.registers:
            return state.get_register(reg)

        # Immediate / hex constant?
        try:
            if operand.startswith("0x") or operand.startswith("-0x"):
                return int(operand, 16)
            if operand.lstrip("-").isdigit():
                return int(operand)
        except ValueError:
            pass

        # Memory dereference like [rax], [rsp+0x8], etc.
        if operand.startswith("[") and operand.endswith("]"):
            inner = operand[1:-1].strip()
            # Try to parse [reg+offset]
            for sep in ("+", "-"):
                if sep in inner:
                    parts = inner.split(sep, 1)
                    base_reg = parts[0].strip().lower()
                    if base_reg in state.registers:
                        base_val = state.get_register(base_reg)
                        try:
                            offset_val = int(parts[1].strip(), 0)
                            if sep == "-":
                                offset_val = -offset_val
                        except ValueError:
                            offset_val = 0
                        if isinstance(base_val, int):
                            return state.read_memory(base_val + offset_val)
                    break
            # Simple [reg]
            inner_lower = inner.lower()
            if inner_lower in state.registers:
                addr = state.get_register(inner_lower)
                if isinstance(addr, int):
                    return state.read_memory(addr)

        # Size prefixed operands (e.g., "dword ptr [rax]")
        for prefix in ("byte ptr ", "word ptr ", "dword ptr ", "qword ptr "):
            if operand.lower().startswith(prefix):
                return self._resolve_operand(state, operand[len(prefix):])

        return 0  # fallback

    def _write_operand(self, state: SymbolicState, operand: str, value: Any) -> None:
        """Write a value to the destination operand."""
        operand = operand.strip()
        reg = operand.lower()
        if reg in state.registers:
            state.set_register(reg, value)
            return

        # Memory dereference
        if operand.startswith("[") and operand.endswith("]"):
            inner = operand[1:-1].strip()
            for sep in ("+", "-"):
                if sep in inner:
                    parts = inner.split(sep, 1)
                    base_reg = parts[0].strip().lower()
                    if base_reg in state.registers:
                        base_val = state.get_register(base_reg)
                        try:
                            offset_val = int(parts[1].strip(), 0)
                            if sep == "-":
                                offset_val = -offset_val
                        except ValueError:
                            offset_val = 0
                        if isinstance(base_val, int):
                            state.write_memory(base_val + offset_val, value)
                        return
                    break
            inner_lower = inner.lower()
            if inner_lower in state.registers:
                addr = state.get_register(inner_lower)
                if isinstance(addr, int):
                    state.write_memory(addr, value)
                return

        # Size prefixed operands
        for prefix in ("byte ptr ", "word ptr ", "dword ptr ", "qword ptr "):
            if operand.lower().startswith(prefix):
                self._write_operand(state, operand[len(prefix):], value)
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
        for rname in state.registers:
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

        return HandlerSymbolicSummary(
            address=handler_address,
            instruction_count=stepped,
            final_registers=final_regs,
            simplified_registers=simplified_regs,
            memory_writes=mem_writes,
            constraints=constraints,
            input_symbols={rname: str(sym) for rname, sym in sym_regs.items()},
        )

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

    def _build_branch_constraint(self, state: SymbolicState, insn: LiftedInstruction) -> Any:
        """Build a z3 constraint for a conditional branch based on the last cmp/test."""
        if not Z3Solver.available():
            return None

        cmp_info = getattr(state, "_last_cmp", None)
        if cmp_info is None:
            return None

        import z3 as _z3

        cmp_mnemonic, left, right = cmp_info
        left = self._ensure_bv(left, state.bit_width)
        right = self._ensure_bv(right, state.bit_width)

        mn = insn.mnemonic

        # TEST performs bitwise AND; CMP performs SUB.
        # Branch conditions after TEST use (left & right) as the "diff";
        # after CMP they use (left - right).
        if cmp_mnemonic == "test":
            diff = left & right
            if mn in ("je", "jz"):
                return diff == 0
            elif mn in ("jne", "jnz"):
                return diff != 0
            # Other branches after TEST are uncommon; fall through to None
            return None

        # --- CMP semantics: branch on (left - right) comparison ---------
        # Map branch mnemonics to z3 predicates
        if mn in ("je", "jz"):
            return left == right
        elif mn in ("jne", "jnz"):
            return left != right
        elif mn in ("jg",):
            return left > right  # signed
        elif mn in ("jge",):
            return left >= right
        elif mn in ("jl",):
            return left < right
        elif mn in ("jle",):
            return left <= right
        elif mn in ("ja",):
            return _z3.UGT(left, right)  # unsigned above
        elif mn in ("jae",):
            return _z3.UGE(left, right)
        elif mn in ("jb",):
            return _z3.ULT(left, right)  # unsigned below
        elif mn in ("jbe",):
            return _z3.ULE(left, right)

        return None
