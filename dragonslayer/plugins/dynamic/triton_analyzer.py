"""
Triton Symbolic-Execution Analyser
===================================

Ported from ``repos/stage4/working/triton/triton_analyzer.py``.

Uses the Triton dynamic binary analysis framework together with
*lief* and *capstone* to symbolically execute entry regions of a
binary and extract AST expression vectors per function.

Heavy dependencies: ``triton``, ``lief``, ``capstone``.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import time
from collections import Counter
from typing import Any, Dict, List, Optional

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

_HAS_TRITON = False
try:
    import lief  # type: ignore[import-untyped]
    from triton import (  # type: ignore[import-untyped]
        ARCH,
        CPUSIZE,
        MODE,
        AST_REPRESENTATION,
        Instruction,
        TritonContext,
        REG,
        CALLBACK,
        OPCODE,
        OPERAND,
    )
    import capstone  # type: ignore[import-untyped]

    _HAS_TRITON = True
except Exception:
    pass


@register_plugin
class TritonAnalyzer(Plugin):
    """Symbolic execution and AST expression extraction via Triton."""

    name = "triton"
    stage = Stage.DYNAMIC
    description = "Triton symbolic execution with AST feature extraction"

    @classmethod
    def available(cls) -> bool:
        return _HAS_TRITON

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        tmp_path: Optional[str] = None
        if not file_path or not os.path.isfile(file_path):
            fd, tmp_path = tempfile.mkstemp(suffix=".bin")
            os.write(fd, file_data)
            os.close(fd)
            file_path = tmp_path

        try:
            result = self._analyze(file_path, context)
            return self._make_result(
                success=True,
                data=result,
                duration=time.monotonic() - t0,
                confidence=result.get("confidence", 0.0),
            )
        except Exception as exc:
            logger.exception("Triton analysis failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _analyze(self, file_path: str, ctx: PluginContext) -> Dict[str, Any]:
        binary = lief.parse(file_path)
        if binary is None:
            raise ValueError(f"lief could not parse {file_path}")

        # Determine architecture
        is_64 = False
        if isinstance(binary, lief.PE.Binary):
            is_64 = binary.header.machine in (
                lief.PE.Header.MACHINE_TYPES.AMD64,
                lief.PE.Header.MACHINE_TYPES.ARM64,
            )
        elif isinstance(binary, lief.ELF.Binary):
            is_64 = binary.header.identity_class == lief.ELF.ELF_CLASS.CLASS64

        # Init Triton
        tc = TritonContext()
        if is_64:
            tc.setArchitecture(ARCH.X86_64)
        else:
            tc.setArchitecture(ARCH.X86)
        tc.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)

        # Load sections
        for section in binary.sections:
            content = bytes(section.content)
            if not content:
                continue
            vaddr = section.virtual_address
            if isinstance(binary, lief.PE.Binary):
                vaddr += binary.optional_header.imagebase
            tc.setConcreteMemoryAreaValue(vaddr, content)

        # --- Taint engine: taint VM context registers -----------------------
        # Taint registers commonly used as VM context pointers
        taint_regs = []
        vm_detected = ctx.shared_data.get("vm_detected", False)
        if vm_detected:
            try:
                if is_64:
                    taint_targets = [
                        tc.registers.rsi, tc.registers.rbp,
                        tc.registers.rdi, tc.registers.r12,
                    ]
                else:
                    taint_targets = [
                        tc.registers.esi, tc.registers.ebp,
                        tc.registers.edi,
                    ]
                for reg in taint_targets:
                    try:
                        tc.taintRegister(reg)
                        taint_regs.append(reg.getName())
                    except Exception:
                        pass
            except Exception:
                pass

        # Guidance intervals from shared context
        guidance: List[Dict[str, int]] = []
        qiling_data = ctx.shared_data.get("qiling", {})
        if isinstance(qiling_data, dict):
            for blk in qiling_data.get("executed_blocks", []):
                if isinstance(blk, dict) and "start" in blk and "end" in blk:
                    guidance.append(blk)

        # Determine entry addresses
        entry = binary.entrypoint
        if isinstance(binary, lief.PE.Binary):
            entry += binary.optional_header.imagebase

        exec_addrs = [entry]
        # Also use dispatcher addresses from VM discovery
        dispatcher_addrs = ctx.shared_data.get("vm_discovery", {}).get("dispatcher_addresses", [])
        if dispatcher_addrs:
            exec_addrs = dispatcher_addrs[:10] + exec_addrs
        if guidance:
            exec_addrs = [g["start"] for g in guidance[:50]] + exec_addrs
        # De-duplicate while preserving order
        seen = set()
        unique_addrs = []
        for a in exec_addrs:
            if a not in seen:
                seen.add(a)
                unique_addrs.append(a)
        exec_addrs = unique_addrs

        # Symbolic execution (limited to prevent explosion)
        MAX_INSNS = 5_000
        insn_count = 0
        ast_counter: Counter[str] = Counter()
        functions_data: List[Dict[str, Any]] = []
        executed_addrs: List[int] = []
        taint_flow: List[Dict[str, Any]] = []
        path_constraints: List[str] = []

        for start_addr in exec_addrs:
            pc = start_addr
            local_counter: Counter[str] = Counter()
            local_insns = 0

            for _ in range(MAX_INSNS // max(len(exec_addrs), 1)):
                opcode = tc.getConcreteMemoryAreaValue(pc, 16)
                if not any(opcode):
                    break

                inst = Instruction(pc, opcode)
                try:
                    if not tc.processing(inst):
                        break
                except Exception:
                    break

                insn_count += 1
                local_insns += 1
                executed_addrs.append(pc)

                # Collect AST expressions
                for expr in inst.getSymbolicExpressions():
                    ast_node = expr.getAst()
                    node_type = type(ast_node).__name__
                    local_counter[node_type] += 1
                    ast_counter[node_type] += 1

                # --- Taint tracking: record taint propagation ---------------
                if taint_regs and inst.isTainted():
                    taint_entry = {
                        "address": pc,
                        "disasm": inst.getDisassembly(),
                    }
                    try:
                        tainted_read = [
                            op.getRegister().getName()
                            for op in inst.getOperands()
                            if hasattr(op, "getRegister") and op.getType() == OPERAND.REG
                            and tc.isRegisterTainted(op.getRegister())
                        ]
                        tainted_write = [
                            op.getRegister().getName()
                            for op in inst.getOperands()
                            if hasattr(op, "getRegister") and op.getType() == OPERAND.REG
                        ]
                        taint_entry["tainted_reads"] = tainted_read
                        taint_entry["tainted_writes"] = tainted_write
                    except Exception:
                        pass
                    taint_flow.append(taint_entry)

                # --- Path constraints: collect on branch instructions --------
                try:
                    if inst.isBranch() and inst.isSymbolized():
                        pc_ast = tc.getPathPredicate()
                        if pc_ast is not None:
                            path_constraints.append(str(pc_ast)[:500])
                except Exception:
                    pass

                pc = int(tc.getConcreteRegisterValue(
                    tc.registers.rip if is_64 else tc.registers.eip
                ))

                if local_insns >= 500:
                    break

            if local_insns > 0:
                func_hash = hashlib.md5(
                    f"{start_addr}:{list(local_counter.items())}".encode()
                ).hexdigest()
                functions_data.append({
                    "address": start_addr,
                    "name": f"func_{start_addr:x}",
                    "instructions_executed": local_insns,
                    "ast_types": dict(local_counter),
                    "hash": func_hash,
                    "mnemonics": list(local_counter.keys()),
                })

        confidence = min(1.0, insn_count / 1000) if insn_count else 0.0

        return {
            "arch": "x86_64" if is_64 else "x86",
            "entry_point": hex(entry),
            "instructions_executed": insn_count,
            "unique_addresses": len(set(executed_addrs)),
            "function_count": len(functions_data),
            "functions": functions_data,
            "global_ast_types": dict(ast_counter),
            "guidance_intervals": len(guidance),
            "taint_flow": taint_flow[:200],
            "taint_flow_count": len(taint_flow),
            "tainted_registers_initial": taint_regs,
            "path_constraints": path_constraints[:50],
            "path_constraint_count": len(path_constraints),
            "confidence": round(confidence, 4),
        }
