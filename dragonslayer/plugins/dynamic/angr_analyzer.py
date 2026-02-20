"""
angr CFG + VEX IR analyser
===========================

Ported from ``repos/stage4/working/angr/angr_analyzer.py``.

Builds a control-flow graph with *angr*, extracts per-function VEX IR
mnemonic vectors, and optionally uses Qiling execution-trace guidance
from the shared context to focus analysis on executed regions.

Heavy dependency: ``angr`` (+ ``archinfo``, ``pyvex``, ``cle``).
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

_HAS_ANGR = False
try:
    import angr  # type: ignore[import-untyped]

    _HAS_ANGR = True
except Exception:
    pass


@register_plugin
class AngrAnalyzer(Plugin):
    """Build CFG and extract VEX-IR feature vectors with *angr*."""

    name = "angr"
    stage = Stage.DYNAMIC
    description = "angr CFG analysis and VEX IR mnemonic extraction"

    @classmethod
    def available(cls) -> bool:
        return _HAS_ANGR

    # ------------------------------------------------------------------ #

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        # If we only have bytes, write to a temp file
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
            logger.exception("angr analysis failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    # ------------------------------------------------------------------ #

    def _analyze(self, file_path: str, ctx: PluginContext) -> Dict[str, Any]:
        # Load Qiling guidance from shared context (populated by qiling plugin)
        guidance: List[int] = []
        qiling_data = ctx.shared_data.get("qiling", {})
        if isinstance(qiling_data, dict):
            for blk in qiling_data.get("executed_blocks", []):
                addr = blk if isinstance(blk, int) else blk.get("start", 0)
                if addr:
                    guidance.append(addr)

        # Load dispatcher addresses from VM discovery
        vm_info = ctx.shared_data.get("vm_discovery", {})
        dispatcher_addrs = vm_info.get("dispatcher_addresses", [])
        vm_detected = ctx.shared_data.get("vm_detected", False)

        # Create angr project
        proj = angr.Project(file_path, auto_load_libs=False)

        # Build CFG with block cap to prevent runaway
        MAX_BLOCKS = 10_000
        if guidance:
            cfg = proj.analyses.CFGEmulated(
                starts=guidance[:50],
                call_depth=3,
                normalize=True,
                max_steps=MAX_BLOCKS,
            )
        else:
            cfg = proj.analyses.CFGFast(normalize=True)

        functions_data: List[Dict[str, Any]] = []
        total_blocks = 0

        for func_addr, func in cfg.kb.functions.items():
            if func.is_simprocedure or func.is_plt:
                continue

            mnemonic_counter: Counter[str] = Counter()
            block_count = 0

            for block_node in func.blocks:
                block_count += 1
                total_blocks += 1
                if total_blocks > MAX_BLOCKS:
                    break
                try:
                    vex_block = proj.factory.block(block_node.addr).vex
                    for stmt in vex_block.statements:
                        mnemonic_counter[type(stmt).__name__] += 1
                except Exception:
                    continue

            func_hash = hashlib.md5(
                f"{func.name}:{sorted(mnemonic_counter.items())}".encode()
            ).hexdigest()

            func_entry: Dict[str, Any] = {
                "name": func.name,
                "address": func_addr,
                "block_count": block_count,
                "mnemonics": dict(mnemonic_counter),
                "hash": func_hash,
            }

            # If this function was in the Qiling trace, flag it
            if guidance and func_addr in guidance:
                func_entry["dynamically_reached"] = True

            # Flag functions near dispatcher addresses (handler candidates)
            if dispatcher_addrs:
                for d_addr in dispatcher_addrs:
                    if abs(func_addr - d_addr) < 0x1000:
                        func_entry["near_dispatcher"] = True
                        func_entry["dispatcher_distance"] = abs(func_addr - d_addr)
                        break

            functions_data.append(func_entry)

        # --- Handler boundary detection via SimulationManager ---------------
        handler_exploration: Dict[str, Any] = {}
        handler_traces: List[Dict[str, Any]] = []
        if vm_detected and dispatcher_addrs:
            handler_exploration = self._explore_handlers(
                proj, dispatcher_addrs, max_steps=2000,
            )
            # Extract per-handler instruction-level traces
            handler_traces = self._extract_handler_traces(
                proj, handler_exploration.get("handler_details", []),
            )

        confidence = min(1.0, len(functions_data) / 50) if functions_data else 0.0

        result = {
            "arch": str(proj.arch),
            "entry_point": hex(proj.entry),
            "function_count": len(functions_data),
            "total_blocks": total_blocks,
            "functions": functions_data,
            "guidance_addresses": len(guidance),
            "handler_exploration": handler_exploration,
            "handler_traces": handler_traces,
            "confidence": round(confidence, 4),
        }

        # Publish to shared context for downstream stages
        ctx.shared_data["angr"] = result
        return result

    # ------------------------------------------------------------------ #

    def _extract_handler_traces(
        self,
        proj: Any,
        handler_details: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        For each discovered handler, lift VEX IR and extract instruction-
        level detail (address, mnemonic, operands) with symbolic register
        state snapshots from a handler-local symbolic execution.
        """
        traces: List[Dict[str, Any]] = []

        for hinfo in handler_details[:20]:
            d_addr = hinfo.get("dispatcher", 0)
            if not d_addr:
                continue

            try:
                # Start fresh symbolic state at the dispatcher
                state = proj.factory.blank_state(addr=d_addr)
                simgr = proj.factory.simulation_manager(state)

                instruction_records: List[Dict[str, Any]] = []
                reg_names = self._get_reg_names(proj)
                visited: set[int] = set()

                for _ in range(hinfo.get("path_length", 200)):
                    if not simgr.active:
                        break
                    s = simgr.active[0]
                    pc = s.addr

                    if pc in visited or pc == d_addr and len(visited) > 0:
                        break
                    visited.add(pc)

                    # Lift block at current PC
                    try:
                        block = proj.factory.block(pc)
                        cap_insns = block.capstone.insns
                        for ci in cap_insns:
                            reg_snapshot: Dict[str, int] = {}
                            for rname in reg_names:
                                try:
                                    rv = getattr(s.regs, rname, None)
                                    if rv is not None and not rv.symbolic:
                                        reg_snapshot[rname] = s.solver.eval(rv)
                                except Exception:
                                    pass

                            instruction_records.append({
                                "address": ci.address,
                                "size": ci.size,
                                "raw_bytes": bytes(ci.insn.bytes).hex(),
                                "disassembly": f"{ci.insn.mnemonic} {ci.insn.op_str}".strip(),
                                "registers": reg_snapshot,
                            })
                    except Exception:
                        pass

                    # Step one block
                    try:
                        simgr.step()
                    except Exception:
                        break

                traces.append({
                    "dispatcher": d_addr,
                    "instruction_count": len(instruction_records),
                    "instructions": instruction_records,
                })
            except Exception as exc:
                logger.debug("Handler trace extraction for %#x failed: %s", d_addr, exc)

        return traces

    @staticmethod
    def _get_reg_names(proj: Any) -> List[str]:
        """Return a list of general-purpose register names for the arch."""
        arch_name = proj.arch.name.lower()
        if "amd64" in arch_name or "x86_64" in arch_name:
            return [
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                "rbp", "rsp", "r8", "r9", "r10", "r11",
                "r12", "r13", "r14", "r15", "rip",
            ]
        elif "x86" in arch_name:
            return [
                "eax", "ebx", "ecx", "edx", "esi", "edi",
                "ebp", "esp", "eip",
            ]
        return []

    def _explore_handlers(
        self,
        proj: Any,
        dispatcher_addrs: List[int],
        max_steps: int = 2000,
    ) -> Dict[str, Any]:
        """
        Use angr's SimulationManager to explore paths from dispatcher
        addresses, identifying handler boundaries (where control returns
        to the dispatcher).

        Returns handler exploration summary.
        """
        handlers_found: List[Dict[str, Any]] = []
        total_paths = 0

        for d_addr in dispatcher_addrs[:5]:  # Limit to first 5 dispatchers
            try:
                state = proj.factory.blank_state(addr=d_addr)
                simgr = proj.factory.simulation_manager(state)

                # Step until we find paths that return to the dispatcher
                # or reach a function boundary
                visited: set = set()
                for step_i in range(max_steps):
                    if not simgr.active:
                        break
                    simgr.step()

                    keep: list = []
                    for s in list(simgr.active):  # snapshot list
                        pc = s.addr
                        if pc in visited:
                            # Probably looped back to dispatcher
                            if pc == d_addr:
                                handlers_found.append({
                                    "dispatcher": d_addr,
                                    "path_length": step_i + 1,
                                    "type": "loop_back",
                                })
                            # Move state out of active
                            simgr.move(
                                from_stash="active",
                                to_stash="deadended",
                                filter_func=lambda s_, target=s: s_ is target,
                            )
                        else:
                            visited.add(pc)
                            keep.append(s)

                    # Cap active states to prevent explosion
                    if len(simgr.active) > 32:
                        excess = list(simgr.active)[32:]
                        for s in excess:
                            simgr.move(
                                from_stash="active",
                                to_stash="deadended",
                                filter_func=lambda s_, tgt=s: s_ is tgt,
                            )

                total_paths += len(simgr.deadended) + len(simgr.active)

            except Exception as exc:
                logger.debug("Handler exploration from %#x failed: %s", d_addr, exc)
                continue

        return {
            "handlers_found": len(handlers_found),
            "total_paths_explored": total_paths,
            "handler_details": handlers_found[:50],
        }
