"""
Qiling Emulation Plugin
========================

Ported from ``repos/stage4/working/qiling/qiling_analyzer.py``.

Emulates the target binary with the *Qiling* framework, collecting a
block-level execution trace that downstream plugins (angr, triton,
vector_share) use as guidance for focused analysis.

Heavy dependency: ``qiling``.
"""

from __future__ import annotations

import contextlib
import logging
import os
import tempfile
import time
from typing import Any

from .. import Plugin, PluginContext, PluginResult, Stage, register_plugin

logger = logging.getLogger(__name__)

_HAS_QILING = False
try:
    from qiling import Qiling  # type: ignore[import-untyped]
    from qiling.const import QL_VERBOSE  # type: ignore[import-untyped]

    _HAS_QILING = True
except (ImportError, OSError):
    pass


def _detect_rootfs(file_data: bytes, context: PluginContext) -> str | None:
    """
    Heuristic root-FS detection.

    Checks shared_data for fileinfo results, falls back to magic-byte
    detection.  Returns a rootfs path suitable for Qiling or ``None``.
    """
    fileinfo = context.shared_data.get("fileinfo", {})
    file_type = fileinfo.get("type", "").lower()

    # Map file type strings to Qiling rootfs subdirectories
    rootfs_map = {
        "pe32": "x86_windows",
        "pe32+": "x8664_windows",
        "elf 32": "x86_linux",
        "elf 64": "x8664_linux",
        "mach-o 64": "x8664_macos",
    }

    for key, rootfs_name in rootfs_map.items():
        if key in file_type:
            candidate = os.path.join(os.sep, "qiling", "rootfs", rootfs_name)
            if os.path.isdir(candidate):
                return candidate

    # Fallback: magic bytes
    if file_data[:2] == b"MZ":
        for name in ("x86_windows", "x8664_windows"):
            p = os.path.join(os.sep, "qiling", "rootfs", name)
            if os.path.isdir(p):
                return p
    elif file_data[:4] == b"\x7fELF":
        for name in ("x86_linux", "x8664_linux"):
            p = os.path.join(os.sep, "qiling", "rootfs", name)
            if os.path.isdir(p):
                return p

    # User-supplied via config
    return context.config.get("qiling.rootfs")


@register_plugin
class QilingAnalyzer(Plugin):
    """Block-level execution trace via Qiling emulation."""

    name = "qiling"
    stage = Stage.DYNAMIC
    description = "Qiling emulation engine — block execution trace"

    @classmethod
    def available(cls) -> bool:
        return _HAS_QILING

    def execute(
        self,
        file_path: str,
        file_data: bytes,
        context: PluginContext,
    ) -> PluginResult:
        t0 = time.monotonic()

        tmp_path: str | None = None
        if not file_path or not os.path.isfile(file_path):
            fd, tmp_path = tempfile.mkstemp(suffix=".bin")
            os.write(fd, file_data)
            os.close(fd)
            file_path = tmp_path

        try:
            result = self._analyze(file_path, file_data, context)
            # Store trace in shared_data for downstream plugins
            context.shared_data["qiling"] = result
            return self._make_result(
                success=True,
                data=result,
                duration=time.monotonic() - t0,
                confidence=result.get("confidence", 0.0),
            )
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, OSError, IndexError) as exc:
            logger.exception("Qiling analysis failed")
            return self._make_result(
                success=False,
                error=str(exc),
                duration=time.monotonic() - t0,
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def _analyze(
        self,
        file_path: str,
        file_data: bytes,
        ctx: PluginContext,
    ) -> dict[str, Any]:
        rootfs = _detect_rootfs(file_data, ctx)
        if not rootfs:
            raise FileNotFoundError(
                "Qiling rootfs not found — set config 'qiling.rootfs' or "
                "install rootfs at /qiling/rootfs/<arch>_<os>"
            )

        executed_blocks: list[dict[str, int]] = []
        block_set: set[int] = set()
        max_blocks = int(ctx.config.get("qiling.max_blocks", 50_000))
        max_insns = int(ctx.config.get("qiling.max_instructions", 200_000))

        # Per-instruction trace data
        instruction_trace: list[dict[str, Any]] = []
        mem_accesses: list[dict[str, Any]] = []
        insn_count = 0

        # Determine architecture for register snapshot
        is_64 = file_data[:2] == b"MZ" and len(file_data) > 0x40
        fileinfo = ctx.shared_data.get("fileinfo", {})
        file_type = fileinfo.get("type", "").lower()
        if "64" in file_type or "pe32+" in file_type:
            is_64 = True
        elif "32" in file_type:
            is_64 = False

        if is_64:
            _REG_LIST = [
                "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                "rbp", "rsp", "r8", "r9", "r10", "r11",
                "r12", "r13", "r14", "r15", "rip",
            ]
        else:
            _REG_LIST = [
                "eax", "ebx", "ecx", "edx", "esi", "edi",
                "ebp", "esp", "eip",
            ]

        # Unified disassembler — created once, reused for every instruction
        from dragonslayer.core.disassembler import create_disassembler as _mk_disasm
        _ql_disasm = _mk_disasm("x64" if is_64 else "x86")

        def _block_hook(ql: Any, address: int, size: int) -> None:
            if len(block_set) >= max_blocks:
                ql.stop()
                return
            if address not in block_set:
                block_set.add(address)
                executed_blocks.append({"start": address, "end": address + size})

        def _code_hook(ql: Any, address: int, size: int) -> None:
            nonlocal insn_count
            if insn_count >= max_insns:
                ql.stop()
                return
            insn_count += 1

            # Register snapshot
            reg_snapshot: dict[str, int] = {}
            for rname in _REG_LIST:
                with contextlib.suppress(ValueError, TypeError, AttributeError, RuntimeError):
                    reg_snapshot[rname] = ql.arch.regs.read(rname)

            # Read raw instruction bytes
            try:
                raw = bytes(ql.mem.read(address, size))
            except (ValueError, TypeError, RuntimeError, OSError):
                raw = b""

            # Disassemble via unified disassembler (one instance, reused)
            disasm = ""
            try:
                _text, _ = _ql_disasm.disassemble_to_text(raw, address)
                disasm = _text
            except (ValueError, TypeError, AttributeError, RuntimeError):
                disasm = raw.hex()

            instruction_trace.append({
                "address": address,
                "size": size,
                "raw_bytes": raw.hex(),
                "disassembly": disasm,
                "registers": reg_snapshot,
                "memory_accesses": [],  # filled by mem hooks via index
            })

        def _mem_read_hook(
            ql: Any, access: int, address: int, size: int, value: int
        ) -> None:
            entry = {
                "type": "read",
                "address": address,
                "size": size,
                "value": value,
            }
            mem_accesses.append(entry)
            # Attach to current instruction
            if instruction_trace:
                instruction_trace[-1]["memory_accesses"].append(entry)

        def _mem_write_hook(
            ql: Any, access: int, address: int, size: int, value: int
        ) -> None:
            entry = {
                "type": "write",
                "address": address,
                "size": size,
                "value": value,
            }
            mem_accesses.append(entry)
            if instruction_trace:
                instruction_trace[-1]["memory_accesses"].append(entry)

        timeout = int(ctx.config.get("qiling.timeout", 60))

        ql = Qiling(
            [file_path],
            rootfs,
            verbose=QL_VERBOSE.DISABLED,
        )
        ql.hook_block(_block_hook)
        ql.hook_code(_code_hook)

        # Memory access hooks
        try:

            ql.hook_mem_read(_mem_read_hook)
            ql.hook_mem_write(_mem_write_hook)
        except (ValueError, TypeError, AttributeError, RuntimeError):
            logger.debug("Qiling memory hooks not fully available")

        # ---- Anti-evasion runtime hooks ------------------------------------
        _hook_install_result = None
        _runtime_hook_set = ctx.shared_data.get("runtime_hook_set")
        if _runtime_hook_set is not None:
            try:
                from dragonslayer.analysis.anti_evasion.runtime_hooks import (
                    apply_hooks_to_qiling,
                )
                _hook_install_result = apply_hooks_to_qiling(ql, _runtime_hook_set)
                logger.info(
                    "Qiling anti-evasion hooks: %d installed, %d skipped",
                    _hook_install_result.success_count,
                    len(_hook_install_result.skipped),
                )
            except Exception:  # pragma: no cover
                logger.debug("Anti-evasion hook installation failed", exc_info=True)

        try:
            ql.run(timeout=timeout * 1_000_000)  # microseconds
        except (ValueError, TypeError, RuntimeError, OSError) as exc:
            logger.warning("Qiling run ended with: %s", exc)

        confidence = min(1.0, len(executed_blocks) / 1000)

        return {
            "rootfs": rootfs,
            "executed_blocks": executed_blocks,
            "unique_blocks": len(block_set),
            "instructions_executed": insn_count,
            "instruction_trace": instruction_trace,
            "memory_accesses": mem_accesses,
            "confidence": round(confidence, 4),
            "anti_evasion_hooks": (
                _hook_install_result.to_dict()
                if _hook_install_result is not None
                else None
            ),
        }
