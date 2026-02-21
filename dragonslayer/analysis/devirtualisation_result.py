"""
Devirtualisation Result
=======================

Typed result dataclass emitted by the ``devirtualize`` pipeline stage.
Replaces the previous ad-hoc ``Dict[str, Any]`` with a structured,
documented container that downstream consumers (API, reporter, LLM)
can rely on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DevirtualisationResult:
    """Structured result of the devirtualisation pipeline stage.

    All heavy sub-products (opcode table, pseudocode, CFG, etc.) are
    stored as *dicts* — the canonical ``to_dict()`` representations of
    the underlying analysis objects — so the result is trivially
    JSON-serialisable.
    """

    # ── Top-level status ─────────────────────────────────────────────
    success: bool = False
    skipped: bool = False
    skip_reason: str = ""

    # ── Core devirt products ─────────────────────────────────────────
    vip_register: str = ""
    handler_count: int = 0
    unique_operations: int = 0

    opcode_table: Dict[str, Any] = field(default_factory=dict)
    """``SemanticOpcodeTable.to_dict()`` — per-opcode handler entries."""

    pseudocode: Dict[str, Any] = field(default_factory=dict)
    """``PseudocodeResult.to_dict()``."""

    pseudocode_text: str = ""
    """Human-readable C-like pseudocode string."""

    # ── Sub-product dicts (Batch 13-25) ──────────────────────────────
    anti_evasion_hooks: Optional[Dict[str, Any]] = None
    vmprotect_dispatcher: Optional[Dict[str, Any]] = None
    handler_extraction: Optional[Dict[str, Any]] = None
    vm_context_layout: Optional[Dict[str, Any]] = None
    handler_clustering: Optional[Dict[str, Any]] = None
    handler_cfg: Optional[Dict[str, Any]] = None
    vm_entry_points: Optional[Dict[str, Any]] = None
    decrypted_handler_table: Optional[Dict[str, Any]] = None
    bytecode_decryptor: Optional[Dict[str, Any]] = None
    static_handler_cfg: Optional[Dict[str, Any]] = None

    # ── ML ensemble classification results ───────────────────────────
    ml_classifications: Optional[Dict[str, str]] = None
    """Maps handler address (hex-string) → ML-predicted label."""

    # ── Multi-protector + nested VM fields (B100) ────────────────────
    dispatcher_match: Optional[Dict[str, Any]] = None
    """Generic dispatcher match dict (works for any protector)."""

    detected_protector: str = "unknown"
    """Name of the detected protector (vmprotect, themida, cv, unknown)."""

    nested_layers: Optional[List[Dict[str, Any]]] = None
    """Nested VM layers discovered by recursive deobfuscation."""

    # ── Convenience ──────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict (JSON-safe)."""
        d: Dict[str, Any] = {
            "success": self.success,
            "skipped": self.skipped,
            "vip_register": self.vip_register,
            "handler_count": self.handler_count,
            "unique_operations": self.unique_operations,
            "opcode_table": self.opcode_table,
            "pseudocode": self.pseudocode,
            "pseudocode_text": self.pseudocode_text,
            "detected_protector": self.detected_protector,
        }
        if self.skipped:
            d["skip_reason"] = self.skip_reason

        # Attach optional sub-products
        _optional = [
            "anti_evasion_hooks", "vmprotect_dispatcher",
            "dispatcher_match", "handler_extraction",
            "vm_context_layout", "handler_clustering",
            "handler_cfg", "vm_entry_points",
            "decrypted_handler_table", "bytecode_decryptor",
            "static_handler_cfg", "ml_classifications",
            "nested_layers",
        ]
        for key in _optional:
            val = getattr(self, key)
            if val is not None:
                d[key] = val

        return d

    @classmethod
    def skipped_result(cls, reason: str) -> "DevirtualisationResult":
        """Factory for a skipped/failed result."""
        return cls(success=False, skipped=True, skip_reason=reason)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DevirtualisationResult":
        """Reconstruct from a serialised dict."""
        known = {
            "success", "skipped", "skip_reason", "vip_register",
            "handler_count", "unique_operations", "opcode_table",
            "pseudocode", "pseudocode_text", "anti_evasion_hooks",
            "vmprotect_dispatcher", "dispatcher_match",
            "detected_protector", "handler_extraction",
            "vm_context_layout", "handler_clustering", "handler_cfg",
            "vm_entry_points", "decrypted_handler_table",
            "bytecode_decryptor", "static_handler_cfg",
            "ml_classifications", "nested_layers",
        }
        kwargs = {k: v for k, v in d.items() if k in known}
        return cls(**kwargs)
