"""
VM Discovery — Database
=======================

Stores and retrieves known VM protector signatures, handler templates,
and detection rules.  Backed by the same :class:`StorageBackend`
abstraction used by the plugin system.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class VMSignature:
    """A known VM protector signature."""
    signature_id: str
    protector: str
    version: str = ""
    section_names: List[str] = field(default_factory=list)
    watermarks: List[str] = field(default_factory=list)
    entry_point_patterns: List[str] = field(default_factory=list)
    description: str = ""
    confidence_weight: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class VMSignatureDatabase:
    """
    In-memory database of VM protector signatures.

    Can be populated from JSON or via :meth:`add_signature`.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self._signatures: Dict[str, VMSignature] = {}
        self._by_protector: Dict[str, List[str]] = {}
        if path and path.exists():
            self._load(path)
        else:
            self._load_builtins()

    def _load(self, path: Path) -> None:
        """Load signatures from a JSON file."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for entry in data if isinstance(data, list) else data.get("signatures", []):
                sig = VMSignature(**entry)
                self.add_signature(sig)
        except Exception as exc:
            logger.warning("Failed to load VM signatures from %s: %s", path, exc)
            self._load_builtins()

    def _load_builtins(self) -> None:
        """Populate with built-in protector signatures."""
        builtins = [
            VMSignature(
                signature_id="vmprotect_v3",
                protector="VMProtect",
                version="3.x",
                section_names=[".vmp0", ".vmp1", ".vmp2"],
                watermarks=["VMProtect", "vmp_"],
                entry_point_patterns=["68????????C3", "E9????????"],
                description="VMProtect 3.x with bytecode interpreter",
                confidence_weight=1.0,
            ),
            VMSignature(
                signature_id="vmprotect_v2",
                protector="VMProtect",
                version="2.x",
                section_names=[".vmp0", ".vmp1"],
                watermarks=["VMProtect"],
                entry_point_patterns=["68????????E9"],
                description="VMProtect 2.x (older handler format)",
                confidence_weight=0.9,
            ),
            VMSignature(
                signature_id="themida_v3",
                protector="Themida",
                version="3.x",
                section_names=[".themida", ".winlice"],
                watermarks=["Themida", "WinLicense", ".oreans"],
                description="Themida 3.x / WinLicense with nested VMs",
                confidence_weight=1.0,
            ),
            VMSignature(
                signature_id="code_virtualizer_v2",
                protector="Code Virtualizer",
                version="2.x",
                section_names=[".cvirt"],
                watermarks=["Code Virtualizer"],
                description="Code Virtualizer 2.x with CISC interpreter",
                confidence_weight=0.8,
            ),
            VMSignature(
                signature_id="enigma_v6",
                protector="Enigma Protector",
                version="6.x+",
                section_names=[".enigma1", ".enigma2"],
                watermarks=["Enigma protector"],
                description="Enigma Protector 6+ with VM layer",
                confidence_weight=0.7,
            ),
        ]
        for sig in builtins:
            self.add_signature(sig)

    def add_signature(self, sig: VMSignature) -> None:
        """Register a signature."""
        self._signatures[sig.signature_id] = sig
        self._by_protector.setdefault(sig.protector, []).append(sig.signature_id)

    def match(self, detection_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Match detection results against known signatures.

        Returns a list of ``{signature, score}`` dicts sorted by score desc.
        """
        matches: List[Dict[str, Any]] = []

        detected_sections = set()
        for ind in detection_result.get("indicators", []):
            if ind.get("check") == "vm_sections":
                detected_sections.update(ind.get("sections", []))

        detected_watermarks = set()
        for ind in detection_result.get("indicators", []):
            if ind.get("check") == "watermarks":
                detected_watermarks.update(ind.get("found", []))

        for sig in self._signatures.values():
            score = 0.0
            sig_sections = set(sig.section_names)
            sig_watermarks = set(sig.watermarks)

            section_overlap = detected_sections & sig_sections
            if section_overlap:
                score += 0.5 * (len(section_overlap) / max(len(sig_sections), 1))

            watermark_overlap = detected_watermarks & sig_watermarks
            if watermark_overlap:
                score += 0.5 * (len(watermark_overlap) / max(len(sig_watermarks), 1))

            score *= sig.confidence_weight

            if score > 0:
                matches.append({
                    "signature": sig.to_dict(),
                    "score": round(score, 4),
                })

        matches.sort(key=lambda m: m["score"], reverse=True)
        return matches

    def get_by_protector(self, protector: str) -> List[VMSignature]:
        """Return all signatures for a given protector name."""
        ids = self._by_protector.get(protector, [])
        return [self._signatures[sid] for sid in ids if sid in self._signatures]

    def __len__(self) -> int:
        return len(self._signatures)
