"""
VM Discovery
=============

Heuristic-based detection and analysis of virtual-machine obfuscation.
"""

from __future__ import annotations

try:
    from .detector import VMDetector
    from .analyzer import VMAnalyzer
    from .database import VMSignature, VMSignatureDatabase
    from .dispatcher import (
        DispatcherAnalyzer,
        DispatchTableResult,
        VMProtectDispatcherMatch,
        find_vmprotect_dispatcher,
        find_dispatcher_in_trace,
    )
    from .handler_boundaries import (
        identify_vip_register,
        score_vip_from_symbolic,
        segment_trace,
        VIPCandidate,
        HandlerBoundary,
        SegmentationResult,
    )
    from .handler_extraction import (
        extract_handler_bodies,
        fingerprint_handler,
        deduplicate_handlers,
        HandlerBody,
        HandlerGroup,
        ExtractionResult,
    )
    from .context_registers import (
        identify_vm_context,
        VMContextLayout,
        VMContextRegister,
    )
    from dragonslayer.analysis.handler_clustering import (
        cluster_handlers_by_semantics,
        normalize_symbolic_effect,
        are_semantically_equivalent,
        refine_opcode_table,
        NormalizedEffect,
        SemanticCluster,
        ClusteringResult,
    )
    from .vm_entry_locator import (
        locate_vm_entries,
        locate_entries_from_pe_result,
        VmEntryCandidate,
        VmEntryReport,
        SectionInfo,
    )
except ImportError:
    pass

__all__ = [
    "VMDetector",
    "VMAnalyzer",
    "VMSignature",
    "VMSignatureDatabase",
    "DispatcherAnalyzer",
    "DispatchTableResult",
    "identify_vip_register",
    "score_vip_from_symbolic",
    "segment_trace",
    "VIPCandidate",
    "HandlerBoundary",
    "SegmentationResult",
    "extract_handler_bodies",
    "fingerprint_handler",
    "deduplicate_handlers",
    "HandlerBody",
    "HandlerGroup",
    "ExtractionResult",
    "identify_vm_context",
    "VMContextLayout",
    "VMContextRegister",
    "cluster_handlers_by_semantics",
    "normalize_symbolic_effect",
    "are_semantically_equivalent",
    "refine_opcode_table",
    "NormalizedEffect",
    "SemanticCluster",
    "ClusteringResult",
    "locate_vm_entries",
    "locate_entries_from_pe_result",
    "VmEntryCandidate",
    "VmEntryReport",
    "SectionInfo",
]
