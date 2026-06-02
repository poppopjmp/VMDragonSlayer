"""
VM Discovery
=============

Heuristic-based detection and analysis of virtual-machine obfuscation.
"""

from __future__ import annotations

try:
    from dragonslayer.analysis.handler_clustering import (
        ClusteringResult,
        NormalizedEffect,
        SemanticCluster,
        are_semantically_equivalent,
        cluster_handlers_by_semantics,
        normalize_symbolic_effect,
        refine_opcode_table,
    )

    from .analyzer import VMAnalyzer
    from .context_registers import (
        VMContextLayout,
        VMContextRegister,
        identify_vm_context,
    )
    from .database import VMSignature, VMSignatureDatabase
    from .detector import VMDetector
    from .dispatcher import (
        DispatcherAnalyzer,
        DispatchTableResult,
        GenericDispatcherMatch,
        TraceRecord,
        VMProtectDispatcherMatch,
        find_cv_dispatcher,
        find_dispatcher,
        find_dispatcher_in_trace,
        find_generic_dispatcher,
        find_themida_dispatcher,
        find_vmprotect_dispatcher,
        register_dispatcher_finder,
    )
    from .handler_boundaries import (
        HandlerBoundary,
        SegmentationResult,
        VIPCandidate,
        identify_vip_register,
        score_vip_from_symbolic,
        segment_trace,
    )
    from .handler_extraction import (
        ExtractionResult,
        HandlerBody,
        HandlerGroup,
        deduplicate_handlers,
        extract_handler_bodies,
        fingerprint_handler,
    )
    from .vm_entry_locator import (
        SectionInfo,
        VmEntryCandidate,
        VmEntryReport,
        locate_entries_from_pe_result,
        locate_vm_entries,
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
    "VMProtectDispatcherMatch",
    "find_vmprotect_dispatcher",
    "find_dispatcher_in_trace",
    "GenericDispatcherMatch",
    "find_dispatcher",
    "find_themida_dispatcher",
    "find_cv_dispatcher",
    "find_generic_dispatcher",
    "register_dispatcher_finder",
    "TraceRecord",
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
