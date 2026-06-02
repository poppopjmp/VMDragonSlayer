"""
Analysis package.
"""

__all__ = [
    # binary_format
    "ParsedBinary", "Section", "BinaryFormat", "Architecture",
    "parse_binary", "detect_format", "LIEF_AVAILABLE",
    # trace_ingestion
    "ExecutionTrace", "TraceInstruction", "TraceMemoryAccess",
    "TraceControlFlow", "HandlerMarker", "parse_trace_text",
    "from_shared_data", "from_triton_result", "from_angr_result",
    "from_qiling_result",
    # cfg
    "build_instruction_cfg", "build_handler_cfg", "extract_basic_blocks",
    "analyse_cfg", "find_dominators", "BasicBlock", "CFGStats", "NX_AVAILABLE",
    # bytecode_extract
    "extract_bytecode", "BytecodeStream", "OpcodeMap", "VMOpcode",
    # handler_semantics
    "analyse_handler_semantics", "HandlerSemantic", "OpcodeTableEntry",
    "SemanticOpcodeTable", "VMOperation",
    # pseudocode
    "emit_pseudocode", "emit_linear", "emit_structured", "emit_c_like",
    "emit_cifuentes", "emit_region", "structure_cfg",
    "StructuredRegion", "StructuredBlock", "PseudocodeResult",
    # bytecode_cfg
    "build_handler_cfg_v2", "build_static_cfg", "walk_trace_bytecode",
    "walk_static_bytecode", "detect_natural_loops", "build_loop_tree",
    "VMInstruction", "HandlerBasicBlock", "CFGEdge", "HandlerCFG",
    "NaturalLoop", "LoopTree",
    # symbolic_depth
    "extract_symbolic_summaries", "run_handler_symbolic_execution",
    "collect_symbolic_summaries",
    # bytecode_decrypt
    "BytecodeDecryptor", "KeyTransform", "TransformOp",
    "parse_decode_transforms", "detect_initial_key", "decrypt_handler_table",
    "make_decryptor_from_dispatcher", "DecryptedHandlerTable", "HandlerTableEntry",
    # mba_simplifier
    "simplify_mba", "simplify_expr", "simplify_batch",
    "simplify_handler_operands", "verify_equivalence", "MBAResult", "MBAStats",
    # devirtualisation_result
    "DevirtualisationResult",
    # themida_devirt (B104)
    "ThemidaVariant", "ThemidaVMProfile", "ThemidaBytecodeDecoder",
    "ThemidaOpcodeTable", "ThemidaDevirtResult",
    "identify_themida_variant", "reconstruct_opcode_table",
    "classify_handler_entries", "devirtualize_themida",
    # cv_devirt (B104)
    "CVVersion", "CVVMProfile", "CVBytecodeDecoder",
    "CVOpcodeTable", "CVDevirtResult",
    "identify_cv_version", "reconstruct_cv_handler_table",
    "classify_cv_handler_entries", "devirtualize_cv",
    # trace_collector (B106)
    "TraceBackend", "TraceConfig", "CollectionResult",
    "collect_trace", "collect_trace_from_plugin", "collect_trace_from_file",
    "filter_trace", "merge_traces", "trace_statistics",
    # trace_export (B106)
    "OutputFormat", "export_trace", "render_trace",
    "render_trace_json", "render_trace_text", "render_trace_csv",
    "render_ida_annotations", "render_ghidra_script",
    "list_formats", "validate_roundtrip",
]

# ---------------------------------------------------------------------------
# Optional sub-module imports — use a helper to eliminate boilerplate.
# Each entry is (module_relative_name, [names_to_import]).  If the module
# cannot be imported (missing C-extension dep, etc.) every name is bound
# to ``None`` at package level so dependents can test availability with a
# simple ``if name is None`` guard.
# ---------------------------------------------------------------------------
import importlib as _importlib

from .binary_format import (  # noqa: F401
    LIEF_AVAILABLE,
    Architecture,
    BinaryFormat,
    ParsedBinary,
    Section,
    detect_format,
    parse_binary,
)
from .bytecode_cfg import (
    CFGEdge,
    HandlerBasicBlock,
    HandlerCFG,
    LoopTree,
    NaturalLoop,
    VMInstruction,
    build_loop_tree,
    build_static_cfg,
    detect_natural_loops,
    walk_static_bytecode,
    walk_trace_bytecode,
)
from .bytecode_cfg import (  # noqa: F401
    build_handler_cfg as build_handler_cfg_v2,
)
from .bytecode_decrypt import (  # noqa: F401
    BytecodeDecryptor,
    DecryptedHandlerTable,
    HandlerTableEntry,
    KeyTransform,
    TransformOp,
    decrypt_handler_table,
    detect_initial_key,
    make_decryptor_from_dispatcher,
    parse_decode_transforms,
)
from .bytecode_extract import (  # noqa: F401
    BytecodeStream,
    OpcodeMap,
    VMOpcode,
    extract_bytecode,
)
from .cfg import (  # noqa: F401
    NX_AVAILABLE,
    BasicBlock,
    CFGStats,
    analyse_cfg,
    build_handler_cfg,
    build_instruction_cfg,
    extract_basic_blocks,
    find_dominators,
)
from .devirtualisation_result import (  # noqa: F401
    DevirtualisationResult,
)
from .handler_semantics import (  # noqa: F401
    HandlerSemantic,
    OpcodeTableEntry,
    SemanticOpcodeTable,
    VMOperation,
    analyse_handler_semantics,
)
from .mba_simplifier import (  # noqa: F401
    MBAResult,
    MBAStats,
    simplify_batch,
    simplify_expr,
    simplify_handler_operands,
    simplify_mba,
    verify_equivalence,
)
from .pseudocode import (  # noqa: F401
    PseudocodeResult,
    StructuredBlock,
    StructuredRegion,
    emit_c_like,
    emit_cifuentes,
    emit_linear,
    emit_pseudocode,
    emit_region,
    emit_structured,
    structure_cfg,
)
from .symbolic_depth import (  # noqa: F401
    collect_symbolic_summaries,
    extract_symbolic_summaries,
    run_handler_symbolic_execution,
)
from .trace_ingestion import (  # noqa: F401
    ExecutionTrace,
    HandlerMarker,
    TraceControlFlow,
    TraceInstruction,
    TraceMemoryAccess,
    from_angr_result,
    from_qiling_result,
    from_shared_data,
    from_triton_result,
    parse_trace_text,
)


def _try_import(module: str, names: list[str]) -> None:
    """Import *names* from a sibling module, or set them to ``None``."""
    try:
        mod = _importlib.import_module(f".{module}", __package__)
        for name in names:
            globals()[name] = getattr(mod, name)
    except (ImportError, AttributeError):
        for name in names:
            globals()[name] = None


_try_import("expr_simplify", [
    "simplify_pseudocode", "fold_constants", "fold_identities",
    "fold_self_cancel", "fold_redundant_casts", "propagate_types",
])

_try_import("key_recovery", [
    "RecoveredKey", "recover_key_from_entry", "recover_key_from_bytes",
])

_try_import("dataflow", [
    "backward_slice", "compute_live_ranges", "BackwardSliceResult",
])

_try_import("themida_devirt", [
    "ThemidaVariant", "ThemidaVMProfile", "ThemidaBytecodeDecoder",
    "ThemidaOpcodeTable", "ThemidaDevirtResult",
    "identify_themida_variant", "reconstruct_opcode_table",
    "classify_handler_entries", "devirtualize_themida",
])

_try_import("cv_devirt", [
    "CVVersion", "CVVMProfile", "CVBytecodeDecoder",
    "CVOpcodeTable", "CVDevirtResult",
    "identify_cv_version", "reconstruct_cv_handler_table",
    "classify_cv_handler_entries", "devirtualize_cv",
])

_try_import("trace_collector", [
    "TraceBackend", "TraceConfig", "CollectionResult",
    "collect_trace", "collect_trace_from_plugin", "collect_trace_from_file",
    "filter_trace", "merge_traces", "trace_statistics",
])

_try_import("trace_export", [
    "OutputFormat", "export_trace", "render_trace",
    "render_trace_json", "render_trace_text", "render_trace_csv",
    "render_ida_annotations", "render_ghidra_script",
    "list_formats", "validate_roundtrip",
])
