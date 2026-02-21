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
]

from .binary_format import (  # noqa: F401
    ParsedBinary,
    Section,
    BinaryFormat,
    Architecture,
    parse_binary,
    detect_format,
    LIEF_AVAILABLE,
)

from .trace_ingestion import (  # noqa: F401
    ExecutionTrace,
    TraceInstruction,
    TraceMemoryAccess,
    TraceControlFlow,
    HandlerMarker,
    parse_trace_text,
    from_shared_data,
    from_triton_result,
    from_angr_result,
    from_qiling_result,
)

from .cfg import (  # noqa: F401
    build_instruction_cfg,
    build_handler_cfg,
    extract_basic_blocks,
    analyse_cfg,
    find_dominators,
    BasicBlock,
    CFGStats,
    NX_AVAILABLE,
)

from .bytecode_extract import (  # noqa: F401
    extract_bytecode,
    BytecodeStream,
    OpcodeMap,
    VMOpcode,
)

from .handler_semantics import (  # noqa: F401
    analyse_handler_semantics,
    HandlerSemantic,
    OpcodeTableEntry,
    SemanticOpcodeTable,
    VMOperation,
)

from .pseudocode import (  # noqa: F401
    emit_pseudocode,
    emit_linear,
    emit_structured,
    emit_c_like,
    emit_cifuentes,
    emit_region,
    structure_cfg,
    StructuredRegion,
    StructuredBlock,
    PseudocodeResult,
)

from .bytecode_cfg import (  # noqa: F401
    build_handler_cfg as build_handler_cfg_v2,
    build_static_cfg,
    walk_trace_bytecode,
    walk_static_bytecode,
    detect_natural_loops,
    build_loop_tree,
    VMInstruction,
    HandlerBasicBlock,
    CFGEdge,
    HandlerCFG,
    NaturalLoop,
    LoopTree,
)

from .symbolic_depth import (  # noqa: F401
    extract_symbolic_summaries,
    run_handler_symbolic_execution,
    collect_symbolic_summaries,
)

from .bytecode_decrypt import (  # noqa: F401
    BytecodeDecryptor,
    KeyTransform,
    TransformOp,
    parse_decode_transforms,
    detect_initial_key,
    decrypt_handler_table,
    make_decryptor_from_dispatcher,
    DecryptedHandlerTable,
    HandlerTableEntry,
)

from .mba_simplifier import (  # noqa: F401
    simplify_mba,
    simplify_expr,
    simplify_batch,
    simplify_handler_operands,
    verify_equivalence,
    MBAResult,
    MBAStats,
)

from .devirtualisation_result import (  # noqa: F401
    DevirtualisationResult,
)

try:
    from .expr_simplify import (  # noqa: F401
        simplify_pseudocode,
        fold_constants,
        fold_identities,
        fold_self_cancel,
        fold_redundant_casts,
        propagate_types,
    )
except (ImportError, AttributeError):
    simplify_pseudocode = None  # type: ignore[assignment,misc]
    fold_constants = None  # type: ignore[assignment,misc]
    fold_identities = None  # type: ignore[assignment,misc]
    fold_self_cancel = None  # type: ignore[assignment,misc]
    fold_redundant_casts = None  # type: ignore[assignment,misc]
    propagate_types = None  # type: ignore[assignment,misc]

try:
    from .key_recovery import (  # noqa: F401
        RecoveredKey,
        recover_key_from_entry,
        recover_key_from_bytes,
    )
except (ImportError, AttributeError):
    RecoveredKey = None  # type: ignore[assignment,misc]
    recover_key_from_entry = None  # type: ignore[assignment,misc]
    recover_key_from_bytes = None  # type: ignore[assignment,misc]

try:
    from .dataflow import (  # noqa: F401
        backward_slice,
        compute_live_ranges,
        BackwardSliceResult,
    )
except (ImportError, AttributeError):
    backward_slice = None  # type: ignore[assignment,misc]
    compute_live_ranges = None  # type: ignore[assignment,misc]
    BackwardSliceResult = None  # type: ignore[assignment,misc]
