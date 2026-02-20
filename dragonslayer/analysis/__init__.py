"""
Analysis package.
"""

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
    PseudocodeResult,
)

from .bytecode_cfg import (  # noqa: F401
    build_handler_cfg as build_handler_cfg_v2,
    build_static_cfg,
    walk_trace_bytecode,
    walk_static_bytecode,
    detect_natural_loops,
    VMInstruction,
    HandlerBasicBlock,
    CFGEdge,
    HandlerCFG,
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
