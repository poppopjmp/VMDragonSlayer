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
