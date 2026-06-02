"""
VMDragonSlayer Core Module

"""

from .config import Config, get_config
from .disassembler import (
    CAPSTONE_AVAILABLE,
    DisasmArchitecture,
    DisassembledInstruction,
    Disassembler,
    create_disassembler,
    disassemble_section,
    from_pe,
    to_lifted_instruction,
    to_lifted_instructions,
)
from .exceptions import (
    AnalysisError,
    AnalysisTimeoutError,
    APIError,
    ConfigurationError,
    DevirtualizationError,
    GatewayError,
    InvalidDataError,
    NetworkError,
    PluginError,
    ResourceLimitError,
    ValidationError,
    VMDragonSlayerError,
)
from .orchestrator import (
    AnalysisMetadataDict,
    AnalysisOptionsDict,
    AnalysisRequest,
    AnalysisResult,
    AnalysisResultDict,
    AnalysisType,
    EngineHandler,
    EngineResult,
    Orchestrator,
)
from .pipeline import (
    AnalysisPipeline,
    PipelineConfig,
    PipelineResult,
    StageResult,
)

__all__ = [
    # Orchestrator
    'Orchestrator',
    'AnalysisType',
    'AnalysisRequest',
    'AnalysisResult',
    'EngineHandler',
    'EngineResult',
    'AnalysisOptionsDict',
    'AnalysisMetadataDict',
    'AnalysisResultDict',

    # Configuration
    'get_config',
    'Config',

    # Pipeline
    'AnalysisPipeline',
    'PipelineConfig',
    'PipelineResult',
    'StageResult',

    # Disassembler
    'Disassembler',
    'DisassembledInstruction',
    'DisasmArchitecture',
    'create_disassembler',
    'from_pe',
    'disassemble_section',
    'to_lifted_instruction',
    'to_lifted_instructions',
    'CAPSTONE_AVAILABLE',

    # Exceptions (full hierarchy)
    'VMDragonSlayerError',
    'AnalysisError',
    'InvalidDataError',
    'ConfigurationError',
    'NetworkError',
    'APIError',
    'DevirtualizationError',
    'PluginError',
    'GatewayError',
    'ResourceLimitError',
    'AnalysisTimeoutError',
    'ValidationError',
]
