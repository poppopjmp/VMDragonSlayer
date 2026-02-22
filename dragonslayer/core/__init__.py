"""
VMDragonSlayer Core Module

"""

from .orchestrator import (
    Orchestrator,
    AnalysisType,
    AnalysisRequest,
    AnalysisResult,
    EngineHandler,
    EngineResult,
    AnalysisOptionsDict,
    AnalysisMetadataDict,
    AnalysisResultDict,
)
from .config import get_config, Config
from .exceptions import (
    VMDragonSlayerError,
    AnalysisError,
    InvalidDataError,
    ConfigurationError,
    NetworkError,
    APIError,
    DevirtualizationError,
    PluginError,
    GatewayError,
    ResourceLimitError,
    AnalysisTimeoutError,
    ValidationError,
)
from .pipeline import (
    AnalysisPipeline,
    PipelineConfig,
    PipelineResult,
    StageResult,
)
from .disassembler import (
    Disassembler,
    DisassembledInstruction,
    DisasmArchitecture,
    create_disassembler,
    from_pe,
    disassemble_section,
    to_lifted_instruction,
    to_lifted_instructions,
    CAPSTONE_AVAILABLE,
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
