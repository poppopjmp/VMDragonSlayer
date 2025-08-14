"""
Workflows Module
===============

Workflow and pipeline management for VMDragonSlayer.
Consolidates workflow functionality from workflow_integration.
"""

from .pipeline import (
    Pipeline,
    PipelineConfig,
    PipelineStage,
    PipelineResult,
    StageResult,
    PipelineExecutor,
    create_default_pipeline,
    create_analysis_pipeline
)

from .manager import (
    WorkflowManager,
    WorkflowJob,
    WorkflowContext,
    WorkflowResult,
    WorkflowStatus,
    WorkflowMetrics,
    create_vm_analysis_workflow,
    create_malware_analysis_workflow,
    quick_vm_scan
)

from .integration import (
    IntegrationManager,
    BaseIntegration,
    AnalysisEngineIntegration,
    ExternalToolIntegration,
    IntegrationConfig,
    IntegrationResult,
    IntegrationType,
    IntegrationStatus,
    create_ghidra_integration,
    create_ida_integration,
    create_binja_integration
)

__all__ = [
    # Pipeline classes and functions
    "Pipeline",
    "PipelineConfig", 
    "PipelineStage",
    "PipelineResult",
    "StageResult",
    "PipelineExecutor",
    "create_default_pipeline",
    "create_analysis_pipeline",
    
    # Workflow manager classes and functions
    "WorkflowManager",
    "WorkflowJob",
    "WorkflowContext", 
    "WorkflowResult",
    "WorkflowStatus",
    "WorkflowMetrics",
    "create_vm_analysis_workflow",
    "create_malware_analysis_workflow",
    "quick_vm_scan",
    
    # Integration classes and functions
    "IntegrationManager",
    "BaseIntegration",
    "AnalysisEngineIntegration", 
    "ExternalToolIntegration",
    "IntegrationConfig",
    "IntegrationResult",
    "IntegrationType",
    "IntegrationStatus",
    "create_ghidra_integration",
    "create_ida_integration",
    "create_binja_integration"
]
