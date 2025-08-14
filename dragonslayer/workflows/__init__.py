# VMDragonSlayer - Advanced VM detection and analysis library
# Copyright (C) 2025 van1sh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
Workflows Module
===============

Workflow and pipeline management for VMDragonSlayer.
Consolidates workflow functionality from workflow_integration.
"""

from .integration import (
    AnalysisEngineIntegration,
    BaseIntegration,
    ExternalToolIntegration,
    IntegrationConfig,
    IntegrationManager,
    IntegrationResult,
    IntegrationStatus,
    IntegrationType,
    create_binja_integration,
    create_ghidra_integration,
    create_ida_integration,
)
from .manager import (
    WorkflowContext,
    WorkflowJob,
    WorkflowManager,
    WorkflowMetrics,
    WorkflowResult,
    WorkflowStatus,
    create_malware_analysis_workflow,
    create_vm_analysis_workflow,
    quick_vm_scan,
)
from .pipeline import (
    Pipeline,
    PipelineConfig,
    PipelineExecutor,
    PipelineResult,
    PipelineStage,
    StageResult,
    create_analysis_pipeline,
    create_default_pipeline,
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
    "create_binja_integration",
]
