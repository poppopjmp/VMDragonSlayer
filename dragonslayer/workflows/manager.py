"""
Workflow Manager
===============

Manages workflow execution and coordination for VMDragonSlayer.
Consolidates workflow management functionality from workflow_integration.
"""

import asyncio
import logging
import time
import threading
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from .pipeline import Pipeline, PipelineConfig, PipelineResult

logger = logging.getLogger(__name__)


class WorkflowStatus(Enum):
    """Workflow execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"


@dataclass
class WorkflowMetrics:
    """Workflow execution metrics"""
    start_time: float
    end_time: Optional[float] = None
    execution_time: Optional[float] = None
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    stages_completed: int = 0
    total_stages: int = 0
    
    @property
    def is_complete(self) -> bool:
        """Check if workflow is complete"""
        return self.end_time is not None
    
    @property
    def progress_percent(self) -> float:
        """Calculate progress percentage"""
        if self.total_stages == 0:
            return 0.0
        return (self.stages_completed / self.total_stages) * 100.0


@dataclass
class WorkflowContext:
    """Context for workflow execution"""
    workflow_id: str
    name: str
    input_data: Dict[str, Any]
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Set[str] = field(default_factory=set)
    
    def add_tag(self, tag: str) -> None:
        """Add a tag to the workflow"""
        self.tags.add(tag)
    
    def has_tag(self, tag: str) -> bool:
        """Check if workflow has a tag"""
        return tag in self.tags


@dataclass
class WorkflowResult:
    """Result from workflow execution"""
    workflow_id: str
    status: WorkflowStatus
    pipeline_results: List[PipelineResult]
    final_output: Dict[str, Any]
    metrics: WorkflowMetrics
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    @property
    def is_success(self) -> bool:
        """Check if workflow was successful"""
        return self.status == WorkflowStatus.COMPLETED and len(self.errors) == 0
    
    def get_pipeline_result(self, pipeline_id: str) -> Optional[PipelineResult]:
        """Get result for specific pipeline"""
        for result in self.pipeline_results:
            if result.pipeline_id == pipeline_id:
                return result
        return None


class WorkflowJob:
    """
    Represents a workflow job that can be executed.
    """
    
    def __init__(self, context: WorkflowContext, pipelines: List[Pipeline]):
        """
        Initialize workflow job.
        
        Args:
            context: Workflow context
            pipelines: List of pipelines to execute
        """
        self.context = context
        self.pipelines = pipelines
        self.status = WorkflowStatus.PENDING
        self.metrics = WorkflowMetrics(start_time=time.time())
        self.pipeline_results: List[PipelineResult] = []
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.logger = logging.getLogger(f"{__name__}.WorkflowJob.{context.workflow_id}")
        
        # Update metrics
        self.metrics.total_stages = sum(len(p.config.stages) for p in pipelines)
    
    async def execute(self) -> WorkflowResult:
        """Execute the workflow job"""
        self.status = WorkflowStatus.RUNNING
        self.logger.info(f"Starting workflow execution: {self.context.workflow_id}")
        
        try:
            # Execute pipelines
            current_data = self.context.input_data.copy()
            
            for pipeline in self.pipelines:
                self.logger.debug(f"Executing pipeline: {pipeline.pipeline_id}")
                
                # Execute pipeline
                pipeline_result = await pipeline.execute(current_data)
                self.pipeline_results.append(pipeline_result)
                
                # Update metrics
                self.metrics.stages_completed += len(pipeline_result.stage_results)
                
                # Collect errors and warnings
                self.errors.extend(pipeline_result.errors)
                self.warnings.extend(pipeline_result.warnings)
                
                # Update data for next pipeline
                if pipeline_result.success:
                    current_data.update(pipeline_result.final_output)
                else:
                    self.logger.warning(f"Pipeline {pipeline.pipeline_id} failed")
            
            # Determine final status
            if any(not r.success for r in self.pipeline_results):
                self.status = WorkflowStatus.FAILED
            else:
                self.status = WorkflowStatus.COMPLETED
            
        except Exception as e:
            self.logger.error(f"Workflow execution failed: {e}")
            self.status = WorkflowStatus.FAILED
            self.errors.append(str(e))
            current_data = {}
        
        # Finalize metrics
        self.metrics.end_time = time.time()
        self.metrics.execution_time = self.metrics.end_time - self.metrics.start_time
        
        result = WorkflowResult(
            workflow_id=self.context.workflow_id,
            status=self.status,
            pipeline_results=self.pipeline_results,
            final_output=current_data,
            metrics=self.metrics,
            errors=self.errors,
            warnings=self.warnings
        )
        
        self.logger.info(f"Workflow completed: {self.context.workflow_id} - {self.status.value}")
        return result


class WorkflowManager:
    """
    Manages workflow execution and coordination.
    Provides high-level interface for creating and executing workflows.
    """
    
    def __init__(self, max_concurrent_workflows: int = 4):
        """
        Initialize workflow manager.
        
        Args:
            max_concurrent_workflows: Maximum number of concurrent workflows
        """
        self.max_concurrent_workflows = max_concurrent_workflows
        self.active_workflows: Dict[str, WorkflowJob] = {}
        self.completed_workflows: Dict[str, WorkflowResult] = {}
        self.workflow_templates: Dict[str, Callable] = {}
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent_workflows)
        self.logger = logging.getLogger(f"{__name__}.WorkflowManager")
        self._lock = threading.Lock()
        
        # Register default templates
        self._register_default_templates()
    
    def register_template(self, name: str, template_func: Callable) -> None:
        """
        Register a workflow template.
        
        Args:
            name: Template name
            template_func: Function that returns (context, pipelines) tuple
        """
        self.workflow_templates[name] = template_func
        self.logger.debug(f"Registered workflow template: {name}")
    
    def _register_default_templates(self) -> None:
        """Register default workflow templates"""
        
        def vm_analysis_template(binary_path: str, **kwargs) -> tuple:
            """Template for VM analysis workflow"""
            workflow_id = f"vm_analysis_{uuid.uuid4().hex[:8]}"
            
            context = WorkflowContext(
                workflow_id=workflow_id,
                name="VM Analysis",
                input_data={"binary_path": binary_path, **kwargs}
            )
            context.add_tag("vm_analysis")
            context.add_tag("binary_analysis")
            
            # Create pipeline for VM analysis
            config = PipelineConfig(
                stages=["preprocessing", "vm_detection", "pattern_analysis", "reporting"],
                timeout_per_stage=300,
                error_handling="continue"
            )
            
            pipeline = Pipeline(f"{workflow_id}_pipeline", config)
            
            return context, [pipeline]
        
        def malware_analysis_template(binary_path: str, **kwargs) -> tuple:
            """Template for malware analysis workflow"""
            workflow_id = f"malware_analysis_{uuid.uuid4().hex[:8]}"
            
            context = WorkflowContext(
                workflow_id=workflow_id,
                name="Malware Analysis",
                input_data={"binary_path": binary_path, **kwargs}
            )
            context.add_tag("malware_analysis")
            context.add_tag("security_analysis")
            
            # Create comprehensive analysis pipeline
            config = PipelineConfig(
                stages=[
                    "preprocessing", 
                    "vm_detection", 
                    "taint_analysis", 
                    "symbolic_execution",
                    "pattern_analysis", 
                    "ml_analysis",
                    "reporting"
                ],
                timeout_per_stage=600,
                error_handling="continue"
            )
            
            pipeline = Pipeline(f"{workflow_id}_pipeline", config)
            
            return context, [pipeline]
        
        def quick_scan_template(binary_path: str, **kwargs) -> tuple:
            """Template for quick scan workflow"""
            workflow_id = f"quick_scan_{uuid.uuid4().hex[:8]}"
            
            context = WorkflowContext(
                workflow_id=workflow_id,
                name="Quick Scan",
                input_data={"binary_path": binary_path, **kwargs}
            )
            context.add_tag("quick_scan")
            context.add_tag("fast_analysis")
            
            # Create minimal pipeline for quick analysis
            config = PipelineConfig(
                stages=["preprocessing", "vm_detection", "reporting"],
                timeout_per_stage=60,
                error_handling="fail_fast"
            )
            
            pipeline = Pipeline(f"{workflow_id}_pipeline", config)
            
            return context, [pipeline]
        
        # Register templates
        self.register_template("vm_analysis", vm_analysis_template)
        self.register_template("malware_analysis", malware_analysis_template)
        self.register_template("quick_scan", quick_scan_template)
    
    def create_workflow(self, template_name: str, **kwargs) -> str:
        """
        Create a workflow from a template.
        
        Args:
            template_name: Name of registered template
            **kwargs: Template arguments
            
        Returns:
            Workflow ID
        """
        template = self.workflow_templates.get(template_name)
        if not template:
            raise ValueError(f"Unknown workflow template: {template_name}")
        
        try:
            context, pipelines = template(**kwargs)
            
            with self._lock:
                # Check if we have capacity
                if len(self.active_workflows) >= self.max_concurrent_workflows:
                    raise RuntimeError("Maximum concurrent workflows reached")
                
                # Create workflow job
                job = WorkflowJob(context, pipelines)
                self.active_workflows[context.workflow_id] = job
                
                self.logger.info(f"Created workflow: {context.workflow_id} ({template_name})")
                return context.workflow_id
        
        except Exception as e:
            self.logger.error(f"Failed to create workflow from template {template_name}: {e}")
            raise
    
    def create_custom_workflow(self, name: str, pipelines: List[Pipeline], 
                             input_data: Dict[str, Any] = None, **kwargs) -> str:
        """
        Create a custom workflow.
        
        Args:
            name: Workflow name
            pipelines: List of pipelines to execute
            input_data: Initial input data
            **kwargs: Additional context data
            
        Returns:
            Workflow ID
        """
        workflow_id = f"custom_{uuid.uuid4().hex[:8]}"
        
        context = WorkflowContext(
            workflow_id=workflow_id,
            name=name,
            input_data=input_data or {},
            config=kwargs.get("config", {}),
            metadata=kwargs.get("metadata", {})
        )
        
        # Add tags
        for tag in kwargs.get("tags", []):
            context.add_tag(tag)
        
        with self._lock:
            if len(self.active_workflows) >= self.max_concurrent_workflows:
                raise RuntimeError("Maximum concurrent workflows reached")
            
            job = WorkflowJob(context, pipelines)
            self.active_workflows[workflow_id] = job
            
            self.logger.info(f"Created custom workflow: {workflow_id}")
            return workflow_id
    
    async def execute_workflow(self, workflow_id: str) -> WorkflowResult:
        """
        Execute a workflow.
        
        Args:
            workflow_id: Workflow identifier
            
        Returns:
            WorkflowResult
        """
        with self._lock:
            job = self.active_workflows.get(workflow_id)
            if not job:
                raise ValueError(f"Workflow not found: {workflow_id}")
        
        try:
            # Execute workflow
            result = await job.execute()
            
            # Move to completed workflows
            with self._lock:
                del self.active_workflows[workflow_id]
                self.completed_workflows[workflow_id] = result
            
            return result
        
        except Exception as e:
            self.logger.error(f"Workflow execution failed: {workflow_id} - {e}")
            # Clean up
            with self._lock:
                if workflow_id in self.active_workflows:
                    del self.active_workflows[workflow_id]
            raise
    
    async def execute_workflow_template(self, template_name: str, **kwargs) -> WorkflowResult:
        """
        Create and execute a workflow from template in one call.
        
        Args:
            template_name: Template name
            **kwargs: Template arguments
            
        Returns:
            WorkflowResult
        """
        workflow_id = self.create_workflow(template_name, **kwargs)
        return await self.execute_workflow(workflow_id)
    
    def get_workflow_status(self, workflow_id: str) -> Optional[WorkflowStatus]:
        """Get workflow status"""
        with self._lock:
            # Check active workflows
            job = self.active_workflows.get(workflow_id)
            if job:
                return job.status
            
            # Check completed workflows
            result = self.completed_workflows.get(workflow_id)
            if result:
                return result.status
        
        return None
    
    def get_workflow_result(self, workflow_id: str) -> Optional[WorkflowResult]:
        """Get workflow result"""
        with self._lock:
            return self.completed_workflows.get(workflow_id)
    
    def list_active_workflows(self) -> List[str]:
        """List active workflow IDs"""
        with self._lock:
            return list(self.active_workflows.keys())
    
    def list_completed_workflows(self) -> List[str]:
        """List completed workflow IDs"""
        with self._lock:
            return list(self.completed_workflows.keys())
    
    def cancel_workflow(self, workflow_id: str) -> bool:
        """
        Cancel a workflow.
        
        Args:
            workflow_id: Workflow identifier
            
        Returns:
            True if cancelled, False if not found or already completed
        """
        with self._lock:
            job = self.active_workflows.get(workflow_id)
            if job and job.status in [WorkflowStatus.PENDING, WorkflowStatus.RUNNING]:
                job.status = WorkflowStatus.CANCELLED
                self.logger.info(f"Cancelled workflow: {workflow_id}")
                return True
        
        return False
    
    def get_workflow_metrics(self, workflow_id: str) -> Optional[WorkflowMetrics]:
        """Get workflow execution metrics"""
        with self._lock:
            # Check active workflows
            job = self.active_workflows.get(workflow_id)
            if job:
                return job.metrics
            
            # Check completed workflows
            result = self.completed_workflows.get(workflow_id)
            if result:
                return result.metrics
        
        return None
    
    def cleanup_completed_workflows(self, keep_recent: int = 100) -> int:
        """
        Clean up old completed workflows.
        
        Args:
            keep_recent: Number of recent workflows to keep
            
        Returns:
            Number of workflows cleaned up
        """
        with self._lock:
            if len(self.completed_workflows) <= keep_recent:
                return 0
            
            # Sort by completion time and keep most recent
            sorted_workflows = sorted(
                self.completed_workflows.items(),
                key=lambda x: x[1].metrics.end_time or 0,
                reverse=True
            )
            
            to_keep = dict(sorted_workflows[:keep_recent])
            cleaned_count = len(self.completed_workflows) - len(to_keep)
            
            self.completed_workflows = to_keep
            
            self.logger.info(f"Cleaned up {cleaned_count} completed workflows")
            return cleaned_count
    
    def shutdown(self) -> None:
        """Shutdown the workflow manager"""
        with self._lock:
            # Cancel all active workflows
            for workflow_id in list(self.active_workflows.keys()):
                self.cancel_workflow(workflow_id)
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        self.logger.info("Workflow manager shutdown complete")


# Convenience functions
def create_vm_analysis_workflow(binary_path: str) -> str:
    """Create a VM analysis workflow"""
    manager = WorkflowManager()
    return manager.create_workflow("vm_analysis", binary_path=binary_path)


def create_malware_analysis_workflow(binary_path: str) -> str:
    """Create a malware analysis workflow"""
    manager = WorkflowManager()
    return manager.create_workflow("malware_analysis", binary_path=binary_path)


async def quick_vm_scan(binary_path: str) -> WorkflowResult:
    """Perform a quick VM scan"""
    manager = WorkflowManager()
    return await manager.execute_workflow_template("quick_scan", binary_path=binary_path)
