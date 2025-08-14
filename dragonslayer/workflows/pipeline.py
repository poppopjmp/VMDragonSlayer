"""
Analysis Pipeline
================

Core pipeline implementation for VMDragonSlayer analysis workflows.
Consolidates pipeline functionality from workflow_integration/pipeline_manager.py.
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class PipelineStage(Enum):
    """Pipeline stages for VM analysis"""
    PREPROCESSING = "preprocessing"
    VM_DETECTION = "vm_detection"
    TAINT_ANALYSIS = "taint_analysis"
    SYMBOLIC_EXECUTION = "symbolic_execution"
    PATTERN_ANALYSIS = "pattern_analysis"
    ML_ANALYSIS = "ml_analysis"
    POSTPROCESSING = "postprocessing"
    REPORTING = "reporting"


@dataclass
class PipelineConfig:
    """Configuration for analysis pipeline"""
    stages: List[str] = field(default_factory=lambda: [
        PipelineStage.PREPROCESSING.value,
        PipelineStage.VM_DETECTION.value,
        PipelineStage.PATTERN_ANALYSIS.value,
        PipelineStage.REPORTING.value
    ])
    parallel_execution: bool = False
    max_workers: int = 4
    timeout_per_stage: int = 300  # seconds
    error_handling: str = "fail_fast"  # "fail_fast" or "continue"
    output_format: str = "json"
    save_intermediate: bool = False
    
    def __post_init__(self):
        """Validate configuration"""
        if self.error_handling not in ["fail_fast", "continue"]:
            raise ValueError("error_handling must be 'fail_fast' or 'continue'")
        
        if self.output_format not in ["json", "xml", "yaml"]:
            raise ValueError("output_format must be 'json', 'xml', or 'yaml'")


@dataclass
class StageResult:
    """Result from a pipeline stage"""
    stage: str
    status: str  # "success", "failed", "skipped", "timeout"
    execution_time: float
    output_data: Dict[str, Any]
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_success(self) -> bool:
        """Check if stage was successful"""
        return self.status == "success"
    
    @property
    def is_failure(self) -> bool:
        """Check if stage failed"""
        return self.status in ["failed", "timeout"]


@dataclass
class PipelineResult:
    """Result from complete pipeline execution"""
    pipeline_id: str
    success: bool
    total_execution_time: float
    stage_results: List[StageResult]
    final_output: Dict[str, Any]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_stage_result(self, stage_name: str) -> Optional[StageResult]:
        """Get result for specific stage"""
        for result in self.stage_results:
            if result.stage == stage_name:
                return result
        return None
    
    def get_successful_stages(self) -> List[str]:
        """Get list of successful stage names"""
        return [r.stage for r in self.stage_results if r.is_success]
    
    def get_failed_stages(self) -> List[str]:
        """Get list of failed stage names"""
        return [r.stage for r in self.stage_results if r.is_failure]


class Pipeline:
    """
    Core pipeline for VMDragonSlayer analysis.
    Orchestrates execution of analysis stages in sequence or parallel.
    """
    
    def __init__(self, pipeline_id: str, config: PipelineConfig):
        """
        Initialize pipeline.
        
        Args:
            pipeline_id: Unique identifier for this pipeline
            config: Pipeline configuration
        """
        self.pipeline_id = pipeline_id
        self.config = config
        self.stage_handlers: Dict[str, Callable] = {}
        self.logger = logging.getLogger(f"{__name__}.Pipeline.{pipeline_id}")
        
        # Register default stage handlers
        self._register_default_handlers()
    
    def register_stage_handler(self, stage: str, handler: Callable) -> None:
        """
        Register a handler for a pipeline stage.
        
        Args:
            stage: Stage name
            handler: Callable that takes (input_data, metadata) and returns output_data
        """
        self.stage_handlers[stage] = handler
        self.logger.debug(f"Registered handler for stage: {stage}")
    
    def _register_default_handlers(self) -> None:
        """Register default handlers for standard stages"""
        
        def preprocessing_handler(input_data: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
            """Default preprocessing handler"""
            self.logger.info("Executing preprocessing stage")
            return {
                "preprocessed": True,
                "input_size": len(str(input_data)),
                "timestamp": time.time()
            }
        
        def vm_detection_handler(input_data: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
            """Default VM detection handler"""
            self.logger.info("Executing VM detection stage")
            return {
                "vm_detected": True,
                "vm_type": "unknown",
                "confidence": 0.5,
                "handlers_found": []
            }
        
        def pattern_analysis_handler(input_data: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
            """Default pattern analysis handler"""
            self.logger.info("Executing pattern analysis stage")
            return {
                "patterns_found": [],
                "pattern_count": 0,
                "analysis_complete": True
            }
        
        def reporting_handler(input_data: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
            """Default reporting handler"""
            self.logger.info("Executing reporting stage")
            return {
                "report_generated": True,
                "format": self.config.output_format,
                "timestamp": time.time()
            }
        
        # Register default handlers
        self.register_stage_handler(PipelineStage.PREPROCESSING.value, preprocessing_handler)
        self.register_stage_handler(PipelineStage.VM_DETECTION.value, vm_detection_handler)
        self.register_stage_handler(PipelineStage.PATTERN_ANALYSIS.value, pattern_analysis_handler)
        self.register_stage_handler(PipelineStage.REPORTING.value, reporting_handler)
    
    async def execute(self, input_data: Dict[str, Any]) -> PipelineResult:
        """
        Execute the complete pipeline.
        
        Args:
            input_data: Initial input data
            
        Returns:
            PipelineResult with execution results
        """
        start_time = time.time()
        stage_results = []
        current_data = input_data.copy()
        errors = []
        warnings = []
        
        self.logger.info(f"Starting pipeline execution: {self.pipeline_id}")
        
        try:
            if self.config.parallel_execution:
                stage_results = await self._execute_parallel(current_data)
            else:
                stage_results = await self._execute_sequential(current_data)
            
            # Check for failures
            failed_stages = [r for r in stage_results if r.is_failure]
            success = len(failed_stages) == 0
            
            if failed_stages:
                errors.extend([f"Stage {r.stage} failed: {r.error_message}" for r in failed_stages])
            
            # Collect warnings
            for result in stage_results:
                warnings.extend(result.warnings)
            
            # Create final output
            final_output = self._create_final_output(stage_results, current_data)
            
        except Exception as e:
            self.logger.error(f"Pipeline execution failed: {e}")
            success = False
            errors.append(str(e))
            final_output = {"error": str(e)}
        
        total_time = time.time() - start_time
        
        result = PipelineResult(
            pipeline_id=self.pipeline_id,
            success=success,
            total_execution_time=total_time,
            stage_results=stage_results,
            final_output=final_output,
            errors=errors,
            warnings=warnings,
            metadata={
                "config": self.config.__dict__,
                "execution_mode": "parallel" if self.config.parallel_execution else "sequential"
            }
        )
        
        self.logger.info(f"Pipeline completed: success={success}, time={total_time:.2f}s")
        return result
    
    async def _execute_sequential(self, input_data: Dict[str, Any]) -> List[StageResult]:
        """Execute stages sequentially"""
        results = []
        current_data = input_data.copy()
        
        for stage_name in self.config.stages:
            result = await self._execute_stage(stage_name, current_data, {})
            results.append(result)
            
            # Handle stage failure
            if result.is_failure and self.config.error_handling == "fail_fast":
                self.logger.error(f"Stage {stage_name} failed, stopping pipeline")
                break
            
            # Update data for next stage
            if result.is_success:
                current_data.update(result.output_data)
        
        return results
    
    async def _execute_parallel(self, input_data: Dict[str, Any]) -> List[StageResult]:
        """Execute stages in parallel (where possible)"""
        # For now, implement as sequential since stages typically depend on each other
        # In a full implementation, you'd analyze dependencies and parallelize independent stages
        self.logger.warning("Parallel execution not fully implemented, falling back to sequential")
        return await self._execute_sequential(input_data)
    
    async def _execute_stage(self, stage_name: str, input_data: Dict[str, Any], 
                           metadata: Dict[str, Any]) -> StageResult:
        """Execute a single pipeline stage"""
        start_time = time.time()
        
        try:
            # Get stage handler
            handler = self.stage_handlers.get(stage_name)
            if not handler:
                return StageResult(
                    stage=stage_name,
                    status="failed",
                    execution_time=time.time() - start_time,
                    output_data={},
                    error_message=f"No handler registered for stage: {stage_name}"
                )
            
            self.logger.debug(f"Executing stage: {stage_name}")
            
            # Execute with timeout
            try:
                output_data = await asyncio.wait_for(
                    self._run_handler(handler, input_data, metadata),
                    timeout=self.config.timeout_per_stage
                )
                
                execution_time = time.time() - start_time
                
                return StageResult(
                    stage=stage_name,
                    status="success",
                    execution_time=execution_time,
                    output_data=output_data or {},
                    metadata={"handler": handler.__name__}
                )
                
            except asyncio.TimeoutError:
                return StageResult(
                    stage=stage_name,
                    status="timeout",
                    execution_time=self.config.timeout_per_stage,
                    output_data={},
                    error_message=f"Stage timed out after {self.config.timeout_per_stage}s"
                )
        
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Stage {stage_name} failed: {e}")
            
            return StageResult(
                stage=stage_name,
                status="failed",
                execution_time=execution_time,
                output_data={},
                error_message=str(e)
            )
    
    async def _run_handler(self, handler: Callable, input_data: Dict[str, Any], 
                          metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Run a stage handler, handling both sync and async handlers"""
        if asyncio.iscoroutinefunction(handler):
            return await handler(input_data, metadata)
        else:
            # Run sync handler in thread pool
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, handler, input_data, metadata)
    
    def _create_final_output(self, stage_results: List[StageResult], 
                           initial_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create final pipeline output"""
        output = {
            "pipeline_id": self.pipeline_id,
            "stages_executed": len(stage_results),
            "successful_stages": len([r for r in stage_results if r.is_success]),
            "failed_stages": len([r for r in stage_results if r.is_failure]),
            "total_warnings": sum(len(r.warnings) for r in stage_results)
        }
        
        # Aggregate outputs from successful stages
        for result in stage_results:
            if result.is_success:
                output[f"{result.stage}_output"] = result.output_data
        
        return output


class PipelineExecutor:
    """
    High-level pipeline executor that manages multiple pipelines.
    """
    
    def __init__(self):
        self.pipelines: Dict[str, Pipeline] = {}
        self.logger = logging.getLogger(f"{__name__}.PipelineExecutor")
    
    def create_pipeline(self, pipeline_id: str, config: PipelineConfig) -> Pipeline:
        """
        Create a new pipeline.
        
        Args:
            pipeline_id: Unique pipeline identifier
            config: Pipeline configuration
            
        Returns:
            Created Pipeline instance
        """
        pipeline = Pipeline(pipeline_id, config)
        self.pipelines[pipeline_id] = pipeline
        self.logger.info(f"Created pipeline: {pipeline_id}")
        return pipeline
    
    def get_pipeline(self, pipeline_id: str) -> Optional[Pipeline]:
        """Get pipeline by ID"""
        return self.pipelines.get(pipeline_id)
    
    async def execute_pipeline(self, pipeline_id: str, input_data: Dict[str, Any]) -> PipelineResult:
        """
        Execute a pipeline by ID.
        
        Args:
            pipeline_id: Pipeline identifier
            input_data: Input data for pipeline
            
        Returns:
            PipelineResult
        """
        pipeline = self.get_pipeline(pipeline_id)
        if not pipeline:
            raise ValueError(f"Pipeline not found: {pipeline_id}")
        
        return await pipeline.execute(input_data)
    
    def list_pipelines(self) -> List[str]:
        """List all pipeline IDs"""
        return list(self.pipelines.keys())
    
    def remove_pipeline(self, pipeline_id: str) -> bool:
        """Remove a pipeline"""
        if pipeline_id in self.pipelines:
            del self.pipelines[pipeline_id]
            self.logger.info(f"Removed pipeline: {pipeline_id}")
            return True
        return False


# Convenience functions
def create_default_pipeline(pipeline_id: str = "default") -> Pipeline:
    """Create a pipeline with default configuration"""
    config = PipelineConfig()
    return Pipeline(pipeline_id, config)


def create_analysis_pipeline(binary_path: str, analysis_types: List[str] = None) -> Pipeline:
    """
    Create a pipeline configured for binary analysis.
    
    Args:
        binary_path: Path to binary file
        analysis_types: List of analysis types to include
        
    Returns:
        Configured Pipeline instance
    """
    if analysis_types is None:
        analysis_types = ["vm_detection", "pattern_analysis"]
    
    stages = ["preprocessing"] + analysis_types + ["reporting"]
    
    config = PipelineConfig(
        stages=stages,
        timeout_per_stage=600,  # Longer timeout for analysis
        error_handling="continue"  # Continue on errors for analysis
    )
    
    pipeline_id = f"analysis_{int(time.time())}"
    pipeline = Pipeline(pipeline_id, config)
    
    # Add binary path to pipeline metadata
    pipeline.binary_path = binary_path
    
    return pipeline
