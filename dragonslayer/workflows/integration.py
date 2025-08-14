"""
Integration Module
=================

Handles integration between different analysis engines and external tools.
Consolidates integration functionality from workflow_integration.
"""

import asyncio
import logging
import subprocess
import time
import json
import tempfile
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
import threading

logger = logging.getLogger(__name__)


class IntegrationType(Enum):
    """Types of integrations supported"""
    ANALYSIS_ENGINE = "analysis_engine"
    EXTERNAL_TOOL = "external_tool"
    API_SERVICE = "api_service"
    DATABASE = "database"
    MESSAGING = "messaging"


class IntegrationStatus(Enum):
    """Integration status"""
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass
class IntegrationConfig:
    """Configuration for an integration"""
    name: str
    type: IntegrationType
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    health_check_interval: int = 300  # seconds
    timeout: int = 30  # seconds
    retry_attempts: int = 3
    retry_delay: float = 1.0  # seconds
    
    def __post_init__(self):
        """Validate configuration"""
        if self.health_check_interval < 0:
            raise ValueError("health_check_interval must be non-negative")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")
        if self.retry_attempts < 0:
            raise ValueError("retry_attempts must be non-negative")


@dataclass
class IntegrationResult:
    """Result from integration operation"""
    integration_name: str
    success: bool
    data: Dict[str, Any]
    execution_time: float
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_success(self) -> bool:
        """Check if operation was successful"""
        return self.success and self.error_message is None


class BaseIntegration:
    """
    Base class for all integrations.
    """
    
    def __init__(self, config: IntegrationConfig):
        """
        Initialize integration.
        
        Args:
            config: Integration configuration
        """
        self.config = config
        self.status = IntegrationStatus.UNKNOWN
        self.last_health_check = 0.0
        self.logger = logging.getLogger(f"{__name__}.{config.name}")
        self._lock = threading.Lock()
    
    async def initialize(self) -> bool:
        """Initialize the integration"""
        try:
            self.logger.info(f"Initializing integration: {self.config.name}")
            success = await self._initialize_impl()
            
            if success:
                self.status = IntegrationStatus.AVAILABLE
                self.logger.info(f"Integration initialized: {self.config.name}")
            else:
                self.status = IntegrationStatus.ERROR
                self.logger.error(f"Integration initialization failed: {self.config.name}")
            
            return success
        
        except Exception as e:
            self.logger.error(f"Integration initialization error: {self.config.name} - {e}")
            self.status = IntegrationStatus.ERROR
            return False
    
    async def _initialize_impl(self) -> bool:
        """Implementation-specific initialization"""
        return True
    
    async def health_check(self) -> bool:
        """Check if integration is healthy"""
        try:
            with self._lock:
                current_time = time.time()
                if (current_time - self.last_health_check) < self.config.health_check_interval:
                    return self.status == IntegrationStatus.AVAILABLE
                
                self.last_health_check = current_time
            
            # Perform health check
            healthy = await self._health_check_impl()
            
            with self._lock:
                if healthy:
                    self.status = IntegrationStatus.AVAILABLE
                else:
                    self.status = IntegrationStatus.UNAVAILABLE
            
            return healthy
        
        except Exception as e:
            self.logger.error(f"Health check failed: {self.config.name} - {e}")
            with self._lock:
                self.status = IntegrationStatus.ERROR
            return False
    
    async def _health_check_impl(self) -> bool:
        """Implementation-specific health check"""
        return True
    
    async def execute(self, operation: str, **kwargs) -> IntegrationResult:
        """
        Execute an operation with retry logic.
        
        Args:
            operation: Operation name
            **kwargs: Operation parameters
            
        Returns:
            IntegrationResult
        """
        start_time = time.time()
        last_error = None
        
        for attempt in range(self.config.retry_attempts + 1):
            try:
                if attempt > 0:
                    await asyncio.sleep(self.config.retry_delay * attempt)
                
                # Check if integration is available
                if not await self.health_check():
                    raise RuntimeError(f"Integration {self.config.name} is not available")
                
                # Execute operation with timeout
                result_data = await asyncio.wait_for(
                    self._execute_impl(operation, **kwargs),
                    timeout=self.config.timeout
                )
                
                execution_time = time.time() - start_time
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    success=True,
                    data=result_data or {},
                    execution_time=execution_time,
                    metadata={"attempts": attempt + 1}
                )
            
            except asyncio.TimeoutError:
                last_error = f"Operation timed out after {self.config.timeout}s"
                self.logger.warning(f"Attempt {attempt + 1} timed out: {self.config.name}")
            
            except Exception as e:
                last_error = str(e)
                self.logger.warning(f"Attempt {attempt + 1} failed: {self.config.name} - {e}")
        
        # All attempts failed
        execution_time = time.time() - start_time
        
        return IntegrationResult(
            integration_name=self.config.name,
            success=False,
            data={},
            execution_time=execution_time,
            error_message=last_error,
            metadata={"attempts": self.config.retry_attempts + 1}
        )
    
    async def _execute_impl(self, operation: str, **kwargs) -> Dict[str, Any]:
        """Implementation-specific operation execution"""
        raise NotImplementedError("Subclasses must implement _execute_impl")
    
    async def shutdown(self) -> None:
        """Shutdown the integration"""
        try:
            await self._shutdown_impl()
            self.status = IntegrationStatus.UNAVAILABLE
            self.logger.info(f"Integration shutdown: {self.config.name}")
        except Exception as e:
            self.logger.error(f"Integration shutdown error: {self.config.name} - {e}")
    
    async def _shutdown_impl(self) -> None:
        """Implementation-specific shutdown"""
        pass


class AnalysisEngineIntegration(BaseIntegration):
    """
    Integration with analysis engines (Ghidra, IDA Pro, Binary Ninja).
    """
    
    def __init__(self, config: IntegrationConfig):
        super().__init__(config)
        self.engine_path = config.config.get("engine_path")
        self.scripts_path = config.config.get("scripts_path")
        self.working_dir = config.config.get("working_dir", tempfile.gettempdir())
    
    async def _initialize_impl(self) -> bool:
        """Initialize analysis engine"""
        if not self.engine_path or not Path(self.engine_path).exists():
            self.logger.error(f"Engine path not found: {self.engine_path}")
            return False
        
        return True
    
    async def _health_check_impl(self) -> bool:
        """Check if analysis engine is available"""
        if not self.engine_path:
            return False
        
        try:
            # Try to run engine with version flag
            process = await asyncio.create_subprocess_exec(
                self.engine_path, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await asyncio.wait_for(process.wait(), timeout=10.0)
            return process.returncode == 0
        
        except Exception:
            return False
    
    async def _execute_impl(self, operation: str, **kwargs) -> Dict[str, Any]:
        """Execute analysis engine operation"""
        if operation == "analyze_binary":
            return await self._analyze_binary(**kwargs)
        elif operation == "run_script":
            return await self._run_script(**kwargs)
        else:
            raise ValueError(f"Unknown operation: {operation}")
    
    async def _analyze_binary(self, binary_path: str, output_format: str = "json", **kwargs) -> Dict[str, Any]:
        """Analyze binary with engine"""
        self.logger.info(f"Analyzing binary: {binary_path}")
        
        # Create temporary output file
        with tempfile.NamedTemporaryFile(mode='w', suffix=f'.{output_format}', delete=False) as temp_file:
            output_path = temp_file.name
        
        try:
            # Build command
            cmd = [
                self.engine_path,
                "-import", binary_path,
                "-postScript", f"export:{output_path}",
                "-deleteProject"
            ]
            
            # Add additional arguments
            for key, value in kwargs.items():
                cmd.extend([f"-{key}", str(value)])
            
            # Execute command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.working_dir
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise RuntimeError(f"Analysis failed: {stderr.decode()}")
            
            # Read results
            if Path(output_path).exists():
                with open(output_path, 'r') as f:
                    if output_format == "json":
                        results = json.load(f)
                    else:
                        results = {"output": f.read()}
            else:
                results = {"output": stdout.decode()}
            
            return {
                "results": results,
                "stdout": stdout.decode(),
                "stderr": stderr.decode(),
                "returncode": process.returncode
            }
        
        finally:
            # Clean up temporary file
            if Path(output_path).exists():
                Path(output_path).unlink()
    
    async def _run_script(self, script_path: str, binary_path: str = None, **kwargs) -> Dict[str, Any]:
        """Run analysis script"""
        self.logger.info(f"Running script: {script_path}")
        
        if not Path(script_path).exists():
            raise FileNotFoundError(f"Script not found: {script_path}")
        
        # Build command
        cmd = [self.engine_path]
        
        if binary_path:
            cmd.extend(["-import", binary_path])
        
        cmd.extend(["-scriptPath", str(Path(script_path).parent)])
        cmd.extend(["-postScript", Path(script_path).name])
        
        if binary_path:
            cmd.append("-deleteProject")
        
        # Execute command
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.working_dir
        )
        
        stdout, stderr = await process.communicate()
        
        return {
            "stdout": stdout.decode(),
            "stderr": stderr.decode(),
            "returncode": process.returncode,
            "success": process.returncode == 0
        }


class ExternalToolIntegration(BaseIntegration):
    """
    Integration with external command-line tools.
    """
    
    def __init__(self, config: IntegrationConfig):
        super().__init__(config)
        self.tool_path = config.config.get("tool_path")
        self.default_args = config.config.get("default_args", [])
    
    async def _initialize_impl(self) -> bool:
        """Initialize external tool"""
        if not self.tool_path:
            self.logger.error("Tool path not specified")
            return False
        
        # Check if tool exists
        if not Path(self.tool_path).exists():
            # Try to find in PATH
            try:
                process = await asyncio.create_subprocess_exec(
                    "which", self.tool_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                
                if process.returncode == 0:
                    self.tool_path = stdout.decode().strip()
                    return True
            except Exception:
                pass
            
            self.logger.error(f"Tool not found: {self.tool_path}")
            return False
        
        return True
    
    async def _health_check_impl(self) -> bool:
        """Check if external tool is available"""
        try:
            process = await asyncio.create_subprocess_exec(
                self.tool_path, "--help",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await asyncio.wait_for(process.wait(), timeout=5.0)
            return True
        
        except Exception:
            return False
    
    async def _execute_impl(self, operation: str, **kwargs) -> Dict[str, Any]:
        """Execute external tool operation"""
        if operation == "run":
            return await self._run_tool(**kwargs)
        else:
            raise ValueError(f"Unknown operation: {operation}")
    
    async def _run_tool(self, args: List[str] = None, input_data: str = None, **kwargs) -> Dict[str, Any]:
        """Run external tool"""
        cmd = [self.tool_path] + self.default_args
        
        if args:
            cmd.extend(args)
        
        self.logger.debug(f"Running command: {' '.join(cmd)}")
        
        # Create process
        if input_data:
            stdin = asyncio.subprocess.PIPE
        else:
            stdin = None
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=stdin,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Communicate with process
        if input_data:
            stdout, stderr = await process.communicate(input_data.encode())
        else:
            stdout, stderr = await process.communicate()
        
        return {
            "stdout": stdout.decode(),
            "stderr": stderr.decode(),
            "returncode": process.returncode,
            "success": process.returncode == 0
        }


class IntegrationManager:
    """
    Manages all integrations for VMDragonSlayer.
    """
    
    def __init__(self):
        """Initialize integration manager"""
        self.integrations: Dict[str, BaseIntegration] = {}
        self.logger = logging.getLogger(f"{__name__}.IntegrationManager")
        self._lock = threading.Lock()
    
    def register_integration(self, integration: BaseIntegration) -> None:
        """
        Register an integration.
        
        Args:
            integration: Integration instance
        """
        with self._lock:
            self.integrations[integration.config.name] = integration
        
        self.logger.info(f"Registered integration: {integration.config.name}")
    
    def create_analysis_engine_integration(self, name: str, engine_path: str, 
                                         scripts_path: str = None, **config) -> BaseIntegration:
        """
        Create and register an analysis engine integration.
        
        Args:
            name: Integration name
            engine_path: Path to analysis engine executable
            scripts_path: Path to analysis scripts
            **config: Additional configuration
            
        Returns:
            Created integration
        """
        integration_config = IntegrationConfig(
            name=name,
            type=IntegrationType.ANALYSIS_ENGINE,
            config={
                "engine_path": engine_path,
                "scripts_path": scripts_path,
                **config
            }
        )
        
        integration = AnalysisEngineIntegration(integration_config)
        self.register_integration(integration)
        return integration
    
    def create_external_tool_integration(self, name: str, tool_path: str, 
                                       default_args: List[str] = None, **config) -> BaseIntegration:
        """
        Create and register an external tool integration.
        
        Args:
            name: Integration name
            tool_path: Path to external tool
            default_args: Default arguments for tool
            **config: Additional configuration
            
        Returns:
            Created integration
        """
        integration_config = IntegrationConfig(
            name=name,
            type=IntegrationType.EXTERNAL_TOOL,
            config={
                "tool_path": tool_path,
                "default_args": default_args or [],
                **config
            }
        )
        
        integration = ExternalToolIntegration(integration_config)
        self.register_integration(integration)
        return integration
    
    async def initialize_all(self) -> Dict[str, bool]:
        """
        Initialize all registered integrations.
        
        Returns:
            Dictionary mapping integration names to initialization success
        """
        results = {}
        
        for name, integration in self.integrations.items():
            if integration.config.enabled:
                try:
                    success = await integration.initialize()
                    results[name] = success
                except Exception as e:
                    self.logger.error(f"Failed to initialize {name}: {e}")
                    results[name] = False
            else:
                results[name] = True  # Disabled integrations are considered "successful"
        
        return results
    
    async def health_check_all(self) -> Dict[str, IntegrationStatus]:
        """
        Perform health check on all integrations.
        
        Returns:
            Dictionary mapping integration names to status
        """
        results = {}
        
        for name, integration in self.integrations.items():
            if integration.config.enabled:
                try:
                    healthy = await integration.health_check()
                    results[name] = integration.status
                except Exception as e:
                    self.logger.error(f"Health check failed for {name}: {e}")
                    results[name] = IntegrationStatus.ERROR
            else:
                results[name] = IntegrationStatus.UNAVAILABLE
        
        return results
    
    async def execute_integration(self, name: str, operation: str, **kwargs) -> IntegrationResult:
        """
        Execute operation on specific integration.
        
        Args:
            name: Integration name
            operation: Operation to execute
            **kwargs: Operation parameters
            
        Returns:
            IntegrationResult
        """
        integration = self.integrations.get(name)
        if not integration:
            return IntegrationResult(
                integration_name=name,
                success=False,
                data={},
                execution_time=0.0,
                error_message=f"Integration not found: {name}"
            )
        
        if not integration.config.enabled:
            return IntegrationResult(
                integration_name=name,
                success=False,
                data={},
                execution_time=0.0,
                error_message=f"Integration disabled: {name}"
            )
        
        return await integration.execute(operation, **kwargs)
    
    def get_integration(self, name: str) -> Optional[BaseIntegration]:
        """Get integration by name"""
        return self.integrations.get(name)
    
    def list_integrations(self) -> List[str]:
        """List all integration names"""
        return list(self.integrations.keys())
    
    def get_integration_status(self, name: str) -> Optional[IntegrationStatus]:
        """Get integration status"""
        integration = self.integrations.get(name)
        return integration.status if integration else None
    
    async def shutdown_all(self) -> None:
        """Shutdown all integrations"""
        for integration in self.integrations.values():
            try:
                await integration.shutdown()
            except Exception as e:
                self.logger.error(f"Error shutting down {integration.config.name}: {e}")
        
        self.logger.info("All integrations shutdown")


# Convenience functions
def create_ghidra_integration(ghidra_path: str, scripts_path: str = None) -> BaseIntegration:
    """Create Ghidra integration"""
    manager = IntegrationManager()
    return manager.create_analysis_engine_integration(
        "ghidra",
        ghidra_path,
        scripts_path
    )


def create_ida_integration(ida_path: str, scripts_path: str = None) -> BaseIntegration:
    """Create IDA Pro integration"""
    manager = IntegrationManager()
    return manager.create_analysis_engine_integration(
        "ida",
        ida_path,
        scripts_path
    )


def create_binja_integration(binja_path: str, scripts_path: str = None) -> BaseIntegration:
    """Create Binary Ninja integration"""
    manager = IntegrationManager()
    return manager.create_analysis_engine_integration(
        "binja",
        binja_path,
        scripts_path
    )
