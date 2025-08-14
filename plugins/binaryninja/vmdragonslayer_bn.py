"""
VMDragonSlayer Binary Ninja Plugin
VM analysis plugin for Binary Ninja integration with core services
"""

import sys
import os
import time
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

# Binary Ninja imports
try:
    import binaryninja as bn
    from binaryninja import PluginCommand, log_info, log_warn, log_error
    from binaryninja.interaction import ChoiceField, TextLineField, IntegerField
    from binaryninja.interaction import get_form_input
    from binaryninja.enums import MediumLevelILOperation
    # UI components
    from binaryninja.dockwidgets import DockHandler, DockContextHandler
    from binaryninja.binaryview import BinaryDataNotification
    BN_AVAILABLE = True
except ImportError:
    BN_AVAILABLE = False
    print("Binary Ninja API not available - plugin will run in compatibility mode")

# Add VMDragonSlayer lib path
plugin_dir = Path(__file__).parent
lib_path = plugin_dir.parent / "lib"
sys.path.insert(0, str(lib_path))

# UI components import
try:
    from .ui import (
        VMDragonSlayerDashboard, RealTimeStatusMonitor, 
        VMAnalysisResultsViewer, PatternMatchViewer,
        VMStructureExplorer, PatternMatchBrowser, ConfigurationEditor
    )
    UI_AVAILABLE = True
except ImportError as e:
    UI_AVAILABLE = False
    print(f"UI components not available: {e}")

# Core services imports
try:
    # Import optimized unified API
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from lib.unified_api import get_api, VMDragonSlayerUnifiedAPI
    
    # Legacy imports for specific services
    from lib.vm_discovery.sample_database_manager import SampleDatabaseManager
    from lib.workflow_integration.validation_framework import ValidationFramework
    from lib.gpu_acceleration.gpu_profiler import GPUProfiler
    from lib.semantic_engine.pattern_recognizer import PatternRecognizer as PatternDatabase
    
    CORE_SERVICES_AVAILABLE = True
    OPTIMIZED_API_AVAILABLE = True
except ImportError as e:
    CORE_SERVICES_AVAILABLE = False
    OPTIMIZED_API_AVAILABLE = False
    print(f"Warning: Core services not available: {e}")


class BinaryNinjaCoreServicesManager:
    """Core services manager using optimized components"""
    
    def __init__(self):
        self.services = {}
        self.api = None
        self.services_available = {}
        self.logger = logging.getLogger(__name__)
        self.initialize_core_services()
    
    def initialize_core_services(self):
        """Initialize all core services with availability checking"""
        self.logger.info("Initializing core services for Binary Ninja...")
        
        # Initialize SampleDatabaseManager
        try:
            self.services['sample_database'] = SampleDatabaseManager()
            self.services_available['sample_database'] = True
            self.logger.info("✓ Sample Database Manager initialized")
        except Exception as e:
            self.services_available['sample_database'] = False
            self.logger.error(f"✗ Sample Database Manager failed: {e}")
        
        # Initialize ValidationFramework
        try:
            self.services['validation_framework'] = ValidationFramework()
            self.services_available['validation_framework'] = True
            self.logger.info("✓ Validation Framework initialized")
        except Exception as e:
            self.services_available['validation_framework'] = False
            self.logger.error(f"✗ Validation Framework failed: {e}")
        
        # Initialize GPUProfiler
        try:
            self.services['gpu_profiler'] = GPUProfiler()
            self.services_available['gpu_profiler'] = True
            self.logger.info("✓ GPU Profiler initialized")
        except Exception as e:
            self.services_available['gpu_profiler'] = False
            self.logger.error(f"✗ GPU Profiler failed: {e}")
        
        # Initialize PatternDatabase
        try:
            self.services['pattern_database'] = PatternDatabase()
            self.services_available['pattern_database'] = True
            self.logger.info("✓ Pattern Database initialized")
        except Exception as e:
            self.services_available['pattern_database'] = False
            self.logger.error(f"✗ Pattern Database failed: {e}")
        
        # Print summary
        available_count = sum(1 for available in self.services_available.values() if available)
        total_count = len(self.services_available)
        self.logger.info(f"Core services initialized: {available_count}/{total_count} available")
    
    def get_service(self, service_name: str):
        """Get a core service if available"""
        if self.services_available.get(service_name, False):
            return self.services.get(service_name)
        return None
    
    def is_service_available(self, service_name: str) -> bool:
        """Check if a core service is available"""
        return self.services_available.get(service_name, False)
    
    def get_service_status(self) -> Dict[str, bool]:
        """Get status of all core services"""
        return self.services_available.copy()
    
    def get_service_metrics(self) -> Dict[str, Dict]:
        """Get real-time metrics from core services"""
        metrics = {}
        
        # GPU metrics
        gpu_profiler = self.get_service('gpu_profiler')
        if gpu_profiler:
            try:
                metrics['gpu'] = gpu_profiler.get_current_metrics()
            except Exception:
                metrics['gpu'] = {'status': 'unavailable'}
        
        # Database metrics
        sample_db = self.get_service('sample_database')
        if sample_db:
            try:
                metrics['database'] = sample_db.get_statistics()
            except Exception:
                metrics['database'] = {'status': 'unavailable'}
        
        # Pattern database metrics
        pattern_db = self.get_service('pattern_database')
        if pattern_db:
            try:
                metrics['patterns'] = pattern_db.get_pattern_statistics()
            except Exception:
                metrics['patterns'] = {'status': 'unavailable'}
        
        return metrics
    
    def shutdown_services(self):
        """Shutdown all core services"""
        for service_name, service in self.services.items():
            try:
                if hasattr(service, 'shutdown'):
                    service.shutdown()
                self.logger.info(f"✓ {service_name} shutdown successfully")
            except Exception as e:
                self.logger.error(f"✗ {service_name} shutdown failed: {e}")


class VMDragonSlayerConfig:
    """Configuration for Binary Ninja plugin with core services support"""
    
    def __init__(self):
        # Analysis configuration
        self.enable_mlil_analysis = True
        self.enable_hlil_analysis = True
        self.enable_dtt = True
        self.enable_se = True
        self.enable_pattern_matching = True
        self.analysis_timeout = 300  # 5 minutes
        self.max_handlers = 100
        self.confidence_threshold = 0.7
        
        # Core services configuration
        self.enable_sample_database = True
        self.enable_validation_framework = True
        self.enable_gpu_profiler = True
        self.enable_pattern_database = True
        
        # Binary Ninja specific settings
        self.auto_comment_handlers = True
        self.auto_tag_functions = True
        self.create_handler_types = True
        self.generate_mlil_mapping = True
        
        # Settings
        self.database_path = "samples.db"
        self.gpu_device_id = 0
        self.validation_threshold = 0.8
        self.auto_store_samples = True
        self.real_time_metrics = True


class BinaryNinjaVMHandlerAnalyzer:
    """Analyzes VM handlers using Binary Ninja's MLIL"""
    
    def __init__(self, config: VMDragonSlayerConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def find_vm_handlers(self, bv: 'bn.BinaryView') -> List[Dict]:
        """Find potential VM handlers using MLIL analysis"""
        self.logger.info("Analyzing binary for VM handlers using MLIL...")
        
        handlers = []
        
        for function in bv.functions:
            if self._is_potential_vm_handler(function):
                handler_info = self._analyze_handler_function(function)
                if handler_info:
                    handlers.append(handler_info)
        
        self.logger.info(f"Found {len(handlers)} potential VM handlers")
        return handlers
    
    def _is_potential_vm_handler(self, function: 'bn.Function') -> bool:
        """Check if function could be a VM handler based on MLIL patterns"""
        
        # Size heuristics
        if len(function.mlil) < 5 or len(function.mlil) > 200:
            return False
        
        # Look for VM-like patterns in MLIL
        switch_count = 0
        indirect_call_count = 0
        memory_access_count = 0
        
        if not BN_AVAILABLE:
            # In compatibility mode, use dummy operations
            return switch_count > 3 and indirect_call_count > 2
        
        for instr in function.mlil:
            if instr.operation == MediumLevelILOperation.MLIL_SWITCH:
                switch_count += 1
            elif instr.operation in [
                MediumLevelILOperation.MLIL_CALL_UNTYPED,
                MediumLevelILOperation.MLIL_TAILCALL_UNTYPED
            ]:
                indirect_call_count += 1
            elif instr.operation in [
                MediumLevelILOperation.MLIL_LOAD,
                MediumLevelILOperation.MLIL_STORE
            ]:
                memory_access_count += 1
        
        # VM handler likelihood score
        score = 0
        if switch_count > 0:
            score += 3
        if indirect_call_count > 0:
            score += 2
        if memory_access_count > len(function.mlil) * 0.3:
            score += 2
        
        return score >= 3
    
    def _analyze_handler_function(self, function: 'bn.Function') -> Optional[Dict]:
        """Analyze a potential handler function"""
        
        handler_info = {
            'address': function.start,
            'name': function.name,
            'size': len(function),
            'mlil_instructions': len(function.mlil),
            'hlil_instructions': len(function.hlil) if function.hlil else 0,
            'complexity': self._calculate_mlil_complexity(function),
            'confidence': 0.0,
            'vm_patterns': [],
            'mlil_operations': self._extract_mlil_operations(function)
        }
        
        # Calculate confidence based on patterns
        confidence = self._calculate_handler_confidence(handler_info)
        handler_info['confidence'] = confidence
        
        return handler_info if confidence > self.config.confidence_threshold else None
    
    def _calculate_mlil_complexity(self, function: 'bn.Function') -> float:
        """Calculate complexity based on MLIL instruction diversity"""
        
        if not function.mlil:
            return 0.0
        
        operation_types = set()
        for instr in function.mlil:
            operation_types.add(instr.operation)
        
        # Complexity based on operation diversity
        complexity = len(operation_types) / 20.0  # Normalize to 0-1 range
        return min(complexity, 1.0)
    
    def _extract_mlil_operations(self, function: 'bn.Function') -> List[str]:
        """Extract MLIL operations for pattern matching"""
        
        operations = []
        for instr in function.mlil:
            operations.append(str(instr.operation))
        
        return operations
    
    def _calculate_handler_confidence(self, handler_info: Dict) -> float:
        """Calculate confidence score for handler detection"""
        
        confidence = 0.0
        
        # Size-based confidence
        if 10 <= handler_info['mlil_instructions'] <= 100:
            confidence += 0.3
        
        # Complexity-based confidence
        confidence += handler_info['complexity'] * 0.4
        
        # Pattern-based confidence
        operations = handler_info['mlil_operations']
        if 'MLIL_SWITCH' in operations:
            confidence += 0.2
        if any(op.startswith('MLIL_CALL') for op in operations):
            confidence += 0.1
        
        return min(confidence, 1.0)


class BinaryNinjaVMStructureAnalyzer:
    """Analyzes VM structure using Binary Ninja's analysis capabilities"""
    
    def __init__(self, config: VMDragonSlayerConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def analyze_vm_structure(self, bv: 'bn.BinaryView', handlers: List[Dict]) -> Dict:
        """Analyze overall VM structure"""
        
        self.logger.info("Analyzing VM structure...")
        
        structure = {
            'vm_type': 'unknown',
            'dispatcher_candidates': [],
            'handler_table': None,
            'vm_context': None,
            'confidence': 0.0,
            'cross_references': [],
            'data_flow': {}
        }
        
        if not handlers:
            return structure
        
        # Find dispatcher using cross-reference analysis
        dispatcher = self._find_dispatcher_with_xrefs(bv, handlers)
        if dispatcher:
            structure['dispatcher_candidates'].append(dispatcher)
        
        # Analyze VM type using MLIL patterns
        vm_type = self._determine_vm_type_mlil(handlers)
        structure['vm_type'] = vm_type
        
        # Find handler table using data analysis
        handler_table = self._find_handler_table_data(bv)
        if handler_table:
            structure['handler_table'] = handler_table
        
        # Analyze cross-references
        structure['cross_references'] = self._analyze_cross_references(bv, handlers)
        
        # Calculate confidence
        confidence = self._calculate_structure_confidence(structure)
        structure['confidence'] = confidence
        
        return structure
    
    def _find_dispatcher_with_xrefs(self, bv: 'bn.BinaryView', handlers: List[Dict]) -> Optional[Dict]:
        """Find dispatcher using cross-reference analysis"""
        
        handler_addresses = {h['address'] for h in handlers}
        ref_counts = {}
        
        for function in bv.functions:
            ref_count = 0
            for ref in function.call_sites:
                if ref.address in handler_addresses:
                    ref_count += 1
            
            if ref_count > 0:
                ref_counts[function.start] = ref_count
        
        if ref_counts:
            dispatcher_addr = max(ref_counts, key=ref_counts.get)
            dispatcher_func = bv.get_function_at(dispatcher_addr)
            
            return {
                'address': dispatcher_addr,
                'name': dispatcher_func.name if dispatcher_func else f"sub_{dispatcher_addr:x}",
                'handler_refs': ref_counts[dispatcher_addr],
                'function': dispatcher_func
            }
        
        return None
    
    def _determine_vm_type_mlil(self, handlers: List[Dict]) -> str:
        """Determine VM type using MLIL operation analysis"""
        
        stack_indicators = 0
        register_indicators = 0
        
        for handler in handlers:
            operations = handler.get('mlil_operations', [])
            
            # Count stack-related operations
            stack_ops = ['MLIL_PUSH', 'MLIL_POP']
            stack_indicators += sum(1 for op in operations if any(s in op for s in stack_ops))
            
            # Count register-related operations
            reg_ops = ['MLIL_SET_VAR', 'MLIL_VAR']
            register_indicators += sum(1 for op in operations if any(r in op for r in reg_ops))
        
        if stack_indicators > register_indicators * 1.5:
            return 'stack_based'
        elif register_indicators > stack_indicators * 1.5:
            return 'register_based'
        else:
            return 'hybrid'
    
    def _find_handler_table_data(self, bv: 'bn.BinaryView') -> Optional[Dict]:
        """Find handler table using Binary Ninja's data analysis"""
        
        # Look for arrays of function pointers
        for segment in bv.segments:
            if segment.readable and not segment.executable:
                # Scan for potential handler tables
                for addr in range(segment.start, segment.end, bv.address_size):
                    if self._is_function_pointer_array(bv, addr):
                        return {
                            'address': addr,
                            'size': self._get_table_size(bv, addr),
                            'segment': segment.name
                        }
        
        return None
    
    def _is_function_pointer_array(self, bv: 'bn.BinaryView', addr: int) -> bool:
        """Check if address contains array of function pointers"""
        
        function_count = 0
        for i in range(8):  # Check first 8 entries
            try:
                ptr_addr = addr + i * bv.address_size
                if ptr_addr >= bv.end:
                    break
                
                ptr_value = bv.read_pointer(ptr_addr)
                if ptr_value and bv.get_function_at(ptr_value):
                    function_count += 1
            except:
                break
        
        return function_count >= 3
    
    def _get_table_size(self, bv: 'bn.BinaryView', addr: int) -> int:
        """Get size of handler table"""
        size = 0
        while True:
            try:
                ptr_addr = addr + size
                if ptr_addr >= bv.end:
                    break
                
                ptr_value = bv.read_pointer(ptr_addr)
                if not ptr_value or not bv.get_function_at(ptr_value):
                    break
                
                size += bv.address_size
            except:
                break
        
        return size
    
    def _analyze_cross_references(self, bv: 'bn.BinaryView', handlers: List[Dict]) -> List[Dict]:
        """Analyze cross-references between handlers and other functions"""
        
        xrefs = []
        
        for handler in handlers:
            handler_func = bv.get_function_at(handler['address'])
            if not handler_func:
                continue
            
            # Incoming references
            incoming_refs = []
            for ref in bv.get_code_refs(handler['address']):
                incoming_refs.append({
                    'from': ref.address,
                    'function': bv.get_function_at(ref.address)
                })
            
            # Outgoing references
            outgoing_refs = []
            for call_site in handler_func.call_sites:
                outgoing_refs.append({
                    'to': call_site.address,
                    'function': bv.get_function_at(call_site.address)
                })
            
            xrefs.append({
                'handler_address': handler['address'],
                'incoming_refs': incoming_refs,
                'outgoing_refs': outgoing_refs
            })
        
        return xrefs
    
    def _calculate_structure_confidence(self, structure: Dict) -> float:
        """Calculate confidence in VM structure analysis"""
        
        confidence = 0.0
        
        # Dispatcher found
        if structure.get('dispatcher_candidates'):
            confidence += 0.3
        
        # Handler table found
        if structure.get('handler_table'):
            confidence += 0.3
        
        # Cross-references analyzed
        if structure.get('cross_references'):
            confidence += 0.2
        
        # VM type determined
        if structure.get('vm_type') != 'unknown':
            confidence += 0.2
        
        return min(confidence, 1.0)


class VMDragonSlayerBinaryNinjaPlugin:
    """VMDragonSlayer Binary Ninja plugin with core services integration"""
    
    def __init__(self):
        self.config = VMDragonSlayerConfig()
        self.core_services = BinaryNinjaCoreServicesManager()
        self.standard_mode = CORE_SERVICES_AVAILABLE
        self.logger = logging.getLogger(__name__)
        
        # Initialize UI manager
        self.ui_manager = VMDragonSlayerUIManager(self)
        
        # Initialize analysis engines
        self.handler_analyzer = BinaryNinjaVMHandlerAnalyzer(self.config)
        self.structure_analyzer = BinaryNinjaVMStructureAnalyzer(self.config)
        
        # Initialize core analysis engines through unified API
        self.analysis_engines = {}
        self.unified_api = None
        if CORE_SERVICES_AVAILABLE:
            try:
                from lib.unified_api import get_api
                self.unified_api = get_api()
                self.analysis_engines['orchestrator'] = self.unified_api.get_orchestrator()
                self.analysis_engines['ml_engine'] = self.unified_api.get_ml_engine()
                self.analysis_engines['dtt_executor'] = self.unified_api.get_dtt_executor()
                self.logger.info("✓ Unified API analysis engines initialized")
            except Exception as e:
                self.logger.warning(f"Could not initialize unified API analysis engines: {e}")
                self.unified_api = None
    
    def analyze_binary_view(self, bv: 'bn.BinaryView') -> Dict:
        """Main analysis entry point for Binary Ninja binary view"""
        
        if not BN_AVAILABLE:
            return {'error': 'Binary Ninja API not available'}
        
        self.logger.info("Starting VMDragonSlayer analysis...")
        start_time = time.time()
        
        results = {
            'binary_name': bv.file.filename,
            'architecture': str(bv.arch),
            'handlers': [],
            'vm_structure': {},
            'analysis_metadata': {},
            'confidence_score': 0.0,
            'analysis_time': 0.0
        }
        
        try:
            # Step 1: Handler Discovery
            self.logger.info("Step 1: Handler Discovery")
            handlers = self.handler_analyzer.find_vm_handlers(bv)
            results['handlers'] = handlers
            
            if not handlers:
                self.logger.info("No VM handlers detected")
                results = self._finalize_results(results, start_time)
                # Update UI even with no results
                self.ui_manager.update_analysis_data(results)
                return results
            
            # Step 2: VM Structure Analysis
            self.logger.info("Step 2: VM Structure Analysis")
            vm_structure = self.structure_analyzer.analyze_vm_structure(bv, handlers)
            results['vm_structure'] = vm_structure
            
            # Step 3: Analysis with Core Services
            if self.standard_mode:
                results = self._run_analysis(bv, handlers, results)
            
            # Step 4: Binary Ninja Integration
            self._integrate_with_binary_ninja(bv, handlers, vm_structure)
            
            # Step 5: Update UI with results
            final_results = self._finalize_results(results, start_time)
            self.ui_manager.update_analysis_data(final_results)
            
            return final_results
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            results['error'] = str(e)
            final_results = self._finalize_results(results, start_time)
            self.ui_manager.update_analysis_data(final_results)
            return final_results
    
    def _run_analysis(self, bv: 'bn.BinaryView', handlers: List[Dict], results: Dict) -> Dict:
        """Run enhanced analysis using core services"""
        
        self.logger.info("Running enhanced analysis with core services...")
        
        # Start GPU profiling if available
        gpu_profiler = self.core_services.get_service('gpu_profiler')
        if gpu_profiler:
            try:
                gpu_profiler.start_profiling()
                self.logger.info("✓ GPU profiling started")
            except Exception as e:
                self.logger.warning(f"GPU profiling failed: {e}")
        
        # Pattern matching enhancement
        pattern_db = self.core_services.get_service('pattern_database')
        if pattern_db:
            try:
                for handler in handlers:
                    patterns = pattern_db.match_patterns(handler.get('mlil_operations', []))
                    handler['pattern_matches'] = patterns
                    if patterns:
                        # Update confidence based on pattern matches
                        pattern_confidence = sum(p.get('confidence', 0) for p in patterns) / len(patterns)
                        handler['confidence'] = max(handler.get('confidence', 0), pattern_confidence)
                self.logger.info("✓ Pattern matching completed")
            except Exception as e:
                self.logger.warning(f"Pattern matching failed: {e}")
        
        # Validation framework integration
        validation_framework = self.core_services.get_service('validation_framework')
        if validation_framework:
            try:
                vm_type = results['vm_structure'].get('vm_type', 'unknown')
                validation_result = validation_framework.validate_vm_detection(
                    vm_type,
                    'BinaryNinja_Analysis',
                    results['vm_structure'].get('confidence', 0.0)
                )
                results['vm_structure']['validation'] = validation_result
                self.logger.info(f"✓ Validation score: {validation_result.get('score', 0.0):.2f}")
            except Exception as e:
                self.logger.warning(f"Validation failed: {e}")
        
        # Sample database storage
        sample_db = self.core_services.get_service('sample_database')
        if sample_db and self.config.auto_store_samples:
            try:
                sample_data = {
                    'binary_name': bv.file.filename,
                    'handlers': handlers,
                    'vm_structure': results['vm_structure'],
                    'analysis_timestamp': time.time(),
                    'analysis_tool': 'BinaryNinja_Enhanced'
                }
                sample_db.store_sample(bv.file.filename, sample_data)
                self.logger.info("✓ Analysis results stored in database")
            except Exception as e:
                self.logger.warning(f"Database storage failed: {e}")
        
        return results
    
    def _integrate_with_binary_ninja(self, bv: 'bn.BinaryView', handlers: List[Dict], vm_structure: Dict):
        """Integrate analysis results with Binary Ninja UI"""
        
        if not self.config.auto_comment_handlers and not self.config.auto_tag_functions:
            return
        
        self.logger.info("Integrating results with Binary Ninja...")
        
        # Comment handlers
        if self.config.auto_comment_handlers:
            for handler in handlers:
                comment = f"VM Handler (confidence: {handler['confidence']:.2f})"
                if handler.get('pattern_matches'):
                    patterns = [p['pattern'] for p in handler['pattern_matches'][:3]]
                    comment += f" - Patterns: {', '.join(patterns)}"
                
                bv.set_comment_at(handler['address'], comment)
        
        # Tag functions
        if self.config.auto_tag_functions:
            # Create VM handler tag type
            tag_type = bv.create_tag_type("VM Handler", "🤖")
            
            for handler in handlers:
                confidence_level = "High" if handler['confidence'] > 0.8 else "Medium" if handler['confidence'] > 0.6 else "Low"
                tag_text = f"VM Handler ({confidence_level})"
                
                function = bv.get_function_at(handler['address'])
                if function:
                    function.add_tag(tag_type, tag_text)
        
        # Mark dispatcher if found
        dispatcher_candidates = vm_structure.get('dispatcher_candidates', [])
        if dispatcher_candidates and self.config.auto_comment_handlers:
            for dispatcher in dispatcher_candidates:
                comment = f"VM Dispatcher (refs: {dispatcher.get('handler_refs', 0)})"
                bv.set_comment_at(dispatcher['address'], comment)
        
        self.logger.info("✓ Binary Ninja integration completed")
    
    def _finalize_results(self, results: Dict, start_time: float) -> Dict:
        """Finalize analysis results"""
        
        # Calculate final metrics
        results['analysis_time'] = time.time() - start_time
        
        # Stop GPU profiling if running
        gpu_profiler = self.core_services.get_service('gpu_profiler')
        if gpu_profiler:
            try:
                gpu_metrics = gpu_profiler.stop_profiling()
                results['gpu_metrics'] = gpu_metrics
            except Exception:
                pass
        
        # Calculate overall confidence
        if results['handlers']:
            handler_confidences = [h.get('confidence', 0) for h in results['handlers']]
            avg_handler_confidence = sum(handler_confidences) / len(handler_confidences)
            structure_confidence = results['vm_structure'].get('confidence', 0)
            results['confidence_score'] = (avg_handler_confidence + structure_confidence) / 2
        
        # Add core service metrics
        results['core_service_metrics'] = self.core_services.get_service_metrics()
        
        self.logger.info(f"Analysis completed in {results['analysis_time']:.2f} seconds")
        self.logger.info(f"Overall confidence: {results['confidence_score']:.2f}")
        
        return results
    
    def get_core_service_status(self) -> Dict[str, bool]:
        """Get status of all core services"""
        return self.core_services.get_service_status()
    
    def shutdown(self):
        """Shutdown plugin and core services"""
        self.logger.info("Shutting down VMDragonSlayer Binary Ninja plugin...")
        
        # Shutdown UI components
        if hasattr(self, 'ui_manager'):
            self.ui_manager.shutdown()
        
        # Shutdown core services
        self.core_services.shutdown_services()
    
    def show_dashboard(self, bv: 'bn.BinaryView' = None):
        """Show the main dashboard UI"""
        self.ui_manager.show_dashboard(bv)
    
    def show_pattern_browser(self):
        """Show the pattern browser UI"""
        self.ui_manager.show_pattern_browser()
    
    def show_structure_explorer(self):
        """Show the VM structure explorer UI"""
        self.ui_manager.show_structure_explorer()
    
    def show_results_viewer(self):
        """Show the analysis results viewer UI"""
        self.ui_manager.show_results_viewer()
    
    def show_config_editor(self):
        """Show the configuration editor UI"""
        self.ui_manager.show_config_editor()


class VMDragonSlayerUIManager:
    """Manages UI components for Binary Ninja integration"""
    
    def __init__(self, plugin_instance):
        self.plugin = plugin_instance
        self.ui_components = {}
        self.active_widgets = {}
        self.analysis_data = {}
        self.ui_enabled = UI_AVAILABLE and BN_AVAILABLE
        
        if self.ui_enabled:
            self._initialize_ui_components()
    
    def _initialize_ui_components(self):
        """Initialize all UI components"""
        try:
            # Main dashboard
            self.ui_components['dashboard'] = VMDragonSlayerDashboard()
            
            # Status monitor for real-time updates
            self.ui_components['status_monitor'] = RealTimeStatusMonitor()
            
            # Results viewer
            self.ui_components['results_viewer'] = VMAnalysisResultsViewer()
            
            # Pattern browser
            self.ui_components['pattern_browser'] = PatternMatchBrowser()
            
            # VM structure explorer
            self.ui_components['structure_explorer'] = VMStructureExplorer()
            
            # Configuration editor
            self.ui_components['config_editor'] = ConfigurationEditor()
            
            # Connect inter-component signals
            self._connect_ui_signals()
            
            log_info("VMDragonSlayer UI components initialized successfully")
            
        except Exception as e:
            log_error(f"Failed to initialize UI components: {e}")
            self.ui_enabled = False
    
    def _connect_ui_signals(self):
        """Connect signals between UI components"""
        if not self.ui_enabled:
            return
            
        try:
            # Connect dashboard to other components
            dashboard = self.ui_components['dashboard']
            
            # Connect analysis triggers
            # dashboard.analysis_requested.connect(self._trigger_analysis)
            
            # Connect navigation signals
            pattern_browser = self.ui_components['pattern_browser']
            structure_explorer = self.ui_components['structure_explorer']
            
            # pattern_browser.navigate_to_address.connect(self._navigate_to_address)
            # structure_explorer.navigate_to_address.connect(self._navigate_to_address)
            
            log_info("UI component signals connected")
            
        except Exception as e:
            log_warn(f"Failed to connect UI signals: {e}")
    
    def show_dashboard(self, bv: 'bn.BinaryView' = None):
        """Show the main dashboard"""
        if not self.ui_enabled:
            log_warn("UI components not available")
            return
            
        try:
            dashboard = self.ui_components['dashboard']
            
            # Update dashboard with current data
            if self.analysis_data:
                dashboard.update_analysis_data(self.analysis_data)
            
            # Update service status
            if self.plugin:
                service_status = self.plugin.get_core_service_status()
                metrics = self.plugin.core_services.get_service_metrics()
                dashboard.update_service_status(service_status, metrics)
            
            # Show widget (implement platform-specific showing)
            self._show_widget('dashboard', dashboard)
            
        except Exception as e:
            log_error(f"Failed to show dashboard: {e}")
    
    def show_pattern_browser(self, pattern_data: List[Dict] = None):
        """Show the pattern match browser"""
        if not self.ui_enabled:
            log_warn("UI components not available")
            return
            
        try:
            pattern_browser = self.ui_components['pattern_browser']
            
            if pattern_data:
                pattern_browser.load_pattern_matches(pattern_data)
            elif self.analysis_data and 'pattern_matches' in self.analysis_data:
                pattern_browser.load_pattern_matches(self.analysis_data['pattern_matches'])
            
            self._show_widget('pattern_browser', pattern_browser)
            
        except Exception as e:
            log_error(f"Failed to show pattern browser: {e}")
    
    def show_structure_explorer(self, vm_structure: Dict = None):
        """Show the VM structure explorer"""
        if not self.ui_enabled:
            log_warn("UI components not available")
            return
            
        try:
            structure_explorer = self.ui_components['structure_explorer']
            
            if vm_structure:
                structure_explorer.load_vm_analysis(vm_structure)
            elif self.analysis_data and 'vm_structure' in self.analysis_data:
                structure_explorer.load_vm_analysis(self.analysis_data['vm_structure'])
            
            self._show_widget('structure_explorer', structure_explorer)
            
        except Exception as e:
            log_error(f"Failed to show structure explorer: {e}")
    
    def show_results_viewer(self, results: Dict = None):
        """Show the analysis results viewer"""
        if not self.ui_enabled:
            log_warn("UI components not available")
            return
            
        try:
            results_viewer = self.ui_components['results_viewer']
            
            if results:
                results_viewer.load_analysis_results(results)
            elif self.analysis_data:
                results_viewer.load_analysis_results(self.analysis_data)
            
            self._show_widget('results_viewer', results_viewer)
            
        except Exception as e:
            log_error(f"Failed to show results viewer: {e}")
    
    def show_config_editor(self):
        """Show the configuration editor"""
        if not self.ui_enabled:
            log_warn("UI components not available")
            return
            
        try:
            config_editor = self.ui_components['config_editor']
            
            # Load current configuration
            if self.plugin and hasattr(self.plugin, 'config'):
                config_data = self.plugin.config.__dict__
                config_editor.set_config_data(config_data)
            
            self._show_widget('config_editor', config_editor)
            
        except Exception as e:
            log_error(f"Failed to show config editor: {e}")
    
    def _show_widget(self, widget_name: str, widget):
        """Show a widget (platform-specific implementation)"""
        # For Binary Ninja, this would integrate with the docking system
        # For now, we'll implement a basic approach
        
        if widget_name in self.active_widgets:
            # Widget already shown, bring to front
            existing_widget = self.active_widgets[widget_name]
            if hasattr(existing_widget, 'show'):
                existing_widget.show()
                existing_widget.raise_()
            return
        
        # Store active widget reference
        self.active_widgets[widget_name] = widget
        
        # Show the widget
        if hasattr(widget, 'show'):
            widget.show()
    
    def update_analysis_data(self, analysis_results: Dict):
        """Update all UI components with new analysis data"""
        self.analysis_data = analysis_results
        
        if not self.ui_enabled:
            return
        
        try:
            # Update dashboard
            if 'dashboard' in self.ui_components:
                self.ui_components['dashboard'].update_analysis_data(analysis_results)
            
            # Update results viewer
            if 'results_viewer' in self.ui_components:
                self.ui_components['results_viewer'].load_analysis_results(analysis_results)
            
            # Update pattern browser if patterns found
            if 'pattern_browser' in self.ui_components and 'handlers' in analysis_results:
                patterns = []
                for handler in analysis_results['handlers']:
                    if 'pattern_matches' in handler:
                        patterns.extend(handler['pattern_matches'])
                if patterns:
                    self.ui_components['pattern_browser'].load_pattern_matches(patterns)
            
            # Update structure explorer
            if 'structure_explorer' in self.ui_components and 'vm_structure' in analysis_results:
                self.ui_components['structure_explorer'].load_vm_analysis(analysis_results['vm_structure'])
            
            log_info(f"UI components updated with analysis data")
            
        except Exception as e:
            log_warn(f"Failed to update UI components: {e}")
    
    def _navigate_to_address(self, address: int):
        """Navigate to address in Binary Ninja"""
        try:
            # This would be implemented with Binary Ninja's navigation API
            log_info(f"Navigate to address: 0x{address:08x}")
        except Exception as e:
            log_warn(f"Navigation failed: {e}")
    
    def _trigger_analysis(self, bv: 'bn.BinaryView'):
        """Trigger analysis from UI"""
        if self.plugin and hasattr(self.plugin, 'analyze_binary_view'):
            results = self.plugin.analyze_binary_view(bv)
            self.update_analysis_data(results)
    
    def shutdown(self):
        """Shutdown UI components"""
        for widget_name, widget in self.active_widgets.items():
            try:
                if hasattr(widget, 'close'):
                    widget.close()
            except Exception as e:
                log_warn(f"Failed to close widget {widget_name}: {e}")
        
        self.active_widgets.clear()
        self.ui_components.clear()


# UI Command Functions
def show_vmdragonslayer_dashboard(bv: 'bn.BinaryView'):
    """Binary Ninja plugin command: Show VMDragonSlayer dashboard"""
    global plugin_instance
    
    if not plugin_instance:
        plugin_instance = VMDragonSlayerBinaryNinjaPlugin()
    
    plugin_instance.show_dashboard(bv)

def show_pattern_browser(bv: 'bn.BinaryView'):
    """Binary Ninja plugin command: Show pattern match browser"""
    global plugin_instance
    
    if not plugin_instance:
        plugin_instance = VMDragonSlayerBinaryNinjaPlugin()
    
    plugin_instance.show_pattern_browser()

def show_structure_explorer(bv: 'bn.BinaryView'):
    """Binary Ninja plugin command: Show VM structure explorer"""
    global plugin_instance
    
    if not plugin_instance:
        plugin_instance = VMDragonSlayerBinaryNinjaPlugin()
    
    plugin_instance.show_structure_explorer()

def show_results_viewer(bv: 'bn.BinaryView'):
    """Binary Ninja plugin command: Show analysis results viewer"""
    global plugin_instance
    
    if not plugin_instance:
        plugin_instance = VMDragonSlayerBinaryNinjaPlugin()
    
    plugin_instance.show_results_viewer()

def show_config_editor(bv: 'bn.BinaryView'):
    """Binary Ninja plugin command: Show configuration editor"""
    global plugin_instance
    
    if not plugin_instance:
        plugin_instance = VMDragonSlayerBinaryNinjaPlugin()
    
    plugin_instance.show_config_editor()

# Global plugin instance
plugin_instance = None

def analyze_current_binary(bv: 'bn.BinaryView'):
    """Binary Ninja plugin command: Analyze current binary for VM protection"""
    global plugin_instance
    
    if not plugin_instance:
        plugin_instance = VMDragonSlayerBinaryNinjaPlugin()
    
    log_info("VMDragonSlayer: Starting VM analysis...")
    
    results = plugin_instance.analyze_binary_view(bv)
    
    if 'error' in results:
        log_error(f"VMDragonSlayer: Analysis failed - {results['error']}")
        return
    
    # Display results
    handler_count = len(results.get('handlers', []))
    vm_type = results.get('vm_structure', {}).get('vm_type', 'unknown')
    confidence = results.get('confidence_score', 0.0)
    analysis_time = results.get('analysis_time', 0.0)
    
    log_info(f"VMDragonSlayer: Analysis complete!")
    log_info(f"  Handlers found: {handler_count}")
    log_info(f"  VM type: {vm_type}")
    log_info(f"  Confidence: {confidence:.2f}")
    log_info(f"  Time: {analysis_time:.2f}s")
    
    # Save detailed results to file
    output_file = f"{bv.file.filename}_vmdragonslayer_results.json"
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        log_info(f"Detailed results saved to: {output_file}")
    except Exception as e:
        log_warn(f"Could not save results file: {e}")

def show_core_service_status(bv: 'bn.BinaryView'):
    """Binary Ninja plugin command: Show core service status"""
    global plugin_instance
    
    if not plugin_instance:
        plugin_instance = VMDragonSlayerBinaryNinjaPlugin()
    
    status = plugin_instance.get_core_service_status()
    metrics = plugin_instance.core_services.get_service_metrics()
    
    log_info("VMDragonSlayer Core Services Status:")
    for service, available in status.items():
        status_icon = "✓" if available else "✗"
        log_info(f"  {status_icon} {service}: {'Available' if available else 'Unavailable'}")
    
    if metrics:
        log_info("Core Service Metrics:")
        for service, service_metrics in metrics.items():
            if service_metrics.get('status') != 'unavailable':
                log_info(f"  {service}: {service_metrics}")

# Register Binary Ninja plugin commands
if BN_AVAILABLE:
    # Core analysis commands
    PluginCommand.register(
        "VMDragonSlayer\\Analyze VM Protection",
        "Analyze current binary for VM protection using VMDragonSlayer",
        analyze_current_binary
    )
    
    PluginCommand.register(
        "VMDragonSlayer\\Show Core Service Status", 
        "Display status of VMDragonSlayer core services",
        show_core_service_status
    )
    
    # UI commands (only register if UI components are available)
    if UI_AVAILABLE:
        PluginCommand.register(
            "VMDragonSlayer\\Show Dashboard",
            "Show VMDragonSlayer analysis dashboard",
            show_vmdragonslayer_dashboard
        )
        
        PluginCommand.register(
            "VMDragonSlayer\\Show Pattern Browser",
            "Show pattern match browser",
            show_pattern_browser
        )
        
        PluginCommand.register(
            "VMDragonSlayer\\Show Structure Explorer",
            "Show VM structure explorer",
            show_structure_explorer
        )
        
        PluginCommand.register(
            "VMDragonSlayer\\Show Results Viewer",
            "Show analysis results viewer",
            show_results_viewer
        )
        
        PluginCommand.register(
            "VMDragonSlayer\\Show Configuration Editor",
            "Show configuration editor",
            show_config_editor
        )
    
    log_info("VMDragonSlayer Binary Ninja plugin loaded successfully!")
    if plugin_instance is None:
        plugin_instance = VMDragonSlayerBinaryNinjaPlugin()
        if plugin_instance.enhanced_mode:
            available_services = sum(plugin_instance.get_core_service_status().values())
            total_services = len(plugin_instance.get_core_service_status())
            log_info(f"Enhanced mode enabled ({available_services}/{total_services} core services)")
        else:
            log_info("Basic mode (core services unavailable)")
        
        # UI status
        if UI_AVAILABLE:
            log_info("UI components available - full interface enabled")
        else:
            log_info("UI components unavailable - command-line interface only")
else:
    print("VMDragonSlayer Binary Ninja plugin: Binary Ninja API not available")
