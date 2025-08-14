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
VMDragonSlayer IDA Pro Plugin
VM analysis plugin for IDA Pro integration
"""

import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_pro
import ida_nalt
import json
import os
import sys
import time
from pathlib import Path

# Add VMDragonSlayer lib path
plugin_dir = Path(__file__).parent
lib_path = plugin_dir.parent / "lib"
sys.path.insert(0, str(lib_path))

try:
    # Import unified API for optimized components
    from lib.unified_api import get_api, VMDragonSlayerUnifiedAPI

    # Core Services Integration
    from lib.vm_discovery.sample_database_manager import SampleDatabaseManager
    from lib.workflow_integration.validation_framework import ValidationFramework
    from lib.gpu_acceleration.gpu_profiler import GPUProfiler
    from lib.semantic_engine.pattern_recognizer import (
        PatternRecognizer as PatternDatabase,
    )

    UNIFIED_API_AVAILABLE = True

except ImportError as e:
    print(f"Warning: Could not import VMDragonSlayer unified API: {e}")
    UNIFIED_API_AVAILABLE = False

    # Fallback to legacy imports if available
    try:
        from dragonslayer.analysis.vm_taint_tracker import VMTaintTracker
        from dragonslayer.analysis.handler_lifter import HandlerLifter
        from dragonslayer.analysis.pattern_recognizer import SemanticPatternRecognizer
        from dragonslayer.core.orchestrator import AnalysisOrchestrator
        from dragonslayer.analysis.structure_analyzer import VMStructureAnalyzer
        from dragonslayer.analysis.environment_normalizer import EnvironmentNormalizer

        # Legacy core services
        from lib.vm_discovery.sample_database_manager import SampleDatabaseManager
        from lib.workflow_integration.validation_framework import ValidationFramework
        from lib.gpu_acceleration.gpu_profiler import GPUProfiler
        from lib.semantic_engine.pattern_recognizer import (
            PatternRecognizer as PatternDatabase,
        )

        LEGACY_COMPONENTS_AVAILABLE = True
    except ImportError as legacy_e:
        print(f"Warning: Could not import legacy VMDragonSlayer modules: {legacy_e}")
        LEGACY_COMPONENTS_AVAILABLE = False


class CoreServicesManager:
    """Manages core services integration for IDA Pro plugin with unified API support"""

    def __init__(self):
        self.services = {}
        self.services_available = {}
        self.unified_api = None
        self.initialize_core_services()

    def initialize_core_services(self):
        """Initialize all core services with unified API if available"""
        print("Initializing core services...")

        # Try to initialize unified API first
        if UNIFIED_API_AVAILABLE:
            try:
                self.unified_api = get_api()
                self.services["unified_api"] = self.unified_api
                self.services_available["unified_api"] = True
                print("✓ Unified API initialized")

                # Initialize optimized components through unified API
                try:
                    self.services["orchestrator"] = self.unified_api.get_orchestrator()
                    self.services_available["orchestrator"] = True
                    print("✓ Optimized orchestrator initialized")
                except Exception as e:
                    self.services_available["orchestrator"] = False
                    print(f"✗ Optimized orchestrator failed: {e}")

                try:
                    self.services["ml_engine"] = self.unified_api.get_ml_engine()
                    self.services_available["ml_engine"] = True
                    print("✓ Optimized ML engine initialized")
                except Exception as e:
                    self.services_available["ml_engine"] = False
                    print(f"✗ Optimized ML engine failed: {e}")

                try:
                    self.services["dtt_executor"] = self.unified_api.get_dtt_executor()
                    self.services_available["dtt_executor"] = True
                    print("✓ Optimized DTT executor initialized")
                except Exception as e:
                    self.services_available["dtt_executor"] = False
                    print(f"✗ Optimized DTT executor failed: {e}")

            except Exception as e:
                self.services_available["unified_api"] = False
                print(f"✗ Unified API failed: {e}")

        # Initialize individual services (unified or legacy)
        # Initialize SampleDatabaseManager
        try:
            if not self.services.get("sample_database"):
                self.services["sample_database"] = SampleDatabaseManager()
            self.services_available["sample_database"] = True
            print("✓ Sample Database Manager initialized")
        except Exception as e:
            self.services_available["sample_database"] = False
            print(f"✗ Sample Database Manager failed: {e}")

        # Initialize ValidationFramework
        try:
            if not self.services.get("validation_framework"):
                self.services["validation_framework"] = ValidationFramework()
            self.services_available["validation_framework"] = True
            print("✓ Validation Framework initialized")
        except Exception as e:
            self.services_available["validation_framework"] = False
            print(f"✗ Validation Framework failed: {e}")

        # Initialize GPUProfiler
        try:
            if not self.services.get("gpu_profiler"):
                self.services["gpu_profiler"] = GPUProfiler()
            self.services_available["gpu_profiler"] = True
            print("✓ GPU Profiler initialized")
        except Exception as e:
            self.services_available["gpu_profiler"] = False
            print(f"✗ GPU Profiler failed: {e}")

        # Initialize PatternDatabase
        try:
            self.services["pattern_database"] = PatternDatabase()
            self.services_available["pattern_database"] = True
            print("✓ Pattern Database initialized")
        except Exception as e:
            self.services_available["pattern_database"] = False
            print(f"✗ Pattern Database failed: {e}")

        # Print summary
        available_count = sum(
            1 for available in self.services_available.values() if available
        )
        total_count = len(self.services_available)
        print(f"Core services initialized: {available_count}/{total_count} available")

    def get_service(self, service_name):
        """Get a core service if available"""
        if self.services_available.get(service_name, False):
            return self.services.get(service_name)
        return None

    def is_service_available(self, service_name):
        """Check if a core service is available"""
        return self.services_available.get(service_name, False)

    def get_service_status(self):
        """Get status of all core services"""
        return self.services_available.copy()

    def shutdown_services(self):
        """Shutdown all core services"""
        for service_name, service in self.services.items():
            try:
                if hasattr(service, "shutdown"):
                    service.shutdown()
                print(f"✓ {service_name} shutdown successfully")
            except Exception as e:
                print(f"✗ {service_name} shutdown failed: {e}")


class VMDragonSlayerConfig:
    """Configuration for VMDragonSlayer analysis"""

    def __init__(self):
        self.enable_dtt = True
        self.enable_se = True
        self.enable_anti_analysis = True
        self.enable_vm_discovery = True
        self.analysis_timeout = 300  # 5 minutes
        self.max_handlers = 100
        self.confidence_threshold = 0.7
        self.output_format = "json"


class VMDragonSlayerConfig:
    """Configuration with core services support"""

    def __init__(self):
        # Original configuration
        self.enable_dtt = True
        self.enable_se = True
        self.enable_anti_analysis = True
        self.enable_vm_discovery = True
        self.analysis_timeout = 300  # 5 minutes
        self.max_handlers = 100
        self.confidence_threshold = 0.7
        self.output_format = "json"

        # Core services configuration
        self.enable_sample_database = True
        self.enable_validation_framework = True
        self.enable_gpu_profiler = True
        self.enable_pattern_database = True

        # Settings
        self.database_path = "samples.db"
        self.gpu_device_id = 0
        self.validation_threshold = 0.8
        self.auto_store_samples = True
        self.real_time_metrics = True


class VMDragonSlayerResults:
    """Analysis results container"""

    def __init__(self):
        self.vm_handlers = []
        self.control_flow = {}
        self.taint_flows = []
        self.polymorphic_groups = {}
        self.confidence_score = 0.0
        self.analysis_time = 0.0
        self.metadata = {}


class VMHandlerAnalyzer:
    """Analyzes VM handlers in IDA Pro"""

    def __init__(self, config):
        self.config = config
        self.handlers = []

    def find_vm_handlers(self):
        """Find potential VM handlers in the binary"""
        print("Scanning for VM handlers...")

        handlers = []

        # Get all functions
        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)
            func_size = idc.get_func_attr(func_ea, idc.FUNCATTR_END) - func_ea

            # Analyze function characteristics
            if self._is_potential_vm_handler(func_ea, func_size):
                handler_info = {
                    "address": func_ea,
                    "name": func_name,
                    "size": func_size,
                    "instructions": self._get_function_instructions(func_ea),
                    "complexity": self._calculate_complexity(func_ea),
                    "confidence": 0.0,
                }
                handlers.append(handler_info)

        print(f"Found {len(handlers)} potential VM handlers")
        self.handlers = handlers
        return handlers

    def _is_potential_vm_handler(self, func_ea, func_size):
        """Check if function could be a VM handler"""

        # Size heuristics - VM handlers are typically small to medium
        if func_size < 10 or func_size > 1000:
            return False

        # Check for VM-like patterns
        has_switch = False
        has_indirect_jumps = False
        register_usage = 0

        for head in idautils.Heads(func_ea, func_ea + func_size):
            if idc.is_code(idc.get_full_flags(head)):
                mnem = idc.print_insn_mnem(head)

                # Look for switch patterns
                if mnem in ["jmp", "call"] and "table" in idc.get_operand_type(head, 0):
                    has_switch = True

                # Look for indirect jumps
                if mnem == "jmp" and idc.get_operand_type(head, 0) in [
                    idc.o_phrase,
                    idc.o_displ,
                ]:
                    has_indirect_jumps = True

                # Count register operations
                if any(
                    reg in idc.print_operand(head, 0)
                    for reg in ["eax", "ebx", "ecx", "edx"]
                ):
                    register_usage += 1

        # VM handler likelihood score
        score = 0
        if has_switch:
            score += 3
        if has_indirect_jumps:
            score += 2
        if register_usage > func_size * 0.3:
            score += 2

        return score >= 3

    def _get_function_instructions(self, func_ea):
        """Get disassembled instructions for function"""
        instructions = []

        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        for head in idautils.Heads(func_ea, func_end):
            if idc.is_code(idc.get_full_flags(head)):
                instructions.append(idc.generate_disasm_line(head, 0))

        return instructions

    def _calculate_complexity(self, func_ea):
        """Calculate function complexity score"""

        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)

        # Count different instruction types
        arithmetic_ops = 0
        memory_ops = 0
        control_ops = 0
        total_instructions = 0

        for head in idautils.Heads(func_ea, func_end):
            if idc.is_code(idc.get_full_flags(head)):
                mnem = idc.print_insn_mnem(head)
                total_instructions += 1

                if mnem in ["add", "sub", "mul", "div", "xor", "and", "or"]:
                    arithmetic_ops += 1
                elif mnem in ["mov", "push", "pop", "lea"]:
                    memory_ops += 1
                elif mnem in ["jmp", "call", "ret", "jz", "jnz"]:
                    control_ops += 1

        if total_instructions == 0:
            return 0.0

        # Complexity based on instruction diversity
        complexity = (arithmetic_ops + memory_ops + control_ops) / total_instructions
        return min(complexity, 1.0)


class VMStructureDiscovery:
    """Discovers VM structure and architecture"""

    def __init__(self, config):
        self.config = config

    def analyze_vm_structure(self, handlers):
        """Analyze overall VM structure"""

        print("Analyzing VM structure...")

        structure = {
            "vm_type": "unknown",
            "dispatcher_candidates": [],
            "handler_table": None,
            "vm_context": None,
            "confidence": 0.0,
        }

        if not handlers:
            return structure

        # Find dispatcher (function with most cross-references)
        dispatcher_candidate = self._find_dispatcher(handlers)
        if dispatcher_candidate:
            structure["dispatcher_candidates"].append(dispatcher_candidate)

        # Determine VM type (stack-based vs register-based)
        vm_type = self._determine_vm_type(handlers)
        structure["vm_type"] = vm_type

        # Find handler table
        handler_table = self._find_handler_table()
        if handler_table:
            structure["handler_table"] = handler_table

        # Find VM context structure
        vm_context = self._find_vm_context(handlers)
        if vm_context:
            structure["vm_context"] = vm_context

        # Calculate confidence
        confidence = self._calculate_structure_confidence(structure)
        structure["confidence"] = confidence

        return structure

    def _find_dispatcher(self, handlers):
        """Find the VM dispatcher function"""

        # Look for function with most cross-references to handlers
        max_refs = 0
        dispatcher = None

        for func_ea in idautils.Functions():
            ref_count = 0

            # Count references to handler functions
            for handler in handlers:
                for ref in idautils.CodeRefsTo(handler["address"], 0):
                    if idc.get_func_attr(ref, idc.FUNCATTR_START) == func_ea:
                        ref_count += 1

            if ref_count > max_refs:
                max_refs = ref_count
                dispatcher = {
                    "address": func_ea,
                    "name": idc.get_func_name(func_ea),
                    "handler_refs": ref_count,
                }

        return dispatcher

    def _determine_vm_type(self, handlers):
        """Determine if VM is stack-based or register-based"""

        stack_indicators = 0
        register_indicators = 0

        for handler in handlers:
            instructions = handler.get("instructions", [])

            for inst in instructions:
                if any(op in inst.lower() for op in ["push", "pop", "esp", "rsp"]):
                    stack_indicators += 1
                if any(reg in inst.lower() for reg in ["eax", "ebx", "ecx", "edx"]):
                    register_indicators += 1

        if stack_indicators > register_indicators * 1.5:
            return "stack_based"
        elif register_indicators > stack_indicators * 1.5:
            return "register_based"
        else:
            return "hybrid"

    def _find_handler_table(self):
        """Find VM handler table in data sections"""

        # Look for arrays of function pointers
        for seg_ea in idautils.Segments():
            seg_name = idc.get_segm_name(seg_ea)

            if "data" in seg_name.lower() or "rodata" in seg_name.lower():
                # Scan for potential handler tables
                for ea in range(seg_ea, idc.get_segm_end(seg_ea), 4):
                    if self._is_function_pointer_array(ea):
                        return {
                            "address": ea,
                            "size": self._get_table_size(ea),
                            "segment": seg_name,
                        }

        return None

    def _is_function_pointer_array(self, ea):
        """Check if address contains array of function pointers"""

        ptr_count = 0
        for i in range(16):  # Check first 16 entries
            try:
                ptr = idc.get_wide_dword(ea + i * 4)
                if idc.get_func_name(ptr):  # Valid function pointer
                    ptr_count += 1
            except:
                break

        return ptr_count >= 4  # At least 4 valid function pointers

    def _get_table_size(self, ea):
        """Get size of handler table"""
        size = 0
        while True:
            try:
                ptr = idc.get_wide_dword(ea + size)
                if not idc.get_func_name(ptr):
                    break
                size += 4
            except:
                break
        return size

    def _find_vm_context(self, handlers):
        """Find VM context structure"""

        # Look for commonly accessed data structures
        data_refs = {}

        for handler in handlers:
            for head in idautils.Heads(
                handler["address"], handler["address"] + handler["size"]
            ):
                if idc.is_code(idc.get_full_flags(head)):
                    for i in range(idc.get_item_size(head)):
                        op_type = idc.get_operand_type(head, i)
                        if op_type in [idc.o_mem, idc.o_displ]:
                            ref_addr = idc.get_operand_value(head, i)
                            data_refs[ref_addr] = data_refs.get(ref_addr, 0) + 1

        # Find most referenced data structure
        if data_refs:
            context_addr = max(data_refs, key=data_refs.get)
            return {
                "address": context_addr,
                "ref_count": data_refs[context_addr],
                "size": self._estimate_structure_size(context_addr),
            }

        return None

    def _estimate_structure_size(self, addr):
        """Estimate size of data structure"""
        # Simple heuristic - look for next defined item
        next_item = idc.next_head(addr)
        if next_item != idc.BADADDR:
            return next_item - addr
        return 64  # Default estimate

    def _calculate_structure_confidence(self, structure):
        """Calculate confidence in VM structure analysis"""

        confidence = 0.0

        # Dispatcher found
        if structure.get("dispatcher_candidates"):
            confidence += 0.3

        # Handler table found
        if structure.get("handler_table"):
            confidence += 0.3

        # VM context found
        if structure.get("vm_context"):
            confidence += 0.2

        # VM type determined
        if structure.get("vm_type") != "unknown":
            confidence += 0.2

        return min(confidence, 1.0)


class TaintFlowAnalyzer:
    """Analyzes taint flows using VMDragonSlayer DTT engine"""

    def __init__(self, config):
        self.config = config
        self.taint_tracker = None

    def initialize_dtt(self):
        """Initialize the DTT engine"""
        try:
            self.taint_tracker = VMTaintTracker()
            return True
        except Exception as e:
            print(f"Failed to initialize DTT engine: {e}")
            return False

    def analyze_taint_flows(self, handlers):
        """Analyze taint flows through VM handlers"""

        if not self.taint_tracker:
            if not self.initialize_dtt():
                return []

        taint_flows = []

        for handler in handlers:
            print(f"Analyzing taint flow for handler at {hex(handler['address'])}")

            # Extract handler bytecode
            bytecode = self._extract_handler_bytecode(handler)

            if bytecode:
                try:
                    # Analyze with DTT engine
                    flow_result = self.taint_tracker.analyze_handler_flow(
                        handler["address"], bytecode
                    )

                    if flow_result:
                        taint_flows.append(
                            {
                                "handler_address": handler["address"],
                                "sources": flow_result.get("taint_sources", []),
                                "sinks": flow_result.get("taint_sinks", []),
                                "flows": flow_result.get("taint_flows", []),
                                "confidence": flow_result.get("confidence", 0.0),
                            }
                        )

                except Exception as e:
                    print(f"Error analyzing handler {hex(handler['address'])}: {e}")

        return taint_flows

    def _extract_handler_bytecode(self, handler):
        """Extract bytecode from handler function"""

        bytecode = []
        func_end = handler["address"] + handler["size"]

        for head in idautils.Heads(handler["address"], func_end):
            if idc.is_code(idc.get_full_flags(head)):
                # Get instruction bytes
                inst_size = idc.get_item_size(head)
                inst_bytes = []

                for i in range(inst_size):
                    inst_bytes.append(idc.get_wide_byte(head + i))

                bytecode.extend(inst_bytes)

        return bytecode


class SymbolicExecutionEngine:
    """Symbolic execution using VMDragonSlayer SE engine"""

    def __init__(self, config):
        self.config = config
        self.se_engine = None

    def initialize_se(self):
        """Initialize the SE engine"""
        try:
            self.se_engine = HandlerLifter()
            return True
        except Exception as e:
            print(f"Failed to initialize SE engine: {e}")
            return False

    def lift_handlers(self, handlers):
        """Lift VM handlers using symbolic execution"""

        if not self.se_engine:
            if not self.initialize_se():
                return []

        lifted_handlers = []

        for handler in handlers:
            print(f"Lifting handler at {hex(handler['address'])}")

            try:
                # Extract handler instructions
                instructions = self._get_handler_instructions(handler)

                # Lift with SE engine
                lifted_result = self.se_engine.lift_vm_handler(
                    handler["address"], instructions
                )

                if lifted_result:
                    lifted_handlers.append(
                        {
                            "handler_address": handler["address"],
                            "lifted_ir": lifted_result.get("ir_code", ""),
                            "semantics": lifted_result.get("semantics", {}),
                            "constraints": lifted_result.get("constraints", []),
                            "confidence": lifted_result.get("confidence", 0.0),
                        }
                    )

            except Exception as e:
                print(f"Error lifting handler {hex(handler['address'])}: {e}")

        return lifted_handlers

    def _get_handler_instructions(self, handler):
        """Get structured instruction data for handler"""

        instructions = []
        func_end = handler["address"] + handler["size"]

        for head in idautils.Heads(handler["address"], func_end):
            if idc.is_code(idc.get_full_flags(head)):
                inst_data = {
                    "address": head,
                    "mnemonic": idc.print_insn_mnem(head),
                    "operands": [],
                    "bytes": [],
                }

                # Get operands
                for i in range(6):  # Max 6 operands
                    op = idc.print_operand(head, i)
                    if op:
                        inst_data["operands"].append(op)

                # Get instruction bytes
                inst_size = idc.get_item_size(head)
                for i in range(inst_size):
                    inst_data["bytes"].append(idc.get_wide_byte(head + i))

                instructions.append(inst_data)

        return instructions


class VMDragonSlayerPlugin(idaapi.plugin_t):
    """VMDragonSlayer IDA Pro plugin with core services integration"""

    flags = idaapi.PLUGIN_UNL
    comment = "VMDragonSlayer - VM Analysis Framework with Core Services"
    help = "Analyze virtual machine protection with DTT, SE, ML, and core services"
    wanted_name = "VMDragonSlayer"
    wanted_hotkey = "Ctrl-Alt-V"

    def __init__(self):
        self.config = VMDragonSlayerConfig()
        self.results = None
        self.analysis_engines = {}
        self.core_services = CoreServicesManager()
        self.standard_mode = True

        # Initialize UI components
        self.ui_components = self._initialize_ui_components()

    def _initialize_ui_components(self):
        """Initialize UI components"""

        ui_components = {
            "status_indicators": StatusIndicatorPanel(self.core_services),
            "config_dialog": ConfigurationDialog(self.config, self.core_services),
            "metrics_dashboard": MetricsDashboard(self.core_services),
            "progress_tracker": ProgressTracker(),
            "service_manager": ServiceManagerPanel(self.core_services),
        }

        # Initialize status indicators
        ui_components["status_indicators"].create_status_indicators()

        print("UI components initialized for user experience")
        return ui_components

    def get_ui_status_summary(self):
        """Get UI status summary for display"""

        if not self.ui_components:
            return {"status": "unavailable", "message": "UI components not initialized"}

        status_summary = self.ui_components[
            "status_indicators"
        ].get_service_status_summary()
        metrics = self.ui_components["metrics_dashboard"].update_metrics_display()
        active_operations = self.ui_components[
            "progress_tracker"
        ].get_active_operations()

        return {
            "service_status": status_summary,
            "metrics_available": len(metrics["dashboard"]) > 0,
            "active_operations": len(active_operations),
            "ui_mode": "standard" if self.standard_mode else "basic",
        }

    def show_ui_dashboard(self):
        """Show the UI dashboard with all components"""

        try:
            # Get current system status
            ui_status = self.get_ui_status_summary()

            # Update all UI components
            status_indicators = self.ui_components[
                "status_indicators"
            ].update_service_status_indicators()
            metrics = self.ui_components["metrics_dashboard"].update_metrics_display()
            service_controls = self.ui_components[
                "service_manager"
            ].create_service_controls()

            # Create dashboard display (in real implementation, this would be a proper IDA Pro widget)
            dashboard_data = {
                "timestamp": time.time(),
                "ui_status": ui_status,
                "service_indicators": status_indicators,
                "metrics": metrics,
                "service_controls": service_controls,
            }

            print("UI Dashboard")
            print("=" * 50)
            print(f"UI Status: {ui_status['ui_mode']} mode")
            print(
                f"Services: {ui_status['service_status']['available']}/{ui_status['service_status']['total']} available"
            )
            print(f"Active Operations: {ui_status['active_operations']}")
            print(f"System Health: {ui_status['service_status']['status']}")

            # In real implementation, this would display the actual IDA Pro UI
            return dashboard_data

        except Exception as e:
            print(f"UI dashboard failed: {e}")
            return None

    def init(self):
        """Initialize plugin"""
        print("VMDragonSlayer plugin loaded")
        return idaapi.PLUGIN_OK

    def term(self):
        """Terminate plugin"""
        print("VMDragonSlayer plugin unloaded")

    def run(self, arg):
        """Run plugin analysis"""
        print("Starting VMDragonSlayer analysis...")

        # Show configuration dialog
        if not self._show_config_dialog():
            return

        # Initialize analysis engines
        self._initialize_engines()

        # Run comprehensive analysis
        results = self._run_comprehensive_analysis()

        # Display results
        self._display_results(results)

    def _show_config_dialog(self):
        """Show configuration dialog"""

        form = """VMDragonSlayer Configuration
        
        <Enable DTT Analysis:{chkDTT}>
        <Enable SE Analysis:{chkSE}>
        <Enable Anti-Analysis:{chkAnti}>
        <Enable VM Discovery:{chkVM}>
        
        <Analysis Timeout:{intTimeout}>
        <Max Handlers:{intHandlers}>
        <Confidence Threshold:{floatConfidence}>
        
        <Output Format:{rOutput}>
        """

        dlg = ida_kernwin.Form(
            form,
            {
                "chkDTT": ida_kernwin.Form.ChkGroupControl(("DTT", "SE", "Anti", "VM")),
                "chkSE": ida_kernwin.Form.ChkGroupControl(("DTT", "SE", "Anti", "VM")),
                "chkAnti": ida_kernwin.Form.ChkGroupControl(
                    ("DTT", "SE", "Anti", "VM")
                ),
                "chkVM": ida_kernwin.Form.ChkGroupControl(("DTT", "SE", "Anti", "VM")),
                "intTimeout": ida_kernwin.Form.NumericInput(
                    tp=ida_kernwin.Form.FT_UINT32
                ),
                "intHandlers": ida_kernwin.Form.NumericInput(
                    tp=ida_kernwin.Form.FT_UINT32
                ),
                "floatConfidence": ida_kernwin.Form.NumericInput(
                    tp=ida_kernwin.Form.FT_FLOAT
                ),
                "rOutput": ida_kernwin.Form.RadGroupControl(("JSON", "XML", "HTML")),
            },
        )

        dlg.Compile()

        # Set default values
        dlg.intTimeout.value = self.config.analysis_timeout
        dlg.intHandlers.value = self.config.max_handlers
        dlg.floatConfidence.value = self.config.confidence_threshold

        if dlg.Execute() != 1:
            dlg.Free()
            return False

        # Update configuration
        self.config.analysis_timeout = dlg.intTimeout.value
        self.config.max_handlers = dlg.intHandlers.value
        self.config.confidence_threshold = dlg.floatConfidence.value

        output_formats = ["json", "xml", "html"]
        self.config.output_format = output_formats[dlg.rOutput.selected]

        dlg.Free()
        return True

    def _initialize_engines(self):
        """Initialize analysis engines with unified API support"""

        # Basic engines that are plugin-specific
        self.analysis_engines = {
            "handler_analyzer": VMHandlerAnalyzer(self.config),
            "structure_analyzer": VMStructureAnalyzer(self.config),
            "taint_analyzer": TaintFlowAnalyzer(self.config),
            "se_engine": SymbolicExecutionEngine(self.config),
        }

        # Initialize advanced engines through unified API if available
        if self.core_services.unified_api:
            try:
                # Use optimized components from unified API
                self.analysis_engines["orchestrator"] = self.core_services.get_service(
                    "orchestrator"
                )
                self.analysis_engines["ml_engine"] = self.core_services.get_service(
                    "ml_engine"
                )
                self.analysis_engines["dtt_executor"] = self.core_services.get_service(
                    "dtt_executor"
                )
                print("✓ Unified API analysis engines initialized")
            except Exception as e:
                print(f"Warning: Could not initialize unified API engines: {e}")

        # Fallback to legacy components if unified API unavailable
        if "orchestrator" not in self.analysis_engines and LEGACY_COMPONENTS_AVAILABLE:
            try:
                self.analysis_engines["semantic_engine"] = SemanticPatternRecognizer()
                self.analysis_engines["orchestrator"] = AnalysisOrchestrator()
                print("✓ Legacy analysis engines initialized")
            except Exception as e:
                print(f"Warning: Could not initialize legacy engines: {e}")

    def _run_comprehensive_analysis(self):
        """Run comprehensive VM analysis"""

        start_time = time.time()
        results = VMDragonSlayerResults()

        print("Step 1: Handler Discovery")
        handler_analyzer = self.analysis_engines["handler_analyzer"]
        handlers = handler_analyzer.find_vm_handlers()
        results.vm_handlers = handlers

        if not handlers:
            print("No VM handlers found!")
            return results

        print("Step 2: VM Structure Analysis")
        structure_analyzer = self.analysis_engines.get("structure_analyzer")
        if structure_analyzer:
            vm_structure = structure_analyzer.analyze_vm_structure(handlers)
            results.metadata["vm_structure"] = vm_structure

        print("Step 3: Taint Flow Analysis")
        if self.config.enable_dtt:
            taint_analyzer = self.analysis_engines["taint_analyzer"]
            taint_flows = taint_analyzer.analyze_taint_flows(handlers)
            results.taint_flows = taint_flows

        print("Step 4: Symbolic Execution")
        if self.config.enable_se:
            se_engine = self.analysis_engines["se_engine"]
            lifted_handlers = se_engine.lift_handlers(handlers)
            results.metadata["lifted_handlers"] = lifted_handlers

        print("Step 5: Semantic Analysis")
        semantic_engine = self.analysis_engines.get("semantic_engine")
        if semantic_engine:
            try:
                semantic_patterns = semantic_engine.analyze_patterns(handlers)
                results.metadata["semantic_patterns"] = semantic_patterns
            except Exception as e:
                print(f"Semantic analysis failed: {e}")

        print("Step 6: Result Integration")
        orchestrator = self.analysis_engines.get("orchestrator")
        if orchestrator:
            try:
                integrated_results = orchestrator.integrate_results(results)
                results.confidence_score = integrated_results.get("confidence", 0.0)
                results.metadata.update(integrated_results.get("metadata", {}))
            except Exception as e:
                print(f"Result integration failed: {e}")

        results.analysis_time = time.time() - start_time
        print(f"Analysis completed in {results.analysis_time:.2f} seconds")

        return results

    def analyze_with_core_services(self):
        """Analysis using core services with UI progress tracking"""

        if not self.standard_mode:
            return self._run_comprehensive_analysis()

        print("Starting analysis with core services...")

        # Start progress tracking
        operation_id = self.ui_components["progress_tracker"].start_analysis_progress(
            "vm_analysis",
            "VM Analysis with Core Services",
            estimated_duration=60,  # 1 minute estimate
        )

        try:
            # Check core service availability
            service_status = self.core_services.get_service_status()
            available_services = sum(
                1 for available in service_status.values() if available
            )
            total_services = len(service_status)

            if available_services == 0:
                print("No core services available, falling back to basic analysis")
                self.standard_mode = False
                self.ui_components["progress_tracker"].update_progress(
                    operation_id, 100, "Fallback to basic analysis complete"
                )
                result = self._run_comprehensive_analysis()
                self.ui_components["progress_tracker"].complete_operation(
                    operation_id, True, "Analysis completed in basic mode"
                )
                return result

            print(
                f"Core services status: {available_services}/{total_services} available"
            )

            # Update progress: 10%
            self.ui_components["progress_tracker"].update_progress(
                operation_id, 10, "Core services validated", 1, 6
            )

            # Start GPU profiling if available
            gpu_profiler = self.core_services.get_service("gpu_profiler")
            if gpu_profiler:
                try:
                    gpu_profiler.start_profiling()
                    print("✓ GPU profiling started")
                except Exception as e:
                    print(f"✗ GPU profiling failed: {e}")

            # Update progress: 15%
            self.ui_components["progress_tracker"].update_progress(
                operation_id, 15, "GPU profiling initialized", 2, 6
            )

            # Run analysis
            start_time = time.time()
            results = VMDragonSlayerResults()

            # Step 1: Handler Discovery with Pattern Database
            print("Step 1: Handler Discovery")
            self.ui_components["progress_tracker"].update_progress(
                operation_id, 20, "Discovering VM handlers", 3, 6
            )

            handler_analyzer = self.analysis_engines["handler_analyzer"]
            handlers = handler_analyzer.find_vm_handlers()

            # Enhance handlers with pattern matching
            pattern_db = self.core_services.get_service("pattern_database")
            if pattern_db and handlers:
                for i, handler in enumerate(handlers):
                    try:
                        patterns = pattern_db.match_patterns(
                            handler.get("instructions", [])
                        )
                        handler["pattern_matches"] = patterns
                        # Update confidence based on pattern matches
                        if patterns:
                            pattern_confidence = sum(
                                p.get("confidence", 0) for p in patterns
                            ) / len(patterns)
                            handler["confidence"] = max(
                                handler.get("confidence", 0), pattern_confidence
                            )
                    except Exception as e:
                        print(
                            f"Pattern matching failed for handler {handler.get('name', 'unknown')}: {e}"
                        )

                    # Update sub-progress
                    handler_progress = 20 + (15 * (i + 1) / len(handlers))
                    self.ui_components["progress_tracker"].update_progress(
                        operation_id,
                        handler_progress,
                        f"Processing handler {i+1}/{len(handlers)}",
                    )

            results.vm_handlers = handlers

            if not handlers:
                print("No VM handlers found!")
                self.ui_components["progress_tracker"].complete_operation(
                    operation_id, False, "No VM handlers detected"
                )
                return self._finalize_analysis(results, start_time)

            # Update progress: 40%
            self.ui_components["progress_tracker"].update_progress(
                operation_id, 40, "VM structure analysis starting", 4, 6
            )

            # Step 2: VM Structure Analysis with validation
            print("Step 2: VM Structure Analysis")
            structure_analyzer = self.analysis_engines.get("structure_analyzer")
            if structure_analyzer:
                vm_structure = structure_analyzer.analyze_vm_structure(handlers)

                # Validate VM structure detection
                validation_framework = self.core_services.get_service(
                    "validation_framework"
                )
                if validation_framework:
                    try:
                        validation_result = validation_framework.validate_vm_detection(
                            vm_structure.get("vm_type", "Unknown"),
                            "IDA_Analysis",
                            vm_structure.get("confidence", 0.0),
                        )
                        vm_structure["validation"] = validation_result
                        print(
                            f"✓ VM structure validation score: {validation_result.get('score', 0.0):.2f}"
                        )
                    except Exception as e:
                        print(f"✗ VM structure validation failed: {e}")

                results.metadata["vm_structure"] = vm_structure

            # Update progress: 60%
            self.ui_components["progress_tracker"].update_progress(
                operation_id, 60, "Analysis steps", 5, 6
            )

            # Step 3-5: Analysis steps (condensed for UI demo)
            print("Step 3: Taint Flow Analysis")
            if self.config.enable_dtt:
                taint_analyzer = self.analysis_engines["taint_analyzer"]
                taint_flows = taint_analyzer.analyze_taint_flows(handlers)
                results.taint_flows = taint_flows

            print("Step 4: Symbolic Execution")
            if self.config.enable_se:
                se_engine = self.analysis_engines["se_engine"]
                lifted_handlers = se_engine.lift_handlers(handlers)
                results.metadata["lifted_handlers"] = lifted_handlers

            print("Step 5: Semantic Analysis")
            semantic_engine = self.analysis_engines.get("semantic_engine")
            if semantic_engine:
                try:
                    semantic_patterns = semantic_engine.analyze_patterns(handlers)
                    results.metadata["semantic_patterns"] = semantic_patterns
                except Exception as e:
                    print(f"Semantic analysis failed: {e}")

            # Update progress: 80%
            self.ui_components["progress_tracker"].update_progress(
                operation_id, 80, "Finalizing analysis results", 6, 6
            )

            # Step 6: Result Integration and Storage
            print("Step 6: Result Integration")
            orchestrator = self.analysis_engines.get("orchestrator")
            if orchestrator:
                try:
                    integrated_results = orchestrator.integrate_results(results)
                    results.confidence_score = integrated_results.get("confidence", 0.0)
                except Exception as e:
                    print(f"Result integration failed: {e}")

            # Store analysis in database if available
            sample_db = self.core_services.get_service("sample_database")
            if sample_db and self.config.auto_store_samples:
                try:
                    binary_name = ida_nalt.get_root_filename()
                    sample_data = {
                        "binary_name": binary_name,
                        "handlers": handlers,
                        "vm_structure": results.metadata.get("vm_structure", {}),
                        "confidence_score": results.confidence_score,
                        "analysis_timestamp": time.time(),
                        "analysis_tool": "IDA_Pro",
                    }
                    sample_db.store_sample(binary_name, sample_data)
                    print("✓ Analysis results stored in database")
                except Exception as e:
                    print(f"✗ Database storage failed: {e}")

            # Complete progress tracking
            self.ui_components["progress_tracker"].complete_operation(
                operation_id,
                True,
                f"Analysis completed successfully with {len(handlers)} handlers",
            )

            return self._finalize_analysis(results, start_time)

        except Exception as e:
            print(f"Analysis failed: {e}")
            print("Falling back to basic analysis...")
            self.standard_mode = False

            # Mark operation as failed
            self.ui_components["progress_tracker"].complete_operation(
                operation_id, False, f"Analysis failed: {e}"
            )

            return self._run_comprehensive_analysis()

    def _finalize_analysis(self, results, start_time):
        """Finalize analysis with core services"""

        # Stop GPU profiling and get metrics
        gpu_profiler = self.core_services.get_service("gpu_profiler")
        if gpu_profiler:
            try:
                gpu_metrics = gpu_profiler.stop_profiling()
                results.metadata["gpu_metrics"] = gpu_metrics
                print(
                    f"✓ GPU metrics: {gpu_metrics.get('execution_time', 0):.3f}s execution time"
                )
            except Exception as e:
                print(f"✗ GPU profiling finalization failed: {e}")

        # Calculate final metrics
        results.analysis_time = time.time() - start_time

        # Generate validation summary
        validation_framework = self.core_services.get_service("validation_framework")
        if validation_framework:
            try:
                # Overall analysis validation
                overall_validation = validation_framework.validate_vm_detection(
                    results.metadata.get("vm_structure", {}).get("vm_type", "Unknown"),
                    "IDA_Analysis",
                    results.confidence_score,
                )
                results.metadata["overall_validation"] = overall_validation
                print(
                    f"✓ Overall validation score: {overall_validation.get('score', 0.0):.2f}"
                )
            except Exception as e:
                print(f"✗ Overall validation failed: {e}")

        print(f"Analysis completed in {results.analysis_time:.2f} seconds")
        print(f"Final confidence score: {results.confidence_score:.2f}")

        return results

    def check_core_service_availability(self):
        """Check which core services are available"""
        return self.core_services.get_service_status()

    def get_core_service_metrics(self):
        """Get real-time metrics from core services"""
        metrics = {}

        # GPU metrics
        gpu_profiler = self.core_services.get_service("gpu_profiler")
        if gpu_profiler:
            try:
                metrics["gpu"] = gpu_profiler.get_current_metrics()
            except Exception:
                metrics["gpu"] = {"status": "unavailable"}

        # Database metrics
        sample_db = self.core_services.get_service("sample_database")
        if sample_db:
            try:
                metrics["database"] = sample_db.get_statistics()
            except Exception:
                metrics["database"] = {"status": "unavailable"}

        # Pattern database metrics
        pattern_db = self.core_services.get_service("pattern_database")
        if pattern_db:
            try:
                metrics["patterns"] = pattern_db.get_pattern_statistics()
            except Exception:
                metrics["patterns"] = {"status": "unavailable"}
        else:
            metrics["patterns"] = {"status": "unavailable"}

        return metrics

    def _show_config_dialog(self):
        """Show configuration dialog with core services options"""

        # Get core service status for display
        service_status = self.check_core_service_availability()

        # Create form with core services section
        form = f"""VMDragonSlayer Configuration
        
        Analysis Options:
        <Enable DTT Analysis:{chkDTT}>
        <Enable SE Analysis:{chkSE}>
        <Enable Anti-Analysis:{chkAnti}>
        <Enable VM Discovery:{chkVM}>
        
        Core Services (Available: {sum(service_status.values())}/{len(service_status)}):
        <Enable Sample Database:{chkDB}>
        <Enable Validation Framework:{chkValidation}>
        <Enable GPU Profiler:{chkGPU}>
        <Enable Pattern Database:{chkPatterns}>
        
        Configuration:
        <Analysis Timeout:{intTimeout}>
        <Max Handlers:{intHandlers}>
        <Confidence Threshold:{floatConfidence}>
        <Validation Threshold:{floatValidation}>
        
        Database:
        <Database Path:{strDBPath}>
        <Auto Store Samples:{chkAutoStore}>
        
        GPU Settings:
        <GPU Device ID:{intGPUDevice}>
        
        <Output Format:{rOutput}>
        """

        try:
            dlg = ida_kernwin.Form(
                form,
                {
                    "chkDTT": ida_kernwin.Form.ChkGroupControl(
                        ("DTT", "SE", "Anti", "VM")
                    ),
                    "chkSE": ida_kernwin.Form.ChkGroupControl(
                        ("DTT", "SE", "Anti", "VM")
                    ),
                    "chkAnti": ida_kernwin.Form.ChkGroupControl(
                        ("DTT", "SE", "Anti", "VM")
                    ),
                    "chkVM": ida_kernwin.Form.ChkGroupControl(
                        ("DTT", "SE", "Anti", "VM")
                    ),
                    "chkDB": ida_kernwin.Form.ChkGroupControl(
                        ("DB", "Val", "GPU", "Pat")
                    ),
                    "chkValidation": ida_kernwin.Form.ChkGroupControl(
                        ("DB", "Val", "GPU", "Pat")
                    ),
                    "chkGPU": ida_kernwin.Form.ChkGroupControl(
                        ("DB", "Val", "GPU", "Pat")
                    ),
                    "chkPatterns": ida_kernwin.Form.ChkGroupControl(
                        ("DB", "Val", "GPU", "Pat")
                    ),
                    "intTimeout": ida_kernwin.Form.NumericInput(
                        tp=ida_kernwin.Form.FT_UINT32
                    ),
                    "intHandlers": ida_kernwin.Form.NumericInput(
                        tp=ida_kernwin.Form.FT_UINT32
                    ),
                    "floatConfidence": ida_kernwin.Form.NumericInput(
                        tp=ida_kernwin.Form.FT_FLOAT
                    ),
                    "floatValidation": ida_kernwin.Form.NumericInput(
                        tp=ida_kernwin.Form.FT_FLOAT
                    ),
                    "strDBPath": ida_kernwin.Form.StringInput(),
                    "chkAutoStore": ida_kernwin.Form.ChkGroupControl(("AutoStore",)),
                    "intGPUDevice": ida_kernwin.Form.NumericInput(
                        tp=ida_kernwin.Form.FT_UINT32
                    ),
                    "rOutput": ida_kernwin.Form.RadGroupControl(
                        ("JSON", "XML", "HTML")
                    ),
                },
            )

            dlg.Compile()

            # Set default values
            dlg.intTimeout.value = self.config.analysis_timeout
            dlg.intHandlers.value = self.config.max_handlers
            dlg.floatConfidence.value = self.config.confidence_threshold
            dlg.floatValidation.value = self.config.validation_threshold
            dlg.strDBPath.value = self.config.database_path
            dlg.intGPUDevice.value = self.config.gpu_device_id

            if dlg.Execute() != 1:
                dlg.Free()
                return False

            # Update configuration from dialog
            self.config.analysis_timeout = dlg.intTimeout.value
            self.config.max_handlers = dlg.intHandlers.value
            self.config.confidence_threshold = dlg.floatConfidence.value
            self.config.validation_threshold = dlg.floatValidation.value
            self.config.database_path = dlg.strDBPath.value
            self.config.auto_store_samples = dlg.chkAutoStore.checked
            self.config.gpu_device_id = dlg.intGPUDevice.value

            dlg.Free()
            return True

        except Exception as e:
            print(f"Configuration dialog failed: {e}")
            return False

    def _display_results(self, results):
        """Display results with core service metrics"""

        # Get real-time metrics from core services
        core_metrics = self.get_core_service_metrics()

        # Prepare results display
        analysis_results = {
            "basic_results": results,
            "core_service_metrics": core_metrics,
            "service_status": self.check_core_service_availability(),
            "standard_mode": self.standard_mode,
        }

        # Show results form
        self._show_results_form(analysis_results)


class StatusIndicatorPanel:
    """Real-time status indicators for core services"""

    def __init__(self, core_services_manager):
        self.core_services = core_services_manager
        self.indicators = {}
        self.update_timer = None
        self.refresh_interval = 2000  # 2 seconds

    def create_status_indicators(self):
        """Create visual status indicators for all core services"""

        # Service status indicators
        services = [
            "sample_database",
            "validation_framework",
            "gpu_profiler",
            "pattern_database",
        ]

        for service in services:
            indicator = {
                "service_name": service,
                "status_color": "red",
                "status_text": "Unavailable",
                "tooltip": f"{service}: Not initialized",
            }
            self.indicators[service] = indicator

        # Start real-time updates
        self.start_status_updates()

    def update_service_status_indicators(self):
        """Update visual status indicators for all core services"""

        service_status = self.core_services.get_service_status()

        for service_name, available in service_status.items():
            if service_name in self.indicators:
                indicator = self.indicators[service_name]

                if available:
                    indicator["status_color"] = "green"
                    indicator["status_text"] = "Available"
                    indicator["tooltip"] = f"{service_name}: Service running normally"
                else:
                    indicator["status_color"] = "red"
                    indicator["status_text"] = "Unavailable"
                    indicator["tooltip"] = f"{service_name}: Service not available"

        return self.indicators

    def start_status_updates(self):
        """Start automatic status updates"""
        self.update_service_status_indicators()
        # In a real IDA Pro plugin, this would use IDA's timer system
        print("Status indicators started (refresh every 2 seconds)")

    def stop_status_updates(self):
        """Stop automatic status updates"""
        if self.update_timer:
            # Cancel timer in real implementation
            pass
        print("Status indicators stopped")

    def get_service_status_summary(self):
        """Get summary of service status for display"""
        available_services = sum(
            1
            for indicator in self.indicators.values()
            if indicator["status_color"] == "green"
        )
        total_services = len(self.indicators)

        return {
            "available": available_services,
            "total": total_services,
            "status": "healthy" if available_services == total_services else "partial",
        }


class ConfigurationDialog:
    """Enhanced configuration dialog with core services support"""

    def __init__(self, config, core_services_manager):
        self.config = config
        self.core_services = core_services_manager
        self.dialog_controls = {}

    def create_enhanced_config_dialog(self):
        """Create enhanced configuration dialog with tabbed interface"""

        # Get current service status for display
        service_status = self.core_services.get_service_status()
        available_count = sum(1 for available in service_status.values() if available)
        total_count = len(service_status)

        # Enhanced form with real-time service status
        form_template = """VMDragonSlayer Enhanced Configuration
        
        === Analysis Options ===
        <Enable DTT Analysis                 :{chkDTT}>
        <Enable SE Analysis                  :{chkSE}>
        <Enable Anti-Analysis Detection      :{chkAnti}>
        <Enable VM Discovery                 :{chkVM}>
        
        === Core Services (%d/%d Available) ===
        <Sample Database                     :{chkDB}%s>
        <Validation Framework                :{chkValidation}%s>
        <GPU Profiler                        :{chkGPU}%s>
        <Pattern Database                    :{chkPatterns}%s>
        
        === Performance Settings ===
        <Analysis Timeout (seconds)          :{intTimeout}>
        <Maximum Handlers                    :{intHandlers}>
        <Confidence Threshold                :{floatConfidence}>
        <Validation Threshold                :{floatValidation}>
        
        === Database Configuration ===
        <Database Path                       :{strDBPath}>
        <Auto Store Analysis Results         :{chkAutoStore}>
        
        === GPU Settings ===
        <GPU Device ID                       :{intGPUDevice}>
        <Real-time Metrics                   :{chkRealTimeMetrics}>
        
        === Output Options ===
        <Output Format                       :{rOutput}>
        """

        # Format with service availability status
        db_status = " ✓" if service_status.get("sample_database") else " ✗"
        val_status = " ✓" if service_status.get("validation_framework") else " ✗"
        gpu_status = " ✓" if service_status.get("gpu_profiler") else " ✗"
        pattern_status = " ✓" if service_status.get("pattern_database") else " ✗"

        form = form_template % (
            available_count,
            total_count,
            db_status,
            val_status,
            gpu_status,
            pattern_status,
        )

        return form

    def show_enhanced_config_dialog(self):
        """Show enhanced configuration dialog with validation"""

        form = self.create_enhanced_config_dialog()

        try:
            # Create dialog controls (simplified for demo)
            dialog_config = {
                "form": form,
                "analysis_options": {
                    "dtt_enabled": self.config.enable_dtt,
                    "se_enabled": self.config.enable_se,
                    "anti_analysis_enabled": self.config.enable_anti_analysis,
                    "vm_discovery_enabled": self.config.enable_vm_discovery,
                },
                "core_services": {
                    "database_enabled": self.config.enable_sample_database,
                    "validation_enabled": self.config.enable_validation_framework,
                    "gpu_enabled": self.config.enable_gpu_profiler,
                    "patterns_enabled": self.config.enable_pattern_database,
                },
                "performance": {
                    "timeout": self.config.analysis_timeout,
                    "max_handlers": self.config.max_handlers,
                    "confidence_threshold": self.config.confidence_threshold,
                    "validation_threshold": self.config.validation_threshold,
                },
                "database": {
                    "path": self.config.database_path,
                    "auto_store": self.config.auto_store_samples,
                },
                "gpu": {
                    "device_id": self.config.gpu_device_id,
                    "real_time_metrics": self.config.real_time_metrics,
                },
            }

            # In real implementation, this would show IDA Pro dialog
            print("Enhanced configuration dialog created")
            print(f"Configuration preview: {json.dumps(dialog_config, indent=2)}")

            return True

        except Exception as e:
            print(f"Enhanced configuration dialog failed: {e}")
            return False

    def validate_configuration(self, config_data):
        """Validate configuration values in real-time"""

        validation_results = {"valid": True, "errors": [], "warnings": []}

        # Validate timeout
        if config_data.get("timeout", 0) <= 0:
            validation_results["errors"].append("Analysis timeout must be positive")
            validation_results["valid"] = False

        # Validate thresholds
        confidence = config_data.get("confidence_threshold", 0)
        if not (0.0 <= confidence <= 1.0):
            validation_results["errors"].append(
                "Confidence threshold must be between 0.0 and 1.0"
            )
            validation_results["valid"] = False

        # Validate database path
        db_path = config_data.get("database_path", "")
        if config_data.get("database_enabled") and not db_path:
            validation_results["warnings"].append(
                "Database path is empty but database is enabled"
            )

        return validation_results


class MetricsDashboard:
    """Real-time metrics display for core services"""

    def __init__(self, core_services_manager):
        self.core_services = core_services_manager
        self.metrics_history = []
        self.max_history = 100  # Keep last 100 metric points

    def create_metrics_dashboard(self):
        """Create real-time metrics display components"""

        dashboard_components = {
            "gpu_metrics": self.create_gpu_metrics_panel(),
            "database_metrics": self.create_database_metrics_panel(),
            "pattern_metrics": self.create_pattern_metrics_panel(),
            "validation_metrics": self.create_validation_metrics_panel(),
            "overall_metrics": self.create_overall_metrics_panel(),
        }

        return dashboard_components

    def create_gpu_metrics_panel(self):
        """Create GPU metrics display panel"""

        gpu_profiler = self.core_services.get_service("gpu_profiler")

        if gpu_profiler:
            try:
                metrics = gpu_profiler.get_current_metrics()
                panel = {
                    "title": "GPU Performance",
                    "status": "active",
                    "metrics": {
                        "execution_time": f"{metrics.get('execution_time', 0):.3f}s",
                        "memory_used": f"{metrics.get('current_memory', 0)}MB",
                        "peak_memory": f"{metrics.get('peak_memory', 0)}MB",
                        "gpu_utilization": f"{metrics.get('gpu_utilization', 0)*100:.1f}%",
                    },
                }
            except Exception as e:
                panel = {"title": "GPU Performance", "status": "error", "error": str(e)}
        else:
            panel = {
                "title": "GPU Performance",
                "status": "unavailable",
                "message": "GPU Profiler not available",
            }

        return panel

    def create_database_metrics_panel(self):
        """Create database metrics display panel"""

        sample_db = self.core_services.get_service("sample_database")

        if sample_db:
            try:
                stats = sample_db.get_statistics()
                panel = {
                    "title": "Sample Database",
                    "status": "active",
                    "metrics": {
                        "total_samples": stats.get("total_samples", 0),
                        "unique_families": stats.get("unique_families", 0),
                        "analysis_results": stats.get("analysis_results", 0),
                        "database_size": f"{stats.get('database_size_mb', 0):.1f}MB",
                    },
                }
            except Exception as e:
                panel = {"title": "Sample Database", "status": "error", "error": str(e)}
        else:
            panel = {
                "title": "Sample Database",
                "status": "unavailable",
                "message": "Sample Database not available",
            }

        return panel

    def create_pattern_metrics_panel(self):
        """Create pattern database metrics panel"""

        pattern_db = self.core_services.get_service("pattern_database")

        if pattern_db:
            try:
                stats = pattern_db.get_pattern_statistics()
                panel = {
                    "title": "Pattern Database",
                    "status": "active",
                    "metrics": {
                        "total_patterns": stats.get("total_patterns", 0),
                        "vm_patterns": stats.get("vm_patterns", 0),
                        "match_accuracy": f"{stats.get('match_accuracy', 0)*100:.1f}%",
                        "last_updated": stats.get("last_updated", "Unknown"),
                    },
                }
            except Exception as e:
                panel = {
                    "title": "Pattern Database",
                    "status": "error",
                    "error": str(e),
                }
        else:
            panel = {
                "title": "Pattern Database",
                "status": "unavailable",
                "message": "Pattern Database not available",
            }

        return panel

    def create_validation_metrics_panel(self):
        """Create validation framework metrics panel"""

        validation_fw = self.core_services.get_service("validation_framework")

        if validation_fw:
            try:
                # Get validation statistics (simulated)
                panel = {
                    "title": "Validation Framework",
                    "status": "active",
                    "metrics": {
                        "validations_performed": 0,
                        "average_confidence": "0.0%",
                        "false_positive_rate": "0.0%",
                        "validation_accuracy": "0.0%",
                    },
                }
            except Exception as e:
                panel = {
                    "title": "Validation Framework",
                    "status": "error",
                    "error": str(e),
                }
        else:
            panel = {
                "title": "Validation Framework",
                "status": "unavailable",
                "message": "Validation Framework not available",
            }

        return panel

    def create_overall_metrics_panel(self):
        """Create overall system metrics panel"""

        service_status = self.core_services.get_service_status()
        available_services = sum(
            1 for available in service_status.values() if available
        )
        total_services = len(service_status)

        panel = {
            "title": "System Overview",
            "status": "active",
            "metrics": {
                "services_available": f"{available_services}/{total_services}",
                "system_health": (
                    "Healthy" if available_services == total_services else "Partial"
                ),
                "uptime": "0:00:00",  # Would be calculated in real implementation
                "memory_usage": "Unknown",
            },
        }

        return panel

    def update_metrics_display(self):
        """Update all metrics displays with current data"""

        current_metrics = {
            "timestamp": time.time(),
            "dashboard": self.create_metrics_dashboard(),
        }

        # Add to history
        self.metrics_history.append(current_metrics)

        # Keep only recent history
        if len(self.metrics_history) > self.max_history:
            self.metrics_history.pop(0)

        return current_metrics


class ProgressTracker:
    """Visual progress tracking for analysis operations"""

    def __init__(self):
        self.current_operations = {}
        self.operation_history = []

    def start_analysis_progress(
        self, operation_id, operation_name, estimated_duration=None
    ):
        """Start tracking progress for an analysis operation"""

        operation = {
            "id": operation_id,
            "name": operation_name,
            "start_time": time.time(),
            "estimated_duration": estimated_duration,
            "current_step": "Initializing",
            "progress_percentage": 0,
            "status": "running",
            "cancellable": True,
            "steps_completed": 0,
            "total_steps": 0,
        }

        self.current_operations[operation_id] = operation
        print(f"Started tracking: {operation_name}")

        return operation_id

    def update_progress(
        self,
        operation_id,
        percentage,
        current_step,
        steps_completed=None,
        total_steps=None,
    ):
        """Update progress for an ongoing operation"""

        if operation_id not in self.current_operations:
            return False

        operation = self.current_operations[operation_id]
        operation["progress_percentage"] = min(100, max(0, percentage))
        operation["current_step"] = current_step

        if steps_completed is not None:
            operation["steps_completed"] = steps_completed
        if total_steps is not None:
            operation["total_steps"] = total_steps

        # Calculate estimated time remaining
        if operation["estimated_duration"] and percentage > 0:
            elapsed_time = time.time() - operation["start_time"]
            estimated_total = elapsed_time / (percentage / 100)
            operation["estimated_remaining"] = max(0, estimated_total - elapsed_time)

        print(
            f"Progress update: {operation['name']} - {percentage:.1f}% - {current_step}"
        )

        return True

    def complete_operation(self, operation_id, success=True, final_message=None):
        """Mark an operation as completed"""

        if operation_id not in self.current_operations:
            return False

        operation = self.current_operations[operation_id]
        operation["status"] = "completed" if success else "failed"
        operation["end_time"] = time.time()
        operation["duration"] = operation["end_time"] - operation["start_time"]
        operation["progress_percentage"] = (
            100 if success else operation["progress_percentage"]
        )

        if final_message:
            operation["final_message"] = final_message

        # Move to history
        self.operation_history.append(operation.copy())
        del self.current_operations[operation_id]

        print(
            f"Operation completed: {operation['name']} - {'Success' if success else 'Failed'}"
        )

        return True

    def cancel_operation(self, operation_id):
        """Cancel an ongoing operation"""

        if operation_id not in self.current_operations:
            return False

        operation = self.current_operations[operation_id]

        if not operation.get("cancellable", False):
            return False

        operation["status"] = "cancelled"
        operation["end_time"] = time.time()
        operation["duration"] = operation["end_time"] - operation["start_time"]

        # Move to history
        self.operation_history.append(operation.copy())
        del self.current_operations[operation_id]

        print(f"Operation cancelled: {operation['name']}")

        return True

    def get_active_operations(self):
        """Get all currently active operations"""
        return self.current_operations.copy()

    def get_operation_history(self, limit=10):
        """Get recent operation history"""
        return self.operation_history[-limit:] if self.operation_history else []


class ServiceManagerPanel:
    """UI panel for managing core services"""

    def __init__(self, core_services_manager):
        self.core_services = core_services_manager
        self.service_logs = {}

    def create_service_controls(self):
        """Create service management controls"""

        services = [
            "sample_database",
            "validation_framework",
            "gpu_profiler",
            "pattern_database",
        ]
        service_controls = {}

        for service_name in services:
            available = self.core_services.is_service_available(service_name)
            service = self.core_services.get_service(service_name)

            control = {
                "service_name": service_name,
                "display_name": service_name.replace("_", " ").title(),
                "available": available,
                "status": "running" if available else "stopped",
                "actions": {
                    "restart": available,
                    "configure": True,
                    "view_logs": True,
                    "diagnostics": available,
                },
                "info": self.get_service_info(service_name, service),
            }

            service_controls[service_name] = control

        return service_controls

    def get_service_info(self, service_name, service):
        """Get detailed service information"""

        info = {
            "type": service_name,
            "status": "Unknown",
            "version": "Unknown",
            "uptime": "Unknown",
            "memory_usage": "Unknown",
            "last_error": None,
        }

        if service:
            try:
                # Try to get service-specific information
                if hasattr(service, "get_status"):
                    status_info = service.get_status()
                    info.update(status_info)
                else:
                    info["status"] = "Running"
            except Exception as e:
                info["last_error"] = str(e)
                info["status"] = "Error"
        else:
            info["status"] = "Not Available"

        return info

    def restart_service(self, service_name):
        """Restart a specific service"""

        try:
            # In real implementation, this would properly restart the service
            print(f"Restarting service: {service_name}")

            # Simulate restart process
            service = self.core_services.get_service(service_name)
            if service and hasattr(service, "restart"):
                result = service.restart()
                if result:
                    self.log_service_action(
                        service_name,
                        "restart",
                        "success",
                        "Service restarted successfully",
                    )
                    return True
                else:
                    self.log_service_action(
                        service_name, "restart", "error", "Service restart failed"
                    )
                    return False
            else:
                self.log_service_action(
                    service_name,
                    "restart",
                    "warning",
                    "Service does not support restart",
                )
                return False

        except Exception as e:
            self.log_service_action(
                service_name, "restart", "error", f"Restart failed: {e}"
            )
            return False

    def get_service_diagnostics(self, service_name):
        """Get diagnostic information for a service"""

        diagnostics = {
            "service_name": service_name,
            "timestamp": time.time(),
            "health_check": "unknown",
            "performance_metrics": {},
            "error_logs": [],
            "configuration_status": "unknown",
        }

        service = self.core_services.get_service(service_name)

        if service:
            try:
                # Health check
                if hasattr(service, "health_check"):
                    diagnostics["health_check"] = service.health_check()
                else:
                    diagnostics["health_check"] = "available"

                # Performance metrics
                if hasattr(service, "get_performance_metrics"):
                    diagnostics["performance_metrics"] = (
                        service.get_performance_metrics()
                    )

                # Configuration status
                diagnostics["configuration_status"] = "valid"

            except Exception as e:
                diagnostics["health_check"] = "error"
                diagnostics["error_logs"].append(f"Diagnostic error: {e}")
        else:
            diagnostics["health_check"] = "unavailable"
            diagnostics["error_logs"].append("Service not available")

        return diagnostics

    def log_service_action(self, service_name, action, level, message):
        """Log service management actions"""

        if service_name not in self.service_logs:
            self.service_logs[service_name] = []

        log_entry = {
            "timestamp": time.time(),
            "action": action,
            "level": level,
            "message": message,
        }

        self.service_logs[service_name].append(log_entry)

        # Keep only recent logs (last 100 entries)
        if len(self.service_logs[service_name]) > 100:
            self.service_logs[service_name].pop(0)

        print(f"Service log [{service_name}] {level.upper()}: {message}")

    def get_service_logs(self, service_name, limit=20):
        """Get recent logs for a service"""

        if service_name not in self.service_logs:
            return []

        return (
            self.service_logs[service_name][-limit:]
            if limit
            else self.service_logs[service_name]
        )
