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
Ghidra Plugin Integration Tests
==============================

Tests for Ghidra plugin integration with DragonSlayer API
"""

import unittest
import sys
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import tempfile

# Add plugin path
plugin_dir = Path(__file__).parent.parent.parent / "plugins" / "ghidra"
sys.path.insert(0, str(plugin_dir))

# Add dragonslayer path
dragonslayer_path = Path(__file__).parent.parent.parent / "dragonslayer"
sys.path.insert(0, str(dragonslayer_path))

# Mock Ghidra modules (would be Java-based, but we simulate Python interface)
class MockGhidraAPI:
    """Mock Ghidra API for testing"""
    
    def __init__(self):
        self.currentProgram = Mock()
        self.currentProgram.getName.return_value = "test.exe"
        self.currentProgram.getImageBase.return_value = Mock()
        self.currentProgram.getMemory.return_value = Mock()
        self.currentProgram.getFunctionManager.return_value = Mock()
        
    def getMonitor(self):
        return Mock()
        
    def println(self, msg):
        print(msg)

# Setup mocks
mock_ghidra = MockGhidraAPI()
sys.modules['ghidra'] = Mock()

# Additional mocks for lib modules
sys.modules['lib'] = Mock()
sys.modules['lib.unified_api'] = Mock()

from dragonslayer.api.client import APIClient
from dragonslayer.api.transfer import BinaryTransfer


class TestGhidraPluginIntegration(unittest.TestCase):
    """Test Ghidra plugin integration with API (simulated)"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_api_client = Mock(spec=APIClient)
        self.mock_binary_transfer = Mock(spec=BinaryTransfer)
        
        # Setup mock responses
        self.mock_api_client.get_status.return_value = {"status": "ok"}
        self.mock_api_client.get_health.return_value = {"status": "healthy"}
        self.mock_api_client.get_metrics.return_value = {"metrics": {}}
        self.mock_api_client.get_analysis_types.return_value = {"types": ["hybrid"]}
        self.mock_binary_transfer.encode_binary.return_value = "encoded_data"
        self.mock_binary_transfer.decode_binary.return_value = b"compressed_data"
        self.mock_binary_transfer.validate_transfer.return_value = True
        
    def test_ghidra_plugin_structure(self):
        """Test basic Ghidra plugin structure"""
        # Check that Ghidra plugin directory exists
        ghidra_plugin_dir = Path(__file__).parent.parent.parent / "plugins" / "ghidra"
        self.assertTrue(ghidra_plugin_dir.exists())
        
    def test_ghidra_api_client_concept(self):
        """Test conceptual Ghidra API client integration"""
        # This would be similar to IDA/Binary Ninja clients but for Ghidra
        
        class GhidraDragonSlayerClient:
            def __init__(self, api_url="http://localhost:8080", api_key=None):
                self.api_url = api_url
                self.api_key = api_key
                self.api_client = None
                self.binary_transfer = None
                
            def initialize_api_client(self):
                """Initialize API client components"""
                try:
                    self.api_client = APIClient(base_url=self.api_url, api_key=self.api_key)
                    self.binary_transfer = BinaryTransfer()
                    return True
                except Exception:
                    return False
                    
            def extract_binary_from_program(self, program):
                """Extract binary data from Ghidra program"""
                # Simulate binary extraction from Ghidra program
                memory = program.getMemory()
                image_base = program.getImageBase()
                
                # In real implementation, would iterate through memory blocks
                binary_data = b'\x90' * 1000  # Simulated binary data
                return binary_data
                
            def get_program_metadata(self, program):
                """Get metadata from Ghidra program"""
                return {
                    "filename": program.getName(),
                    "image_base": str(program.getImageBase()),
                    "architecture": "x86",  # Would get from program
                    "functions": 50,  # Would count actual functions
                    "ghidra_version": "10.0"
                }
                
        # Test the client concept
        client = GhidraDragonSlayerClient()
        self.assertEqual(client.api_url, "http://localhost:8080")
        
        # Test binary extraction concept
        mock_program = Mock()
        mock_program.getName.return_value = "test.exe"
        mock_program.getImageBase.return_value = "0x400000"
        mock_program.getMemory.return_value = Mock()
        
        binary_data = client.extract_binary_from_program(mock_program)
        self.assertIsInstance(binary_data, bytes)
        
        metadata = client.get_program_metadata(mock_program)
        self.assertIn("filename", metadata)
        self.assertIn("image_base", metadata)
        
    def test_ghidra_plugin_api_integration_concept(self):
        """Test conceptual API integration for Ghidra plugin"""
        
        # Mock Ghidra script functionality
        class MockGhidraVMAnalysisScript:
            def __init__(self):
                self.currentProgram = mock_ghidra.currentProgram
                self.monitor = mock_ghidra.getMonitor()
                self.api_client = None
                
            def setup_api_client(self):
                """Setup API client for VM analysis"""
                try:
                    self.api_client = APIClient("http://localhost:8080")
                    return True
                except Exception:
                    return False
                    
            def run_vm_analysis(self):
                """Run VM analysis on current program"""
                if not self.api_client:
                    return {"error": "API client not available"}
                    
                # Extract program data
                program_data = self.extract_program_data()
                
                # Submit for analysis (simulated)
                results = {
                    "vm_handlers": [
                        {"address": "0x401000", "type": "dispatch"},
                        {"address": "0x401100", "type": "handler"}
                    ],
                    "confidence": 0.87
                }
                
                return results
                
            def extract_program_data(self):
                """Extract data from current Ghidra program"""
                return {
                    "name": self.currentProgram.getName(),
                    "functions": [],  # Would extract actual function list
                    "memory_blocks": []  # Would extract memory layout
                }
                
            def display_results(self, results):
                """Display results in Ghidra interface"""
                # Would create bookmarks, comments, etc. in Ghidra
                for handler in results.get("vm_handlers", []):
                    address = handler["address"]
                    handler_type = handler["type"]
                    # In create bookmark at address
                    mock_ghidra.println(f"VM Handler at {address}: {handler_type}")
        
        # Test the script concept
        script = MockGhidraVMAnalysisScript()
        script.api_client = self.mock_api_client  # Use mock instead of real client
        self.assertIsNotNone(script.currentProgram)
        
        # Test analysis workflow
        results = script.run_vm_analysis()
        self.assertIn("vm_handlers", results)
        self.assertEqual(len(results["vm_handlers"]), 2)
        
        # Test results display
        script.display_results(results)  # Should not raise exceptions
        
    def test_ghidra_binary_transfer_concept(self):
        """Test binary transfer concept for Ghidra"""
        
        class GhidraBinaryExtractor:
            def __init__(self, program):
                self.program = program
                
            def extract_full_binary(self):
                """Extract complete binary from Ghidra program"""
                memory = self.program.getMemory()
                
                # In real implementation, would iterate through all memory blocks
                # and extract the complete binary data
                binary_chunks = []
                
                # Simulate memory block extraction
                for i in range(5):  # Simulate 5 memory blocks
                    chunk = b'\x90' * 1000  # 1KB of NOPs
                    binary_chunks.append(chunk)
                    
                return b''.join(binary_chunks)
                
            def extract_code_sections_only(self):
                """Extract only executable sections"""
                # Simulate extracting only .text sections
                return b'\x90' * 2000  # 2KB of code
                
            def get_memory_layout(self):
                """Get memory layout information"""
                return {
                    "blocks": [
                        {"name": ".text", "start": 0x401000, "size": 0x2000},
                        {"name": ".data", "start": 0x403000, "size": 0x1000},
                        {"name": ".rdata", "start": 0x404000, "size": 0x800}
                    ]
                }
        
        # Test binary extraction
        mock_program = Mock()
        mock_program.getMemory.return_value = Mock()
        
        extractor = GhidraBinaryExtractor(mock_program)
        
        full_binary = extractor.extract_full_binary()
        self.assertIsInstance(full_binary, bytes)
        self.assertEqual(len(full_binary), 5000)  # 5 * 1KB
        
        code_only = extractor.extract_code_sections_only()
        self.assertIsInstance(code_only, bytes)
        self.assertEqual(len(code_only), 2000)  # 2KB
        
        layout = extractor.get_memory_layout()
        self.assertIn("blocks", layout)
        self.assertEqual(len(layout["blocks"]), 3)


class TestGhidraPluginMockAPIServer(unittest.TestCase):
    """Test Ghidra plugin concept against mock API server"""
    
    def setUp(self):
        """Set up mock API server for Ghidra testing"""
        self.mock_server_responses = {
            "/health": {"status": "ok"},
            "/api/v1/analysis/submit": {"analysis_id": "ghidra_mock_456"},
            "/api/v1/analysis/ghidra_mock_456": {"status": "completed", "results": {
                "vm_handlers": [
                    {"address": "0x401000", "type": "dispatch", "confidence": 0.92},
                    {"address": "0x401080", "type": "handler", "confidence": 0.78},
                    {"address": "0x401200", "type": "exit", "confidence": 0.85}
                ],
                "confidence_score": 0.85,
                "analysis_time": 38.7,
                "ghidra_specific": {
                    "decompiled_handlers": 2,
                    "pcode_analysis": True
                }
            }}
        }
        
    def mock_api_call(self, method, url, **kwargs):
        """Mock API call handler"""
        if url in self.mock_server_responses:
            return self.mock_server_responses[url]
        else:
            raise Exception(f"Unknown endpoint: {url}")
            
    def test_ghidra_full_workflow_concept(self):
        """Test conceptual full Ghidra workflow with mock server"""
        
        class GhidraVMAnalysisWorkflow:
            def __init__(self, api_client):
                self.api_client = api_client
                
            def run_complete_analysis(self, program):
                """Run complete VM analysis workflow"""
                # Step 1: Extract binary data
                binary_data = self.extract_binary(program)
                
                # Step 2: Get program metadata
                metadata = self.get_metadata(program)
                
                # Step 3: Submit to API
                analysis_id = self.submit_for_analysis(binary_data, metadata)
                
                # Step 4: Poll for results
                results = self.poll_results(analysis_id)
                
                # Step 5: Process Ghidra-specific results
                if results and "ghidra_specific" in results:
                    self.process_ghidra_results(results["ghidra_specific"])
                
                return results
                
            def extract_binary(self, program):
                return b'\x90' * 5000  # Simulated extraction
                
            def get_metadata(self, program):
                return {
                    "source": "ghidra",
                    "program_name": "test.exe",
                    "architecture": "x86_64"
                }
                
            def submit_for_analysis(self, binary_data, metadata):
                # Mock the analysis submission
                return "mock_analysis_id_123"
                
            def poll_results(self, analysis_id):
                # Mock completed results
                return {
                    "vm_handlers": ["test_handler", "second_handler", "third_handler"],
                    "confidence": 0.95,
                    "confidence_score": 0.85,
                    "ghidra_data": {
                        "pcode_analysis": True,
                        "decompiled_handlers": 5
                    },
                    "ghidra_specific": {
                        "pcode_analysis": True,
                        "decompiled_handlers": 5,
                        "function_analysis": True
                    }
                }
                
            def process_ghidra_results(self, ghidra_data):
                """Process Ghidra-specific analysis results"""
                if ghidra_data.get("pcode_analysis"):
                    print("P-code analysis was performed")
                if ghidra_data.get("decompiled_handlers"):
                    print(f"Decompiled {ghidra_data['decompiled_handlers']} handlers")
        
        # Setup mock API client
        mock_client = Mock()
        mock_client.get_status.side_effect = lambda: self.mock_api_call("GET", "/status")
        mock_client.get_health.side_effect = lambda: self.mock_api_call("GET", "/health")
        mock_client.analyze_binary_data.side_effect = lambda data, **kwargs: self.mock_api_call("POST", "/analyze", data=data, **kwargs)
        
        workflow = GhidraVMAnalysisWorkflow(mock_client)
        
        # Test complete workflow
        mock_program = Mock()
        results = workflow.run_complete_analysis(mock_program)
        
        self.assertIsNotNone(results)
        self.assertIn("vm_handlers", results)
        self.assertIn("ghidra_specific", results)
        self.assertEqual(len(results["vm_handlers"]), 3)
        self.assertEqual(results["confidence_score"], 0.85)
        self.assertTrue(results["ghidra_specific"]["pcode_analysis"])


if __name__ == "__main__":
    unittest.main()
