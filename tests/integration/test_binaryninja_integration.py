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
Binary Ninja Plugin Integration Tests
====================================

Tests for Binary Ninja plugin integration with DragonSlayer API
"""

import unittest
import sys
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import tempfile
import threading

# Add plugin path
plugin_dir = Path(__file__).parent.parent.parent / "plugins" / "binaryninja"
sys.path.insert(0, str(plugin_dir))

# Add dragonslayer path
dragonslayer_path = Path(__file__).parent.parent.parent / "dragonslayer"
sys.path.insert(0, str(dragonslayer_path))

# Mock Binary Ninja modules
class MockBinaryView:
    """Mock Binary Ninja BinaryView"""
    def __init__(self):
        self.file = Mock()
        self.file.filename = "test.exe"
        self.arch = "x86_64"
        self.platform = "windows"
        self.entry_point = 0x401000
        self.functions = [Mock() for _ in range(10)]
        self.sections = [
            Mock(name=".text", start=0x401000, length=0x1000, semantics="ReadOnlyCodeSectionSemantics"),
            Mock(name=".data", start=0x402000, length=0x500, semantics="ReadWriteDataSectionSemantics")
        ]
        
    def __len__(self):
        return 0x5000
        
    def read(self, offset, length):
        """Mock read method"""
        return b'\x90' * length  # Return NOP instructions
        
    def set_comment_at(self, address, comment):
        """Mock comment setting"""
        pass

class MockBinaryNinja:
    """Mock Binary Ninja module"""
    def __init__(self):
        self.PluginCommand = Mock()
        self.log_info = Mock()
        self.log_warn = Mock()
        self.log_error = Mock()
        self.BackgroundTaskThread = Mock()
        
    def core_version(self):
        return "3.1"

mock_bn = MockBinaryNinja()

# Setup mocks before importing plugin
sys.modules['binaryninja'] = mock_bn
sys.modules['binaryninja.interaction'] = Mock()
sys.modules['binaryninja.enums'] = Mock()
sys.modules['binaryninja.dockwidgets'] = Mock()
sys.modules['binaryninja.binaryview'] = Mock()

# Mock UI modules
class MockUI:
    pass

for ui_name in ['VMDragonSlayerDashboard', 'RealTimeStatusMonitor', 'VMAnalysisResultsViewer',
               'PatternMatchViewer', 'VMStructureExplorer', 'PatternMatchBrowser', 'ConfigurationEditor']:
    setattr(MockUI, ui_name, Mock())

sys.modules['ui'] = MockUI

# Additional mocks for lib modules
sys.modules['lib'] = Mock()
sys.modules['lib.unified_api'] = Mock()
sys.modules['lib.vm_discovery'] = Mock()
sys.modules['lib.vm_discovery.sample_database_manager'] = Mock()
sys.modules['lib.workflow_integration'] = Mock()
sys.modules['lib.workflow_integration.validation_framework'] = Mock()
sys.modules['lib.gpu_acceleration'] = Mock()
sys.modules['lib.gpu_acceleration.gpu_profiler'] = Mock()
sys.modules['lib.semantic_engine'] = Mock()
sys.modules['lib.semantic_engine.pattern_recognizer'] = Mock()

# Import after mocking
try:
    from vmdragonslayer_bn import (
        BinaryNinjaDragonSlayerClient, 
        BinaryNinjaCoreServicesManager,
        BackgroundAnalysisTask
    )
except ImportError as e:
    print(f"Could not import Binary Ninja plugin: {e}")
    BinaryNinjaDragonSlayerClient = None
    BinaryNinjaCoreServicesManager = None
    BackgroundAnalysisTask = None

from dragonslayer.api.client import APIClient
from dragonslayer.api.transfer import BinaryTransfer


class TestBinaryNinjaPluginIntegration(unittest.TestCase):
    """Test Binary Ninja plugin integration with API"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_api_client = Mock(spec=APIClient)
        self.mock_binary_transfer = Mock(spec=BinaryTransfer)
        self.mock_binary_view = MockBinaryView()
        
        # Setup mock responses
        self.mock_api_client.get.return_value = {"status": "ok"}
        self.mock_binary_transfer.prepare_transfer.return_value = b"compressed_data"
        
    def test_binja_client_initialization(self):
        """Test Binary Ninja client initialization"""
        if not BinaryNinjaDragonSlayerClient:
            self.skipTest("Binary Ninja plugin not available")
            
        with patch('vmdragonslayer_bn.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_bn.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_bn.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            client = BinaryNinjaDragonSlayerClient("http://test:8080", "test_key")
            
            self.assertEqual(client.api_url, "http://test:8080")
            self.assertEqual(client.api_key, "test_key")
            self.assertIsNotNone(client.api_client)
            self.assertIsNotNone(client.binary_transfer)
            
    def test_binja_client_connection_check(self):
        """Test API connection checking"""
        if not BinaryNinjaDragonSlayerClient:
            self.skipTest("Binary Ninja plugin not available")
            
        with patch('vmdragonslayer_bn.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_bn.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_bn.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            client = BinaryNinjaDragonSlayerClient()
            
            # Test successful connection
            self.assertTrue(client.is_connected())
            self.mock_api_client.get.assert_called_with("/health")
            
            # Test failed connection
            self.mock_api_client.get.side_effect = Exception("Connection failed")
            self.assertFalse(client.is_connected())
            
    def test_binary_data_extraction_from_binaryview(self):
        """Test binary data extraction from BinaryView"""
        if not BinaryNinjaDragonSlayerClient:
            self.skipTest("Binary Ninja plugin not available")
            
        with patch('vmdragonslayer_bn.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_bn.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_bn.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            client = BinaryNinjaDragonSlayerClient()
            binary_data = client._extract_binary_data(self.mock_binary_view)
            
            # Should return some binary data
            self.assertIsInstance(binary_data, bytes)
            self.assertEqual(len(binary_data), len(self.mock_binary_view))
            
    def test_binary_metadata_extraction_from_binaryview(self):
        """Test metadata extraction from BinaryView"""
        if not BinaryNinjaDragonSlayerClient:
            self.skipTest("Binary Ninja plugin not available")
            
        with patch('vmdragonslayer_bn.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_bn.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_bn.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            client = BinaryNinjaDragonSlayerClient()
            metadata = client._get_binary_metadata(self.mock_binary_view)
            
            # Check required metadata fields
            self.assertIn("filename", metadata)
            self.assertIn("architecture", metadata)
            self.assertIn("platform", metadata)
            self.assertIn("entry_point", metadata)
            self.assertIn("file_size", metadata)
            self.assertIn("function_count", metadata)
            self.assertIn("sections", metadata)
            self.assertIn("binja_version", metadata)
            
    def test_large_binary_handling(self):
        """Test handling of large binaries (>100MB)"""
        if not BinaryNinjaDragonSlayerClient:
            self.skipTest("Binary Ninja plugin not available")
            
        # Create a large mock binary
        large_binary = MockBinaryView()
        large_binary.__len__ = lambda: 150 * 1024 * 1024  # 150MB
        
        with patch('vmdragonslayer_bn.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_bn.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_bn.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            client = BinaryNinjaDragonSlayerClient()
            
            # Should handle large binary without issues
            binary_data = client._extract_binary_data(large_binary)
            self.assertIsInstance(binary_data, bytes)
            
    def test_background_analysis_task(self):
        """Test background analysis functionality"""
        if not BinaryNinjaDragonSlayerClient or not BackgroundAnalysisTask:
            self.skipTest("Binary Ninja plugin components not available")
            
        with patch('vmdragonslayer_bn.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_bn.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_bn.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            client = BinaryNinjaDragonSlayerClient()
            
            # Setup mock responses for background task
            self.mock_api_client.post.return_value = {"analysis_id": "bg_test_123"}
            self.mock_api_client.get.return_value = {
                "status": "completed",
                "results": {"vm_handlers": [], "confidence": 0.7}
            }
            
            # Create background task
            task = BackgroundAnalysisTask(
                client, 
                b"test_data", 
                {"filename": "test.exe"}, 
                self.mock_binary_view
            )
            
            self.assertIsInstance(task, BackgroundAnalysisTask)
            self.assertEqual(task.client, client)
            self.assertFalse(task.cancelled)
            
    def test_background_analysis_workflow(self):
        """Test complete background analysis workflow"""
        if not BinaryNinjaDragonSlayerClient:
            self.skipTest("Binary Ninja plugin not available")
            
        with patch('vmdragonslayer_bn.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_bn.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_bn.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            # Setup API responses
            self.mock_api_client.post.return_value = {"analysis_id": "bg_workflow_123"}
            self.mock_api_client.get.return_value = {
                "status": "completed",
                "results": {
                    "vm_handlers": [
                        {"address": 0x401000, "type": "dispatch"}
                    ],
                    "confidence": 0.8
                }
            }
            
            client = BinaryNinjaDragonSlayerClient()
            
            # Test background analysis
            analysis_id = client.analyze_binary_view(self.mock_binary_view, background=True)
            
            self.assertIsNotNone(analysis_id)
            
            # Check that background task was created
            active_tasks = client.get_active_tasks()
            self.assertIsInstance(active_tasks, list)
            
    def test_synchronous_analysis_workflow(self):
        """Test synchronous analysis workflow"""
        if not BinaryNinjaDragonSlayerClient:
            self.skipTest("Binary Ninja plugin not available")
            
        with patch('vmdragonslayer_bn.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_bn.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_bn.BinaryTransfer', return_value=self.mock_binary_transfer), \
             patch('time.sleep'):  # Mock sleep to speed up test
            
            # Setup API responses
            self.mock_api_client.post.return_value = {"analysis_id": "sync_test_123"}
            responses = [
                {"status": "processing"},
                {"status": "completed", "results": {"vm_handlers": [], "confidence": 0.9}}
            ]
            self.mock_api_client.get.side_effect = responses
            
            client = BinaryNinjaDragonSlayerClient()
            
            # Test synchronous analysis
            analysis_id = client.analyze_binary_view(self.mock_binary_view, background=False)
            
            self.assertIsNotNone(analysis_id)
            self.assertEqual(analysis_id, "sync_test_123")
            
    def test_results_display_in_ui(self):
        """Test displaying results in Binary Ninja UI"""
        if not BinaryNinjaDragonSlayerClient:
            self.skipTest("Binary Ninja plugin not available")
            
        with patch('vmdragonslayer_bn.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_bn.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_bn.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            client = BinaryNinjaDragonSlayerClient()
            
            results = {
                "vm_handlers": [
                    {"address": 0x401000, "type": "dispatcher", "confidence": 0.9},
                    {"address": 0x401100, "type": "handler", "confidence": 0.7}
                ]
            }
            
            # Should not raise any exceptions
            client._display_results_in_ui(self.mock_binary_view, results)
            
    def test_core_services_manager_binja(self):
        """Test Binary Ninja core services manager"""
        if not BinaryNinjaCoreServicesManager:
            self.skipTest("Binary Ninja core services manager not available")
            
        with patch('vmdragonslayer_bn.CORE_SERVICES_AVAILABLE', True):
            manager = BinaryNinjaCoreServicesManager()
            
            # Check that services were attempted to initialize
            self.assertIsInstance(manager.services, dict)
            self.assertIsInstance(manager.services_available, dict)
            
            # Test service status
            status = manager.get_service_status()
            self.assertIsInstance(status, dict)
            
            # Test service metrics (should not crash)
            metrics = manager.get_service_metrics()
            self.assertIsInstance(metrics, dict)


class TestBinaryNinjaPluginMockAPIServer(unittest.TestCase):
    """Test Binary Ninja plugin against mock API server"""
    
    def setUp(self):
        """Set up mock API server"""
        self.mock_server_responses = {
            "/health": {"status": "ok"},
            "/api/v1/analysis/submit": {"analysis_id": "bn_mock_123"},
            "/api/v1/analysis/bn_mock_123": {"status": "completed", "results": {
                "vm_handlers": [
                    {"address": 0x401000, "type": "dispatch", "confidence": 0.95},
                    {"address": 0x401050, "type": "handler", "confidence": 0.85},
                    {"address": 0x401100, "type": "exit", "confidence": 0.75}
                ],
                "confidence_score": 0.88,
                "analysis_time": 45.2
            }}
        }
        self.mock_binary_view = MockBinaryView()
        
    def mock_api_call(self, method, url, **kwargs):
        """Mock API call handler"""
        if url in self.mock_server_responses:
            return self.mock_server_responses[url]
        else:
            raise Exception(f"Unknown endpoint: {url}")
            
    def test_full_analysis_workflow_with_mock_server(self):
        """Test complete analysis workflow with mock API server"""
        if not BinaryNinjaDragonSlayerClient:
            self.skipTest("Binary Ninja plugin not available")
            
        with patch('vmdragonslayer_bn.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_bn.APIClient') as mock_client_class, \
             patch('vmdragonslayer_bn.BinaryTransfer', return_value=Mock()), \
             patch('time.sleep'):
            
            # Setup mock client
            mock_client = Mock()
            mock_client.get.side_effect = lambda url: self.mock_api_call("GET", url)
            mock_client.post.side_effect = lambda url, **kwargs: self.mock_api_call("POST", url, **kwargs)
            mock_client_class.return_value = mock_client
            
            client = BinaryNinjaDragonSlayerClient()
            
            # Test synchronous analysis workflow
            analysis_id = client.analyze_binary_view(self.mock_binary_view, background=False)
            
            self.assertEqual(analysis_id, "bn_mock_123")


if __name__ == "__main__":
    unittest.main()
