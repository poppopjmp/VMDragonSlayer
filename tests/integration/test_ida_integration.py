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
IDA Pro Plugin Integration Tests
================================

Tests for IDA Pro plugin integration with DragonSlayer API
"""

import unittest
import sys
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import tempfile

# Add plugin path
plugin_dir = Path(__file__).parent.parent.parent / "plugins" / "idapro"
sys.path.insert(0, str(plugin_dir))

# Add dragonslayer path
dragonslayer_path = Path(__file__).parent.parent.parent / "dragonslayer"
sys.path.insert(0, str(dragonslayer_path))

# Mock IDA modules
class MockIDAAPI:
    """Mock IDA API for testing"""
    def __init__(self):
        self.plugin_t = Mock()
        
mock_idaapi = MockIDAAPI()
mock_idautils = Mock()
mock_idc = Mock()
mock_ida_bytes = Mock()
mock_ida_funcs = Mock()
mock_ida_kernwin = Mock()
mock_ida_pro = Mock()
mock_ida_nalt = Mock()

# Setup mocks before importing plugin
sys.modules['idaapi'] = mock_idaapi
sys.modules['idautils'] = mock_idautils
sys.modules['idc'] = mock_idc
sys.modules['ida_bytes'] = mock_ida_bytes
sys.modules['ida_funcs'] = mock_ida_funcs
sys.modules['ida_kernwin'] = mock_ida_kernwin
sys.modules['ida_pro'] = mock_ida_pro
sys.modules['ida_nalt'] = mock_ida_nalt

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
    from vmdragonslayer_ida import IDADragonSlayerClient, CoreServicesManager
except ImportError as e:
    print(f"Could not import IDA plugin: {e}")
    IDADragonSlayerClient = None
    CoreServicesManager = None

from dragonslayer.api.client import APIClient
from dragonslayer.api.transfer import BinaryTransfer


class TestIDAPluginIntegration(unittest.TestCase):
    """Test IDA Pro plugin integration with API"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_api_client = Mock(spec=APIClient)
        self.mock_binary_transfer = Mock(spec=BinaryTransfer)
        
        # Setup mock responses
        self.mock_api_client.get.return_value = {"status": "ok"}
        self.mock_binary_transfer.prepare_transfer.return_value = b"compressed_data"
        
        # Setup IDA mocks
        mock_ida_nalt.get_imagebase.return_value = 0x400000
        mock_idc.get_inf_attr.return_value = 0x500000
        mock_ida_bytes.get_byte.return_value = 0x90
        mock_ida_nalt.get_root_filename.return_value = "test.exe"
        mock_ida_pro.get_inf_structure.return_value.procname = "metapc"
        mock_ida_pro.get_kernel_version.return_value = "7.5"
        
    def test_ida_client_initialization(self):
        """Test IDA client initialization"""
        if not IDADragonSlayerClient:
            self.skipTest("IDA plugin not available")
            
        with patch('vmdragonslayer_ida.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_ida.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_ida.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            client = IDADragonSlayerClient("http://test:8080", "test_key")
            
            self.assertEqual(client.api_url, "http://test:8080")
            self.assertEqual(client.api_key, "test_key")
            self.assertIsNotNone(client.api_client)
            self.assertIsNotNone(client.binary_transfer)
            
    def test_ida_client_connection_check(self):
        """Test API connection checking"""
        if not IDADragonSlayerClient:
            self.skipTest("IDA plugin not available")
            
        with patch('vmdragonslayer_ida.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_ida.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_ida.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            client = IDADragonSlayerClient()
            
            # Test successful connection
            self.assertTrue(client.is_connected())
            self.mock_api_client.get.assert_called_with("/health")
            
            # Test failed connection
            self.mock_api_client.get.side_effect = Exception("Connection failed")
            self.assertFalse(client.is_connected())
            
    def test_binary_data_extraction(self):
        """Test binary data extraction from IDA"""
        if not IDADragonSlayerClient:
            self.skipTest("IDA plugin not available")
            
        with patch('vmdragonslayer_ida.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_ida.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_ida.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            client = IDADragonSlayerClient()
            binary_data = client._extract_binary_data()
            
            # Should return some binary data
            self.assertIsInstance(binary_data, bytes)
            self.assertGreater(len(binary_data), 0)
            
    def test_binary_metadata_extraction(self):
        """Test metadata extraction from IDA"""
        if not IDADragonSlayerClient:
            self.skipTest("IDA plugin not available")
            
        with patch('vmdragonslayer_ida.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_ida.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_ida.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            client = IDADragonSlayerClient()
            metadata = client._get_binary_metadata()
            
            # Check required metadata fields
            self.assertIn("filename", metadata)
            self.assertIn("architecture", metadata)
            self.assertIn("entry_point", metadata)
            self.assertIn("file_size", metadata)
            self.assertIn("ida_version", metadata)
            
    def test_binary_submission(self):
        """Test binary submission to API"""
        if not IDADragonSlayerClient:
            self.skipTest("IDA plugin not available")
            
        with patch('vmdragonslayer_ida.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_ida.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_ida.BinaryTransfer', return_value=self.mock_binary_transfer):
            
            # Setup API response
            self.mock_api_client.post.return_value = {"analysis_id": "test_123"}
            
            client = IDADragonSlayerClient()
            analysis_id = client._submit_binary_for_analysis(b"test_data", {"filename": "test.exe"})
            
            self.assertEqual(analysis_id, "test_123")
            self.mock_api_client.post.assert_called_once()
            
    def test_analysis_results_polling(self):
        """Test polling for analysis results"""
        if not IDADragonSlayerClient:
            self.skipTest("IDA plugin not available")
            
        with patch('vmdragonslayer_ida.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_ida.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_ida.BinaryTransfer', return_value=self.mock_binary_transfer), \
             patch('time.sleep'):  # Mock sleep to speed up test
            
            # Setup API responses
            responses = [
                {"status": "queued"},
                {"status": "processing"},
                {"status": "completed", "results": {"vm_handlers": [], "confidence": 0.8}}
            ]
            self.mock_api_client.get.side_effect = responses
            
            client = IDADragonSlayerClient()
            results = client._poll_analysis_results("test_123", timeout=30)
            
            self.assertIsNotNone(results)
            self.assertIn("vm_handlers", results)
            self.assertIn("confidence", results)
            
    def test_analysis_hooks_installation(self):
        """Test installation of analysis hooks"""
        if not IDADragonSlayerClient:
            self.skipTest("IDA plugin not available")
            
        with patch('vmdragonslayer_ida.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_ida.APIClient', return_value=self.mock_api_client), \
             patch('vmdragonslayer_ida.BinaryTransfer', return_value=self.mock_binary_transfer), \
             patch('vmdragonslayer_ida.IDABinaryLoadHook') as mock_hook_class:
            
            mock_hook = Mock()
            mock_hook.hook.return_value = True
            mock_hook_class.return_value = mock_hook
            
            client = IDADragonSlayerClient()
            client.install_analysis_hooks()
            
            self.assertEqual(len(client.analysis_hooks), 1)
            mock_hook.hook.assert_called_once()
            
    def test_core_services_manager(self):
        """Test core services manager initialization"""
        if not CoreServicesManager:
            self.skipTest("Core services manager not available")
            
        with patch('vmdragonslayer_ida.UNIFIED_API_AVAILABLE', False), \
             patch('vmdragonslayer_ida.LEGACY_COMPONENTS_AVAILABLE', True):
            
            manager = CoreServicesManager()
            
            # Check that services were attempted to initialize
            self.assertIsInstance(manager.services, dict)
            self.assertIsInstance(manager.services_available, dict)


class TestIDAPluginMockAPIServer(unittest.TestCase):
    """Test IDA plugin against mock API server"""
    
    def setUp(self):
        """Set up mock API server"""
        self.mock_server_responses = {
            "/health": {"status": "ok"},
            "/api/v1/analysis/submit": {"analysis_id": "mock_123"},
            "/api/v1/analysis/mock_123": {"status": "completed", "results": {
                "vm_handlers": [
                    {"address": 0x401000, "type": "dispatch", "confidence": 0.9},
                    {"address": 0x401050, "type": "handler", "confidence": 0.8}
                ],
                "confidence_score": 0.85
            }}
        }
        
    def mock_api_call(self, method, url, **kwargs):
        """Mock API call handler"""
        if url in self.mock_server_responses:
            return self.mock_server_responses[url]
        else:
            raise Exception(f"Unknown endpoint: {url}")
            
    def test_full_analysis_workflow(self):
        """Test complete analysis workflow with mock server"""
        if not IDADragonSlayerClient:
            self.skipTest("IDA plugin not available")
            
        with patch('vmdragonslayer_ida.API_CLIENT_AVAILABLE', True), \
             patch('vmdragonslayer_ida.APIClient') as mock_client_class, \
             patch('vmdragonslayer_ida.BinaryTransfer', return_value=Mock()), \
             patch('time.sleep'):
            
            # Setup mock client
            mock_client = Mock()
            mock_client.get.side_effect = lambda url: self.mock_api_call("GET", url)
            mock_client.post.side_effect = lambda url, **kwargs: self.mock_api_call("POST", url, **kwargs)
            mock_client_class.return_value = mock_client
            
            client = IDADragonSlayerClient()
            
            # Test full workflow
            results = client.analyze_current_binary()
            
            self.assertIsNotNone(results)
            self.assertIn("vm_handlers", results)
            self.assertEqual(len(results["vm_handlers"]), 2)
            self.assertEqual(results["confidence_score"], 0.85)


if __name__ == "__main__":
    unittest.main()
