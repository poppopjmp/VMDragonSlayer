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
Mock API Server for Plugin Testing
=================================

A mock implementation of the VMDragonSlayer API server for testing plugin integration.
"""

import json
import logging
import threading
import time
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Any, Optional
from urllib.parse import urlparse, parse_qs
import socketserver

logger = logging.getLogger(__name__)


class MockAnalysisResult:
    """Mock analysis result generator"""
    
    @staticmethod
    def generate_vm_analysis_result(analysis_id: str, binary_size: int = 1000) -> Dict[str, Any]:
        """Generate a mock VM analysis result"""
        num_handlers = min(max(binary_size // 5000, 1), 20)  # 1-20 handlers based on size
        
        handlers = []
        base_addr = 0x401000
        
        for i in range(num_handlers):
            handler_types = ["dispatch", "handler", "exit", "crypto", "anti_debug"]
            handlers.append({
                "address": hex(base_addr + (i * 0x100)),
                "type": handler_types[i % len(handler_types)],
                "confidence": round(0.6 + (i * 0.05), 2),
                "size": 50 + (i * 10),
                "instructions": [
                    {"address": hex(base_addr + (i * 0x100) + j), "mnemonic": "mov", "operands": "eax, ebx"}
                    for j in range(0, 20, 4)
                ]
            })
        
        return {
            "analysis_id": analysis_id,
            "status": "completed",
            "results": {
                "vm_handlers": handlers,
                "control_flow": {
                    "dispatcher_count": max(num_handlers // 4, 1),
                    "handler_count": num_handlers,
                    "complexity_score": round(0.3 + (num_handlers * 0.02), 2)
                },
                "taint_flows": [
                    {
                        "source": hex(0x401000 + i * 0x50),
                        "sink": hex(0x401000 + (i + 1) * 0x50),
                        "path_length": 5 + i,
                        "confidence": round(0.7 + (i * 0.03), 2)
                    }
                    for i in range(min(num_handlers // 2, 10))
                ],
                "polymorphic_groups": {
                    f"group_{i}": [
                        hex(0x401000 + i * 0x100 + j * 0x20) 
                        for j in range(3)
                    ]
                    for i in range(min(num_handlers // 3, 5))
                },
                "confidence_score": round(0.75 + (num_handlers * 0.01), 2),
                "analysis_time": round(10.5 + (binary_size / 1000), 1),
                "metadata": {
                    "binary_size": binary_size,
                    "analysis_timestamp": datetime.now().isoformat(),
                    "vm_type": "custom_vm" if num_handlers > 10 else "simple_vm",
                    "obfuscation_level": "high" if num_handlers > 15 else "medium"
                }
            },
            "error": None
        }


class MockAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for mock API server"""
    
    # Class-level storage for analysis jobs
    analysis_jobs = {}
    job_lock = threading.Lock()
    
    def do_GET(self):
        """Handle GET requests"""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            
            if path == "/health":
                self.send_json_response({"status": "ok", "timestamp": datetime.now().isoformat()})
                
            elif path.startswith("/api/v1/analysis/"):
                analysis_id = path.split("/")[-1]
                self.handle_get_analysis_status(analysis_id)
                
            elif path == "/api/v1/status":
                self.send_json_response({
                    "server": "mock_vmdragonslayer_api",
                    "version": "2.0.0",
                    "active_analyses": len(self.analysis_jobs),
                    "uptime": "mock_uptime"
                })
                
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            logger.error(f"Error handling GET request: {e}")
            self.send_error(500, f"Internal Server Error: {str(e)}")
    
    def do_POST(self):
        """Handle POST requests"""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            
            if path == "/api/v1/analysis/submit":
                self.handle_analysis_submission()
            else:
                self.send_error(404, "Not Found")
                
        except Exception as e:
            logger.error(f"Error handling POST request: {e}")
            self.send_error(500, f"Internal Server Error: {str(e)}")
    
    def handle_get_analysis_status(self, analysis_id: str):
        """Handle getting analysis status"""
        with self.job_lock:
            if analysis_id not in self.analysis_jobs:
                self.send_error(404, "Analysis not found")
                return
            
            job = self.analysis_jobs[analysis_id]
            
            # Simulate processing time
            elapsed_time = time.time() - job["start_time"]
            
            if elapsed_time < 2:  # First 2 seconds: queued
                response = {
                    "analysis_id": analysis_id,
                    "status": "queued",
                    "progress": 0,
                    "estimated_completion": 30
                }
            elif elapsed_time < 8:  # 2-8 seconds: processing
                progress = min(int((elapsed_time - 2) / 6 * 100), 99)
                response = {
                    "analysis_id": analysis_id,
                    "status": "processing",
                    "progress": progress,
                    "estimated_completion": max(30 - int(elapsed_time), 5)
                }
            else:  # After 8 seconds: completed
                if "result" not in job:
                    # Generate result
                    binary_size = job.get("binary_size", 1000)
                    job["result"] = MockAnalysisResult.generate_vm_analysis_result(analysis_id, binary_size)
                
                response = job["result"]
            
            self.send_json_response(response)
    
    def handle_analysis_submission(self):
        """Handle analysis submission"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            
            try:
                request_data = json.loads(post_data.decode('utf-8'))
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON")
                return
            
            # Validate required fields
            if "binary_data" not in request_data:
                self.send_error(400, "Missing binary_data")
                return
            
            # Generate analysis ID
            analysis_id = str(uuid.uuid4())[:8]  # Short ID for testing
            
            # Extract metadata
            metadata = request_data.get("metadata", {})
            binary_size = metadata.get("file_size", len(str(request_data.get("binary_data", ""))))
            
            # Store analysis job
            with self.job_lock:
                self.analysis_jobs[analysis_id] = {
                    "analysis_id": analysis_id,
                    "start_time": time.time(),
                    "binary_size": binary_size,
                    "metadata": metadata,
                    "status": "queued"
                }
            
            # Return analysis ID
            response = {
                "analysis_id": analysis_id,
                "status": "accepted",
                "estimated_completion": 30
            }
            
            self.send_json_response(response, status_code=202)
            logger.info(f"Analysis submitted: {analysis_id}")
            
        except Exception as e:
            logger.error(f"Error handling analysis submission: {e}")
            self.send_error(500, f"Submission error: {str(e)}")
    
    def send_json_response(self, data: Dict[str, Any], status_code: int = 200):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')  # For CORS
        self.end_headers()
        
        json_data = json.dumps(data, indent=2)
        self.wfile.write(json_data.encode('utf-8'))
    
    def log_message(self, format, *args):
        """Custom log message formatting"""
        logger.info(f"MockAPI: {format % args}")


class MockAPIServer:
    """Mock API server for testing"""
    
    def __init__(self, host: str = "localhost", port: int = 8080):
        self.host = host
        self.port = port
        self.server = None
        self.server_thread = None
        self.running = False
        
    def start(self) -> bool:
        """Start the mock API server"""
        try:
            # Create server
            self.server = HTTPServer((self.host, self.port), MockAPIHandler)
            
            # Start server in background thread
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
            self.server_thread.start()
            
            self.running = True
            logger.info(f"Mock API server started at http://{self.host}:{self.port}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start mock API server: {e}")
            return False
    
    def stop(self):
        """Stop the mock API server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            
        if self.server_thread:
            self.server_thread.join(timeout=5)
            
        self.running = False
        logger.info("Mock API server stopped")
    
    def is_running(self) -> bool:
        """Check if server is running"""
        return self.running and self.server_thread and self.server_thread.is_alive()
    
    def get_active_analyses(self) -> Dict[str, Dict]:
        """Get currently active analysis jobs"""
        with MockAPIHandler.job_lock:
            return MockAPIHandler.analysis_jobs.copy()
    
    def clear_analyses(self):
        """Clear all analysis jobs (for testing)"""
        with MockAPIHandler.job_lock:
            MockAPIHandler.analysis_jobs.clear()
    
    def add_custom_analysis_result(self, analysis_id: str, result: Dict[str, Any]):
        """Add a custom analysis result (for testing specific scenarios)"""
        with MockAPIHandler.job_lock:
            if analysis_id in MockAPIHandler.analysis_jobs:
                MockAPIHandler.analysis_jobs[analysis_id]["result"] = result


class MockAPIServerContext:
    """Context manager for mock API server"""
    
    def __init__(self, host: str = "localhost", port: int = 8080):
        self.server = MockAPIServer(host, port)
        
    def __enter__(self):
        if self.server.start():
            # Wait a moment for server to be ready
            time.sleep(0.1)
            return self.server
        else:
            raise RuntimeError("Failed to start mock API server")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.server.stop()


# Utility functions for testing
def run_mock_server_standalone(host: str = "localhost", port: int = 8080):
    """Run mock server standalone for manual testing"""
    server = MockAPIServer(host, port)
    
    if server.start():
        print(f"Mock VMDragonSlayer API server running at http://{host}:{port}")
        print("Endpoints:")
        print("  GET  /health - Health check")
        print("  GET  /api/v1/status - Server status")
        print("  POST /api/v1/analysis/submit - Submit binary for analysis")
        print("  GET  /api/v1/analysis/{id} - Get analysis results")
        print("\nPress Ctrl+C to stop...")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping server...")
            server.stop()
    else:
        print("Failed to start server")


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Run standalone server
    run_mock_server_standalone()
