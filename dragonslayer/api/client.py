"""
API Client
==========

Client library for accessing the VMDragonSlayer REST API.
"""

import json
import base64
import asyncio
import logging
from typing import Dict, Any, Optional, BinaryIO
from pathlib import Path

# Handle HTTP client imports gracefully
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    try:
        import requests
        REQUESTS_AVAILABLE = True
    except ImportError:
        REQUESTS_AVAILABLE = False

from ..core.exceptions import APIError, NetworkError

logger = logging.getLogger(__name__)


class APIClient:
    """
    Client for VMDragonSlayer REST API.
    
    Provides convenient methods for interacting with the VMDragonSlayer
    API server from Python applications.
    """
    
    def __init__(self, base_url: str = "http://localhost:8000", 
                 api_key: Optional[str] = None, timeout: float = 300.0):
        """
        Initialize API client.
        
        Args:
            base_url: Base URL of the API server
            api_key: Optional API key for authentication
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = timeout
        self.logger = logging.getLogger(f"{__name__}.APIClient")
        
        # Setup HTTP client
        if HTTPX_AVAILABLE:
            self.client = httpx.Client(timeout=timeout)
            self.async_client = httpx.AsyncClient(timeout=timeout)
            self._use_httpx = True
        elif REQUESTS_AVAILABLE:
            import requests
            self.session = requests.Session()
            self.session.timeout = timeout
            self._use_httpx = False
        else:
            raise ImportError("Either httpx or requests is required for API client")
        
        # Setup headers
        self.headers = {"Content-Type": "application/json"}
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"
        
        self.logger.info(f"API client initialized for {base_url}")
    
    def analyze_file(self, file_path: str, analysis_type: str = "hybrid", 
                    **options) -> Dict[str, Any]:
        """
        Analyze a binary file.
        
        Args:
            file_path: Path to the binary file
            analysis_type: Type of analysis to perform
            **options: Additional analysis options
            
        Returns:
            Analysis results dictionary
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read and encode file
        with open(file_path, 'rb') as f:
            binary_data = f.read()
        
        encoded_data = base64.b64encode(binary_data).decode()
        
        # Prepare request
        request_data = {
            "sample_data": encoded_data,
            "analysis_type": analysis_type,
            "options": options,
            "metadata": {"filename": file_path.name}
        }
        
        return self._post("/analyze", request_data)
    
    def analyze_binary_data(self, binary_data: bytes, analysis_type: str = "hybrid",
                           metadata: Optional[Dict[str, Any]] = None,
                           **options) -> Dict[str, Any]:
        """
        Analyze binary data directly.
        
        Args:
            binary_data: Binary data to analyze
            analysis_type: Type of analysis to perform
            metadata: Optional metadata about the binary
            **options: Additional analysis options
            
        Returns:
            Analysis results dictionary
        """
        encoded_data = base64.b64encode(binary_data).decode()
        
        request_data = {
            "sample_data": encoded_data,
            "analysis_type": analysis_type,
            "options": options,
            "metadata": metadata or {}
        }
        
        return self._post("/analyze", request_data)
    
    def upload_and_analyze(self, file_path: str, analysis_type: str = "hybrid") -> Dict[str, Any]:
        """
        Upload file and analyze using multipart form data.
        
        Args:
            file_path: Path to file to upload
            analysis_type: Type of analysis to perform
            
        Returns:
            Analysis results dictionary
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        url = f"{self.base_url}/upload-analyze"
        
        try:
            if self._use_httpx:
                with open(file_path, 'rb') as f:
                    files = {"file": (file_path.name, f, "application/octet-stream")}
                    data = {"analysis_type": analysis_type}
                    headers = {}
                    if self.api_key:
                        headers["Authorization"] = f"Bearer {self.api_key}"
                    
                    response = self.client.post(url, files=files, data=data, headers=headers)
                    response.raise_for_status()
                    return response.json()
            else:
                with open(file_path, 'rb') as f:
                    files = {"file": (file_path.name, f, "application/octet-stream")}
                    data = {"analysis_type": analysis_type}
                    headers = {}
                    if self.api_key:
                        headers["Authorization"] = f"Bearer {self.api_key}"
                    
                    response = self.session.post(url, files=files, data=data, headers=headers)
                    response.raise_for_status()
                    return response.json()
                    
        except Exception as e:
            self.logger.error(f"Upload and analyze failed: {e}")
            raise APIError(
                f"Failed to upload and analyze file: {file_path}",
                error_code="UPLOAD_ANALYZE_FAILED",
                cause=e
            )
    
    def get_status(self) -> Dict[str, Any]:
        """Get API server status"""
        return self._get("/status")
    
    def get_health(self) -> Dict[str, Any]:
        """Get API server health"""
        return self._get("/health")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        return self._get("/metrics")
    
    def get_analysis_types(self) -> Dict[str, Any]:
        """Get supported analysis types"""
        return self._get("/analysis-types")
    
    async def analyze_file_async(self, file_path: str, analysis_type: str = "hybrid",
                                **options) -> Dict[str, Any]:
        """Async version of analyze_file"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Read and encode file
        with open(file_path, 'rb') as f:
            binary_data = f.read()
        
        encoded_data = base64.b64encode(binary_data).decode()
        
        request_data = {
            "sample_data": encoded_data,
            "analysis_type": analysis_type,
            "options": options,
            "metadata": {"filename": file_path.name}
        }
        
        return await self._post_async("/analyze", request_data)
    
    async def analyze_binary_data_async(self, binary_data: bytes, 
                                       analysis_type: str = "hybrid",
                                       metadata: Optional[Dict[str, Any]] = None,
                                       **options) -> Dict[str, Any]:
        """Async version of analyze_binary_data"""
        encoded_data = base64.b64encode(binary_data).decode()
        
        request_data = {
            "sample_data": encoded_data,
            "analysis_type": analysis_type,
            "options": options,
            "metadata": metadata or {}
        }
        
        return await self._post_async("/analyze", request_data)
    
    def _get(self, endpoint: str) -> Dict[str, Any]:
        """Make GET request"""
        url = f"{self.base_url}{endpoint}"
        
        try:
            if self._use_httpx:
                response = self.client.get(url, headers=self.headers)
                response.raise_for_status()
                return response.json()
            else:
                response = self.session.get(url, headers=self.headers)
                response.raise_for_status()
                return response.json()
                
        except Exception as e:
            self.logger.error(f"GET {endpoint} failed: {e}")
            raise NetworkError(
                f"GET request failed: {endpoint}",
                error_code="GET_REQUEST_FAILED",
                cause=e
            )
    
    def _post(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make POST request"""
        url = f"{self.base_url}{endpoint}"
        
        try:
            if self._use_httpx:
                response = self.client.post(url, json=data, headers=self.headers)
                response.raise_for_status()
                return response.json()
            else:
                response = self.session.post(url, json=data, headers=self.headers)
                response.raise_for_status()
                return response.json()
                
        except Exception as e:
            self.logger.error(f"POST {endpoint} failed: {e}")
            raise NetworkError(
                f"POST request failed: {endpoint}",
                error_code="POST_REQUEST_FAILED",
                cause=e
            )
    
    async def _get_async(self, endpoint: str) -> Dict[str, Any]:
        """Make async GET request"""
        if not self._use_httpx:
            raise NotImplementedError("Async requests require httpx")
        
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = await self.async_client.get(url, headers=self.headers)
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Async GET {endpoint} failed: {e}")
            raise NetworkError(
                f"Async GET request failed: {endpoint}",
                error_code="ASYNC_GET_REQUEST_FAILED",
                cause=e
            )
    
    async def _post_async(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make async POST request"""
        if not self._use_httpx:
            raise NotImplementedError("Async requests require httpx")
        
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = await self.async_client.post(url, json=data, headers=self.headers)
            response.raise_for_status()
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Async POST {endpoint} failed: {e}")
            raise NetworkError(
                f"Async POST request failed: {endpoint}",
                error_code="ASYNC_POST_REQUEST_FAILED",
                cause=e
            )
    
    def close(self):
        """Close HTTP client connections"""
        try:
            if self._use_httpx:
                self.client.close()
            elif hasattr(self, 'session'):
                self.session.close()
        except Exception as e:
            self.logger.warning(f"Error closing HTTP client: {e}")
    
    async def aclose(self):
        """Close async HTTP client connections"""
        try:
            if self._use_httpx and hasattr(self, 'async_client'):
                await self.async_client.aclose()
        except Exception as e:
            self.logger.warning(f"Error closing async HTTP client: {e}")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.aclose()


def create_client(base_url: str = "http://localhost:8000", 
                 api_key: Optional[str] = None, 
                 timeout: float = 300.0) -> APIClient:
    """Create API client instance"""
    return APIClient(base_url=base_url, api_key=api_key, timeout=timeout)
