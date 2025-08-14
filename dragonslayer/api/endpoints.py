"""
API Endpoints
============

Endpoint definitions and handlers for the VMDragonSlayer REST API.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from ..core.exceptions import APIError, ValidationError


@dataclass
class Endpoint:
    """API endpoint definition"""
    path: str
    method: str
    handler: str
    description: str
    parameters: List[Dict[str, Any]]
    responses: Dict[int, Dict[str, Any]]


class EndpointRegistry:
    """Registry of API endpoints"""
    
    def __init__(self):
        self.endpoints = {}
        self._register_endpoints()
    
    def _register_endpoints(self):
        """Register all API endpoints"""
        
        # Analysis endpoints
        self.endpoints['/analyze'] = Endpoint(
            path='/analyze',
            method='POST',
            handler='analyze_binary',
            description='Analyze binary data for VM patterns',
            parameters=[
                {
                    'name': 'sample_data',
                    'type': 'string',
                    'required': True,
                    'description': 'Base64 encoded binary data'
                },
                {
                    'name': 'analysis_type',
                    'type': 'string',
                    'required': False,
                    'default': 'hybrid',
                    'description': 'Type of analysis to perform'
                }
            ],
            responses={
                200: {'description': 'Analysis completed successfully'},
                400: {'description': 'Invalid request data'},
                500: {'description': 'Internal server error'}
            }
        )
        
        self.endpoints['/upload-analyze'] = Endpoint(
            path='/upload-analyze',
            method='POST',
            handler='upload_and_analyze',
            description='Upload and analyze binary file',
            parameters=[
                {
                    'name': 'file',
                    'type': 'file',
                    'required': True,
                    'description': 'Binary file to analyze'
                }
            ],
            responses={
                200: {'description': 'Analysis completed successfully'},
                413: {'description': 'File too large'},
                500: {'description': 'Internal server error'}
            }
        )
        
        # Status and information endpoints
        self.endpoints['/status'] = Endpoint(
            path='/status',
            method='GET',
            handler='get_status',
            description='Get service status information',
            parameters=[],
            responses={
                200: {'description': 'Status information'}
            }
        )
        
        self.endpoints['/health'] = Endpoint(
            path='/health',
            method='GET',
            handler='health_check',
            description='Health check endpoint',
            parameters=[],
            responses={
                200: {'description': 'Service is healthy'}
            }
        )
        
        self.endpoints['/metrics'] = Endpoint(
            path='/metrics',
            method='GET',
            handler='get_metrics',
            description='Get performance metrics',
            parameters=[],
            responses={
                200: {'description': 'Performance metrics'}
            }
        )
        
        # Configuration endpoints
        self.endpoints['/analysis-types'] = Endpoint(
            path='/analysis-types',
            method='GET',
            handler='get_analysis_types',
            description='Get supported analysis types',
            parameters=[],
            responses={
                200: {'description': 'List of supported analysis types'}
            }
        )
    
    def get_endpoint(self, path: str) -> Optional[Endpoint]:
        """Get endpoint definition by path"""
        return self.endpoints.get(path)
    
    def get_all_endpoints(self) -> Dict[str, Endpoint]:
        """Get all registered endpoints"""
        return self.endpoints.copy()
    
    def get_openapi_spec(self) -> Dict[str, Any]:
        """Generate OpenAPI specification"""
        paths = {}
        
        for endpoint in self.endpoints.values():
            if endpoint.path not in paths:
                paths[endpoint.path] = {}
            
            paths[endpoint.path][endpoint.method.lower()] = {
                'summary': endpoint.description,
                'parameters': endpoint.parameters,
                'responses': endpoint.responses
            }
        
        return {
            'openapi': '3.0.0',
            'info': {
                'title': 'VMDragonSlayer API',
                'version': '1.0.0',
                'description': 'REST API for virtual machine analysis'
            },
            'paths': paths
        }
