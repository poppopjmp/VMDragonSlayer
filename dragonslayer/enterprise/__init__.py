"""
Enterprise Integration Module for VMDragonSlayer
==============================================

This module consolidates enterprise-grade integration capabilities including:
    - API integration systems (REST, GraphQL)
    - Compliance and regulatory frameworks 
    - Enterprise architecture patterns
    - Third-party service connectors
    - Webhook management and processing
    - Audit trails and compliance monitoring

Components:
    - IntegrationAPISystem: REST/GraphQL API management
    - ComplianceFramework: SOC2, ISO27001, GDPR, HIPAA compliance
    - EnterpriseArchitecture: Enterprise integration patterns
    - WebhookManager: Webhook processing and management
    - AuditTrailManager: Compliance audit trails
"""

from .api_integration import (
    IntegrationAPISystem,
    APIConnector,
    WebhookManager,
    IntegrationType,
    APIMethod,
    WebhookEvent
)

from .compliance_framework import (
    ComplianceManager,
    ComplianceFramework,
    AuditTrailManager,
    ComplianceStatus,
    AuditEvent,
    SecurityControl
)

from .enterprise_architecture import (
    EnterpriseArchitecture,
    ServiceMesh,
    MessageBroker,
    LoadBalancer,
    ArchitecturePattern
)

__all__ = [
    # API Integration
    'IntegrationAPISystem',
    'APIConnector', 
    'WebhookManager',
    'IntegrationType',
    'APIMethod',
    'WebhookEvent',
    
    # Compliance Framework
    'ComplianceManager',
    'ComplianceFramework',
    'AuditTrailManager', 
    'ComplianceStatus',
    'AuditEvent',
    'SecurityControl',
    
    # Enterprise Architecture
    'EnterpriseArchitecture',
    'ServiceMesh',
    'MessageBroker',
    'LoadBalancer',
    'ArchitecturePattern'
]
