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
    APIConnector,
    APIMethod,
    IntegrationAPISystem,
    IntegrationType,
    WebhookEvent,
    WebhookManager,
)
from .compliance_framework import (
    AuditEvent,
    AuditTrailManager,
    ComplianceFramework,
    ComplianceManager,
    ComplianceStatus,
    SecurityControl,
)
from .enterprise_architecture import (
    ArchitecturePattern,
    EnterpriseArchitecture,
    LoadBalancer,
    MessageBroker,
    ServiceMesh,
)

__all__ = [
    # API Integration
    "IntegrationAPISystem",
    "APIConnector",
    "WebhookManager",
    "IntegrationType",
    "APIMethod",
    "WebhookEvent",
    # Compliance Framework
    "ComplianceManager",
    "ComplianceFramework",
    "AuditTrailManager",
    "ComplianceStatus",
    "AuditEvent",
    "SecurityControl",
    # Enterprise Architecture
    "EnterpriseArchitecture",
    "ServiceMesh",
    "MessageBroker",
    "LoadBalancer",
    "ArchitecturePattern",
]
