#!/usr/bin/env python3
"""
Enterprise Compliance Framework for VMDragonSlayer
================================================

Provides comprehensive compliance and regulatory frameworks including:
    - SOC2 Type I/II compliance monitoring
    - ISO27001 security management
    - GDPR data protection compliance
    - HIPAA healthcare compliance
    - PCI DSS payment card security
    - NIST Cybersecurity Framework
    - Automated audit trails and reporting
    - Security controls management

This module consolidates enterprise compliance functionality
from the original enterprise modules.
"""

import asyncio
import json
import logging
import hashlib
import os
import sqlite3
import time
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
import threading

# Core dependencies
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from jinja2 import Template, Environment, FileSystemLoader
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    import schedule
    SCHEDULE_AVAILABLE = True
except ImportError:
    SCHEDULE_AVAILABLE = False

# Configure logging
logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    SOC2_TYPE1 = "soc2_type1"
    SOC2_TYPE2 = "soc2_type2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    NIST_CSF = "nist_csf"
    COBIT = "cobit"
    FedRAMP = "fedramp"


class ComplianceStatus(Enum):
    """Compliance status levels"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL_COMPLIANCE = "partial_compliance"
    UNDER_REVIEW = "under_review"
    NOT_APPLICABLE = "not_applicable"


class AuditEvent(Enum):
    """Types of audit events"""
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_DELETION = "data_deletion"
    SECURITY_INCIDENT = "security_incident"
    CONFIGURATION_CHANGE = "configuration_change"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    FAILED_LOGIN = "failed_login"
    SYSTEM_ERROR = "system_error"


class SecurityControl(Enum):
    """Security control categories"""
    ACCESS_CONTROL = "access_control"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ENCRYPTION = "encryption"
    LOGGING = "logging"
    MONITORING = "monitoring"
    BACKUP = "backup"
    INCIDENT_RESPONSE = "incident_response"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    NETWORK_SECURITY = "network_security"


@dataclass
class ComplianceRequirement:
    """Individual compliance requirement"""
    framework: ComplianceFramework
    control_id: str
    title: str
    description: str
    severity: str  # HIGH, MEDIUM, LOW
    status: ComplianceStatus
    evidence: List[str] = None
    last_assessed: datetime = None
    next_review: datetime = None
    responsible_party: str = ""
    
    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
        if self.last_assessed is None:
            self.last_assessed = datetime.now()


@dataclass
class AuditTrailEntry:
    """Audit trail entry"""
    event_id: str
    event_type: AuditEvent
    timestamp: datetime
    user_id: str
    resource: str
    action: str
    details: Dict[str, Any]
    ip_address: str = ""
    user_agent: str = ""
    session_id: str = ""
    
    def __post_init__(self):
        if not self.event_id:
            self.event_id = hashlib.sha256(
                f"{self.timestamp.isoformat()}{self.user_id}{self.action}".encode()
            ).hexdigest()[:16]


@dataclass
class SecurityControlStatus:
    """Security control implementation status"""
    control: SecurityControl
    implemented: bool
    effectiveness: float  # 0.0 to 1.0
    last_tested: datetime
    findings: List[str] = None
    remediation_actions: List[str] = None
    
    def __post_init__(self):
        if self.findings is None:
            self.findings = []
        if self.remediation_actions is None:
            self.remediation_actions = []


class AuditTrailManager:
    """Manages audit trails and logging"""
    
    def __init__(self, db_path: str = "audit_trail.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_database()
    
    def _init_database(self):
        """Initialize audit trail database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS audit_trail (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    session_id TEXT
                )
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_trail(timestamp)
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_user_id ON audit_trail(user_id)
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_event_type ON audit_trail(event_type)
            ''')
    
    def log_event(self, entry: AuditTrailEntry):
        """Log audit event"""
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute('''
                        INSERT INTO audit_trail 
                        (event_id, event_type, timestamp, user_id, resource, action, 
                         details, ip_address, user_agent, session_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        entry.event_id,
                        entry.event_type.value,
                        entry.timestamp.isoformat(),
                        entry.user_id,
                        entry.resource,
                        entry.action,
                        json.dumps(entry.details),
                        entry.ip_address,
                        entry.user_agent,
                        entry.session_id
                    ))
                logger.debug(f"Logged audit event: {entry.event_id}")
            except Exception as e:
                logger.error(f"Failed to log audit event: {e}")
    
    def get_events(self, 
                  start_time: datetime = None,
                  end_time: datetime = None,
                  user_id: str = None,
                  event_type: AuditEvent = None,
                  limit: int = 1000) -> List[AuditTrailEntry]:
        """Get audit events"""
        query = "SELECT * FROM audit_trail WHERE 1=1"
        params = []
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        events = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute(query, params)
                
                for row in cursor:
                    events.append(AuditTrailEntry(
                        event_id=row['event_id'],
                        event_type=AuditEvent(row['event_type']),
                        timestamp=datetime.fromisoformat(row['timestamp']),
                        user_id=row['user_id'],
                        resource=row['resource'],
                        action=row['action'],
                        details=json.loads(row['details']),
                        ip_address=row['ip_address'] or "",
                        user_agent=row['user_agent'] or "",
                        session_id=row['session_id'] or ""
                    ))
        except Exception as e:
            logger.error(f"Failed to get audit events: {e}")
        
        return events
    
    def generate_audit_report(self, 
                            start_time: datetime,
                            end_time: datetime,
                            format: str = "json") -> str:
        """Generate audit report"""
        events = self.get_events(start_time, end_time)
        
        if format == "json":
            return json.dumps([asdict(event) for event in events], 
                            default=str, indent=2)
        
        elif format == "csv" and PANDAS_AVAILABLE:
            df = pd.DataFrame([asdict(event) for event in events])
            return df.to_csv(index=False)
        
        else:
            # Simple text format
            report = f"Audit Report: {start_time} to {end_time}\n"
            report += "=" * 50 + "\n\n"
            
            for event in events:
                report += f"Event ID: {event.event_id}\n"
                report += f"Type: {event.event_type.value}\n"
                report += f"Time: {event.timestamp}\n"
                report += f"User: {event.user_id}\n"
                report += f"Action: {event.action}\n"
                report += f"Resource: {event.resource}\n"
                report += "-" * 30 + "\n"
            
            return report


class ComplianceManager:
    """Main compliance management system"""
    
    def __init__(self, data_dir: str = "compliance_data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        self.requirements: Dict[str, ComplianceRequirement] = {}
        self.security_controls: Dict[SecurityControl, SecurityControlStatus] = {}
        self.audit_manager = AuditTrailManager()
        
        self._load_compliance_data()
        self._init_security_controls()
    
    def _load_compliance_data(self):
        """Load compliance requirements from configuration"""
        # SOC2 Type 1 requirements
        self._add_soc2_requirements()
        
        # ISO27001 requirements  
        self._add_iso27001_requirements()
        
        # GDPR requirements
        self._add_gdpr_requirements()
        
        # HIPAA requirements
        self._add_hipaa_requirements()
        
        logger.info(f"Loaded {len(self.requirements)} compliance requirements")
    
    def _add_soc2_requirements(self):
        """Add SOC2 compliance requirements"""
        soc2_requirements = [
            {
                "control_id": "CC1.1",
                "title": "Control Environment",
                "description": "The entity demonstrates a commitment to integrity and ethical values",
                "severity": "HIGH"
            },
            {
                "control_id": "CC2.1", 
                "title": "Communication and Information",
                "description": "The entity obtains or generates and uses relevant, quality information",
                "severity": "MEDIUM"
            },
            {
                "control_id": "CC3.1",
                "title": "Risk Assessment",
                "description": "The entity specifies objectives with sufficient clarity",
                "severity": "HIGH"
            },
            {
                "control_id": "CC6.1",
                "title": "Logical and Physical Access Controls",
                "description": "The entity implements logical access security software",
                "severity": "HIGH"
            },
            {
                "control_id": "CC7.1",
                "title": "System Operations",
                "description": "The entity ensures authorized system changes are completed",
                "severity": "MEDIUM"
            }
        ]
        
        for req in soc2_requirements:
            requirement = ComplianceRequirement(
                framework=ComplianceFramework.SOC2_TYPE1,
                control_id=req["control_id"],
                title=req["title"],
                description=req["description"],
                severity=req["severity"],
                status=ComplianceStatus.UNDER_REVIEW
            )
            self.requirements[f"SOC2_{req['control_id']}"] = requirement
    
    def _add_iso27001_requirements(self):
        """Add ISO27001 compliance requirements"""
        iso_requirements = [
            {
                "control_id": "A.5.1.1",
                "title": "Information Security Policies",
                "description": "Set of policies for information security shall be defined",
                "severity": "HIGH"
            },
            {
                "control_id": "A.6.1.1",
                "title": "Information Security Roles and Responsibilities", 
                "description": "All information security responsibilities shall be defined",
                "severity": "HIGH"
            },
            {
                "control_id": "A.9.1.1",
                "title": "Access Control Policy",
                "description": "An access control policy shall be established",
                "severity": "HIGH"
            },
            {
                "control_id": "A.12.1.1",
                "title": "Documented Operating Procedures",
                "description": "Operating procedures shall be documented and made available",
                "severity": "MEDIUM"
            }
        ]
        
        for req in iso_requirements:
            requirement = ComplianceRequirement(
                framework=ComplianceFramework.ISO27001,
                control_id=req["control_id"],
                title=req["title"],
                description=req["description"],
                severity=req["severity"],
                status=ComplianceStatus.UNDER_REVIEW
            )
            self.requirements[f"ISO27001_{req['control_id']}"] = requirement
    
    def _add_gdpr_requirements(self):
        """Add GDPR compliance requirements"""
        gdpr_requirements = [
            {
                "control_id": "Art.5",
                "title": "Principles for Processing Personal Data",
                "description": "Personal data shall be processed lawfully, fairly and transparently",
                "severity": "HIGH"
            },
            {
                "control_id": "Art.25",
                "title": "Data Protection by Design and by Default",
                "description": "Implement appropriate technical and organizational measures",
                "severity": "HIGH"
            },
            {
                "control_id": "Art.32",
                "title": "Security of Processing",
                "description": "Implement appropriate technical and organizational measures",
                "severity": "HIGH"
            },
            {
                "control_id": "Art.33",
                "title": "Notification of Personal Data Breach",
                "description": "Notify supervisory authority within 72 hours",
                "severity": "HIGH"
            }
        ]
        
        for req in gdpr_requirements:
            requirement = ComplianceRequirement(
                framework=ComplianceFramework.GDPR,
                control_id=req["control_id"],
                title=req["title"],
                description=req["description"],
                severity=req["severity"],
                status=ComplianceStatus.UNDER_REVIEW
            )
            self.requirements[f"GDPR_{req['control_id']}"] = requirement
    
    def _add_hipaa_requirements(self):
        """Add HIPAA compliance requirements"""
        hipaa_requirements = [
            {
                "control_id": "164.308(a)(1)",
                "title": "Security Officer",
                "description": "Assign security responsibilities to an individual",
                "severity": "HIGH"
            },
            {
                "control_id": "164.308(a)(3)",
                "title": "Workforce Training",
                "description": "Implement procedures for workforce training",
                "severity": "MEDIUM"
            },
            {
                "control_id": "164.312(a)(1)",
                "title": "Access Control",
                "description": "Implement technical safeguards to control access",
                "severity": "HIGH"
            },
            {
                "control_id": "164.312(b)",
                "title": "Audit Controls",
                "description": "Implement hardware, software, and/or procedural mechanisms",
                "severity": "HIGH"
            }
        ]
        
        for req in hipaa_requirements:
            requirement = ComplianceRequirement(
                framework=ComplianceFramework.HIPAA,
                control_id=req["control_id"],
                title=req["title"],
                description=req["description"],
                severity=req["severity"],
                status=ComplianceStatus.UNDER_REVIEW
            )
            self.requirements[f"HIPAA_{req['control_id']}"] = requirement
    
    def _init_security_controls(self):
        """Initialize security controls"""
        for control in SecurityControl:
            self.security_controls[control] = SecurityControlStatus(
                control=control,
                implemented=False,
                effectiveness=0.0,
                last_tested=datetime.now(),
                findings=[],
                remediation_actions=[]
            )
    
    def assess_compliance(self, framework: ComplianceFramework) -> Dict[str, Any]:
        """Assess compliance for a framework"""
        framework_requirements = [
            req for req in self.requirements.values() 
            if req.framework == framework
        ]
        
        if not framework_requirements:
            return {"error": f"No requirements found for {framework.value}"}
        
        total_requirements = len(framework_requirements)
        compliant_count = len([
            req for req in framework_requirements 
            if req.status == ComplianceStatus.COMPLIANT
        ])
        partial_count = len([
            req for req in framework_requirements
            if req.status == ComplianceStatus.PARTIAL_COMPLIANCE
        ])
        
        compliance_percentage = (compliant_count / total_requirements) * 100
        
        return {
            "framework": framework.value,
            "total_requirements": total_requirements,
            "compliant_requirements": compliant_count,
            "partial_compliance": partial_count,
            "compliance_percentage": compliance_percentage,
            "assessment_date": datetime.now().isoformat(),
            "requirements": [asdict(req) for req in framework_requirements]
        }
    
    def update_requirement_status(self, requirement_id: str, status: ComplianceStatus, evidence: List[str] = None):
        """Update compliance requirement status"""
        if requirement_id in self.requirements:
            self.requirements[requirement_id].status = status
            self.requirements[requirement_id].last_assessed = datetime.now()
            
            if evidence:
                self.requirements[requirement_id].evidence.extend(evidence)
            
            # Log audit event
            self.audit_manager.log_event(AuditTrailEntry(
                event_id="",
                event_type=AuditEvent.CONFIGURATION_CHANGE,
                timestamp=datetime.now(),
                user_id="system",
                resource=f"compliance_requirement_{requirement_id}",
                action="status_update",
                details={
                    "requirement_id": requirement_id,
                    "new_status": status.value,
                    "evidence_count": len(evidence) if evidence else 0
                }
            ))
            
            logger.info(f"Updated requirement {requirement_id} status to {status.value}")
        else:
            logger.error(f"Requirement {requirement_id} not found")
    
    def update_security_control(self, control: SecurityControl, implemented: bool, effectiveness: float, findings: List[str] = None):
        """Update security control status"""
        if control in self.security_controls:
            self.security_controls[control].implemented = implemented
            self.security_controls[control].effectiveness = effectiveness
            self.security_controls[control].last_tested = datetime.now()
            
            if findings:
                self.security_controls[control].findings.extend(findings)
            
            # Log audit event
            self.audit_manager.log_event(AuditTrailEntry(
                event_id="",
                event_type=AuditEvent.CONFIGURATION_CHANGE,
                timestamp=datetime.now(),
                user_id="system",
                resource=f"security_control_{control.value}",
                action="control_update",
                details={
                    "control": control.value,
                    "implemented": implemented,
                    "effectiveness": effectiveness,
                    "findings_count": len(findings) if findings else 0
                }
            ))
            
            logger.info(f"Updated security control {control.value}")
    
    def generate_compliance_report(self, frameworks: List[ComplianceFramework] = None, format: str = "json") -> str:
        """Generate comprehensive compliance report"""
        if frameworks is None:
            frameworks = list(ComplianceFramework)
        
        report_data = {
            "report_date": datetime.now().isoformat(),
            "frameworks": {},
            "security_controls": {},
            "summary": {}
        }
        
        # Framework assessments
        total_compliant = 0
        total_requirements = 0
        
        for framework in frameworks:
            assessment = self.assess_compliance(framework)
            report_data["frameworks"][framework.value] = assessment
            
            if "compliant_requirements" in assessment:
                total_compliant += assessment["compliant_requirements"]
                total_requirements += assessment["total_requirements"]
        
        # Security controls
        for control, status in self.security_controls.items():
            report_data["security_controls"][control.value] = asdict(status)
        
        # Summary
        overall_compliance = (total_compliant / total_requirements * 100) if total_requirements > 0 else 0
        report_data["summary"] = {
            "overall_compliance_percentage": overall_compliance,
            "total_requirements": total_requirements,
            "total_compliant": total_compliant,
            "frameworks_assessed": len(frameworks),
            "security_controls_implemented": len([
                c for c in self.security_controls.values() if c.implemented
            ])
        }
        
        if format == "json":
            return json.dumps(report_data, default=str, indent=2)
        elif format == "html" and JINJA2_AVAILABLE:
            return self._generate_html_report(report_data)
        else:
            return self._generate_text_report(report_data)
    
    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate HTML compliance report"""
        template_str = '''
        <html>
        <head>
            <title>VMDragonSlayer Compliance Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .header { background-color: #f0f0f0; padding: 20px; }
                .summary { background-color: #e8f4f8; padding: 15px; margin: 20px 0; }
                .framework { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
                .requirement { margin: 10px 0; padding: 10px; background-color: #f9f9f9; }
                .compliant { border-left: 4px solid #4CAF50; }
                .non-compliant { border-left: 4px solid #f44336; }
                .partial { border-left: 4px solid #ff9800; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>VMDragonSlayer Compliance Report</h1>
                <p>Generated: {{ report_date }}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <p>Overall Compliance: {{ "%.1f"|format(summary.overall_compliance_percentage) }}%</p>
                <p>Total Requirements: {{ summary.total_requirements }}</p>
                <p>Compliant Requirements: {{ summary.total_compliant }}</p>
                <p>Security Controls Implemented: {{ summary.security_controls_implemented }}</p>
            </div>
            
            {% for framework_name, framework_data in frameworks.items() %}
            <div class="framework">
                <h2>{{ framework_name|upper }}</h2>
                <p>Compliance: {{ "%.1f"|format(framework_data.compliance_percentage) }}%</p>
                <p>{{ framework_data.compliant_requirements }}/{{ framework_data.total_requirements }} requirements met</p>
            </div>
            {% endfor %}
        </body>
        </html>
        '''
        
        template = Template(template_str)
        return template.render(**data)
    
    def _generate_text_report(self, data: Dict[str, Any]) -> str:
        """Generate text compliance report"""
        report = "VMDragonSlayer Compliance Report\n"
        report += "=" * 40 + "\n"
        report += f"Generated: {data['report_date']}\n\n"
        
        # Summary
        summary = data['summary']
        report += "SUMMARY\n"
        report += "-" * 20 + "\n"
        report += f"Overall Compliance: {summary['overall_compliance_percentage']:.1f}%\n"
        report += f"Total Requirements: {summary['total_requirements']}\n"
        report += f"Compliant Requirements: {summary['total_compliant']}\n"
        report += f"Security Controls Implemented: {summary['security_controls_implemented']}\n\n"
        
        # Frameworks
        for framework_name, framework_data in data['frameworks'].items():
            report += f"{framework_name.upper()}\n"
            report += "-" * 20 + "\n"
            report += f"Compliance: {framework_data['compliance_percentage']:.1f}%\n"
            report += f"Requirements: {framework_data['compliant_requirements']}/{framework_data['total_requirements']}\n\n"
        
        return report


# Example usage
async def main():
    """Example usage of compliance framework"""
    
    # Initialize compliance manager
    compliance_manager = ComplianceManager()
    
    # Update some requirement statuses
    compliance_manager.update_requirement_status(
        "SOC2_CC1.1",
        ComplianceStatus.COMPLIANT,
        ["Policy document created", "Training completed"]
    )
    
    compliance_manager.update_requirement_status(
        "ISO27001_A.5.1.1", 
        ComplianceStatus.PARTIAL_COMPLIANCE,
        ["Draft policy exists"]
    )
    
    # Update security controls
    compliance_manager.update_security_control(
        SecurityControl.ACCESS_CONTROL,
        implemented=True,
        effectiveness=0.85,
        findings=["Strong password policy implemented"]
    )
    
    # Generate compliance reports
    soc2_assessment = compliance_manager.assess_compliance(ComplianceFramework.SOC2_TYPE1)
    print("SOC2 Assessment:", json.dumps(soc2_assessment, indent=2, default=str))
    
    # Generate full compliance report
    full_report = compliance_manager.generate_compliance_report()
    print("\nFull Compliance Report:")
    print(full_report)


if __name__ == "__main__":
    asyncio.run(main())
