"""
Report Schema and Validation Module
===================================

Defines data structures, enums, and validation logic for compliance reports.

Author: AuditEase Security Team
Version: 2.0.0
"""

from enum import Enum
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field, asdict
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class RuleStatus(str, Enum):
    """Compliance rule status enumeration."""
    MET = "met"
    PARTIAL = "partial"
    UNMET = "unmet"
    SKIPPED = "skipped"
    ERROR = "error"


class Priority(str, Enum):
    """Remediation priority levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Framework(str, Enum):
    """Supported compliance frameworks."""
    CIS = "CIS"
    ISO27001 = "ISO27001"
    RBI = "RBI"
    NIST = "NIST"
    PCI_DSS = "PCI_DSS"
    HIPAA = "HIPAA"
    GDPR = "GDPR"


class Severity(str, Enum):
    """Issue severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class CVEReference:
    """CVE vulnerability reference."""
    cve_id: str
    summary: str
    cvss_score: Optional[float] = None
    link: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationCommand:
    """Platform-specific remediation command."""
    platform: str  # windows, linux, macos, android
    commands: List[str]
    description: Optional[str] = None
    requires_admin: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationStep:
    """Detailed remediation guidance."""
    title: str
    description: str
    steps: List[str]
    commands: List[RemediationCommand] = field(default_factory=list)
    estimated_effort_hours: float = 0.0
    cost_estimate: Optional[str] = None
    priority: Priority = Priority.MEDIUM
    validation_command: Optional[str] = None
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['priority'] = self.priority.value
        return result


@dataclass
class RuleResult:
    """Individual compliance rule result."""
    rule_id: str
    framework: str
    title: str
    description: str
    category: str
    status: RuleStatus
    severity: Severity
    weight: int = 1
    
    # Evidence and analysis
    expected: Any = None
    actual: Any = None
    evidence: Optional[str] = None
    reason: Optional[str] = None
    
    # Remediation
    remediation: Optional[RemediationStep] = None
    priority: Priority = Priority.MEDIUM
    estimated_effort_hours: float = 0.0
    
    # References
    cve_references: List[CVEReference] = field(default_factory=list)
    compliance_references: List[str] = field(default_factory=list)
    
    # Metadata
    field_path: Optional[str] = None
    last_checked: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'rule_id': self.rule_id,
            'framework': self.framework,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'status': self.status.value,
            'severity': self.severity.value,
            'weight': self.weight,
            'expected': self.expected,
            'actual': self.actual,
            'evidence': self.evidence,
            'reason': self.reason,
            'priority': self.priority.value,
            'estimated_effort_hours': self.estimated_effort_hours,
            'cve_references': [cve.to_dict() for cve in self.cve_references],
            'compliance_references': self.compliance_references,
            'field_path': self.field_path,
            'last_checked': self.last_checked.isoformat() if self.last_checked else None
        }
        
        if self.remediation:
            result['remediation'] = self.remediation.to_dict()
        
        return result


@dataclass
class FrameworkSummary:
    """Framework-level compliance summary."""
    framework: str
    total_rules: int
    met: int
    partial: int
    unmet: int
    skipped: int
    error: int
    pass_rate: float
    total_weight: int
    achieved_weight: int
    weighted_score: float
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CategorySummary:
    """Category-level compliance summary."""
    category: str
    framework: str
    total_rules: int
    met: int
    partial: int
    unmet: int
    pass_rate: float
    severity_counts: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReportMetadata:
    """Report generation metadata."""
    run_id: str
    generated_at: datetime
    dataset_source: str
    model_version: Optional[str] = None
    generator_version: str = "2.0.0"
    company_name: Optional[str] = None
    assessment_date: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'run_id': self.run_id,
            'generated_at': self.generated_at.isoformat(),
            'dataset_source': self.dataset_source,
            'model_version': self.model_version,
            'generator_version': self.generator_version,
            'company_name': self.company_name,
            'assessment_date': self.assessment_date.isoformat() if self.assessment_date else None
        }


class ReportSchema:
    """Complete report schema definition."""
    
    @staticmethod
    def create_empty_report(run_id: str, dataset_source: str) -> Dict[str, Any]:
        """Create an empty report structure."""
        metadata = ReportMetadata(
            run_id=run_id,
            generated_at=datetime.now(),
            dataset_source=dataset_source
        )
        
        return {
            'metadata': metadata.to_dict(),
            'summary_scores': {
                'overall_score': 0.0,
                'risk_level': 'UNKNOWN',
                'total_rules': 0,
                'met': 0,
                'partial': 0,
                'unmet': 0,
                'skipped': 0
            },
            'frameworks': {},
            'categories': {},
            'rules': [],
            'top_gaps': [],
            'remediation_summary': {
                'critical_count': 0,
                'high_count': 0,
                'medium_count': 0,
                'low_count': 0,
                'total_estimated_hours': 0.0,
                'total_estimated_cost': '$0'
            },
            'aggregations': {}
        }


def validate_snapshot(snapshot: Dict[str, Any]) -> tuple[bool, List[str]]:
    """
    Validate input snapshot structure.
    
    Args:
        snapshot: Input compliance snapshot
        
    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    errors = []
    
    # Check for required top-level keys
    if not isinstance(snapshot, dict):
        errors.append("Snapshot must be a dictionary")
        return False, errors
    
    # Check for common data sections (at least one should exist)
    expected_sections = [
        'network', 'vulnerability_management', 'patch_management',
        'antimalware', 'endpoint_security', 'access_control',
        'logging', 'detailed_frameworks', 'dashboard_summary'
    ]
    
    has_data = any(section in snapshot for section in expected_sections)
    if not has_data:
        errors.append(f"Snapshot missing expected data sections. Expected at least one of: {expected_sections}")
    
    # Validate structure if detailed_frameworks exists
    if 'detailed_frameworks' in snapshot:
        frameworks = snapshot['detailed_frameworks']
        if not isinstance(frameworks, dict):
            errors.append("detailed_frameworks must be a dictionary")
        else:
            for fw_name, fw_data in frameworks.items():
                if not isinstance(fw_data, dict):
                    errors.append(f"Framework {fw_name} data must be a dictionary")
    
    is_valid = len(errors) == 0
    return is_valid, errors


def validate_input_snapshot(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate and normalize input snapshot.
    
    Args:
        snapshot: Raw input snapshot
        
    Returns:
        Normalized snapshot
        
    Raises:
        ValueError: If snapshot is invalid
    """
    is_valid, errors = validate_snapshot(snapshot)
    
    if not is_valid:
        error_msg = "Invalid snapshot structure:\n" + "\n".join(f"  - {err}" for err in errors)
        logger.error(error_msg)
        raise ValueError(error_msg)
    
    logger.info("✓ Snapshot validation passed")
    return snapshot

