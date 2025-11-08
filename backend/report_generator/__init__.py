"""
AuditEase Report Generator Module

Production-ready compliance report generation for ISO 27001, CIS Controls v8, and RBI Guidelines.
Generates JSON, Excel, PDF reports with embedded charts, heatmaps, and detailed remediation guidance.

Author: AuditEase Team
Version: 2.0.0
"""

from .integrated_generator import (
    generate_comprehensive_report,
    generate_and_return_summary,
    ReportGenerator
)
from .schema import (
    ReportSchema,
    validate_input_snapshot as validate_snapshot,
    RuleStatus,
    Priority,
    Framework,
    Severity
)

__version__ = "2.0.0"
__all__ = [
    "generate_comprehensive_report",
    "generate_and_return_summary",
    "ReportGenerator",
    "ReportSchema",
    "validate_snapshot",
    "RuleStatus",
    "Priority",
    "Framework",
    "Severity"
]

