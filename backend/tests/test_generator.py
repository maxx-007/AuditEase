"""
Report Generator Tests
======================

Pytest test suite for report generator module.

Author: AuditEase Security Team
Version: 2.0.0
"""

import pytest
import json
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from report_generator import (
    generate_comprehensive_report,
    generate_and_return_summary,
    ReportGenerator,
    validate_snapshot,
    RuleStatus,
    Priority,
    Framework
)


@pytest.fixture
def sample_snapshot():
    """Sample compliance snapshot for testing."""
    return {
        "meta": {
            "version": "1.0.0",
            "generated_at": "2025-11-08T12:00:00Z"
        },
        "dashboard_summary": {
            "company": {
                "name": "Test Organization",
                "type": "Enterprise"
            },
            "overall_score": 45.5,
            "risk_level": "HIGH"
        },
        "key_metrics": {
            "total_rules_checked": 100,
            "rules_passed": 45,
            "rules_failed": 55
        },
        "framework_scores": [
            {
                "name": "CIS",
                "score": 42.0,
                "passed": 21,
                "total": 50,
                "risk_level": "HIGH"
            },
            {
                "name": "ISO27001",
                "score": 48.0,
                "passed": 24,
                "total": 50,
                "risk_level": "MEDIUM"
            }
        ],
        "detailed_frameworks": {
            "CIS": {
                "overall": {
                    "total_rules": 50,
                    "passed_rules": 21,
                    "failed_rules": 29,
                    "compliance_percentage": 42.0
                },
                "critical_gaps": [
                    {
                        "rule_id": "CIS-1.1",
                        "description": "Ensure password policy is configured",
                        "category": "Access Control",
                        "severity": "CRITICAL",
                        "weight": 3,
                        "field": "password_policy.enabled",
                        "expected": True,
                        "actual": False,
                        "remediation": "Configure password policy with minimum length and complexity requirements"
                    }
                ]
            }
        },
        "priority_issues": [
            {
                "id": "CIS-1.1",
                "title": "Password Policy Not Configured",
                "category": "Access Control",
                "severity": "CRITICAL",
                "current_status": False,
                "required_status": True,
                "remediation": "Enable and configure password policy"
            }
        ]
    }


@pytest.fixture
def temp_output_dir(tmp_path):
    """Temporary output directory for tests."""
    output_dir = tmp_path / "test_reports"
    output_dir.mkdir()
    return output_dir


def test_validate_snapshot_valid(sample_snapshot):
    """Test snapshot validation with valid data."""
    is_valid, errors = validate_snapshot(sample_snapshot)
    assert is_valid is True
    assert len(errors) == 0


def test_validate_snapshot_invalid():
    """Test snapshot validation with invalid data."""
    invalid_snapshot = {"invalid": "data"}
    is_valid, errors = validate_snapshot(invalid_snapshot)
    assert is_valid is False
    assert len(errors) > 0


def test_generate_comprehensive_report(sample_snapshot, temp_output_dir):
    """Test comprehensive report generation."""
    result = generate_comprehensive_report(
        snapshot=sample_snapshot,
        output_dir=str(temp_output_dir)
    )
    
    assert 'run_id' in result
    assert 'summary' in result
    assert 'files' in result


def test_report_generator_class(sample_snapshot, temp_output_dir):
    """Test ReportGenerator class."""
    generator = ReportGenerator(output_dir=str(temp_output_dir))
    result = generator.generate(snapshot=sample_snapshot)
    
    assert 'run_id' in result
    assert 'summary' in result


def test_enums():
    """Test enum definitions."""
    assert RuleStatus.MET.value == "met"
    assert RuleStatus.UNMET.value == "unmet"
    assert Priority.CRITICAL.value == "CRITICAL"
    assert Framework.CIS.value == "CIS"


def test_generate_from_file(sample_snapshot, temp_output_dir):
    """Test report generation from JSON file."""
    # Create temp input file
    input_file = temp_output_dir / "test_input.json"
    with open(input_file, 'w') as f:
        json.dump(sample_snapshot, f)
    
    # Generate report
    generator = ReportGenerator(output_dir=str(temp_output_dir))
    result = generator.generate_from_file(str(input_file))
    
    assert 'run_id' in result
    assert 'summary' in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

