"""
Report Generator Example Usage
==============================

Example script demonstrating how to use the report generator module.

Author: AuditEase Security Team
Version: 2.0.0
"""

import json
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from report_generator import (
    generate_comprehensive_report,
    generate_and_return_summary,
    ReportGenerator
)


def example_1_from_file():
    """Example 1: Generate report from existing JSON file."""
    print("=" * 80)
    print("EXAMPLE 1: Generate Report from JSON File")
    print("=" * 80)
    
    # Path to your audit results JSON file
    input_file = "reports/frontend_report_20251108_235939.json"
    output_dir = "reports/generated"
    
    # Generate report
    result = generate_and_return_summary(
        input_json_path=input_file,
        output_dir=output_dir
    )
    
    # Print results
    print(f"\n✅ Report Generated!")
    print(f"Run ID: {result['run_id']}")
    print(f"\nGenerated Files:")
    for file_type, path in result['files'].items():
        if isinstance(path, list):
            print(f"  {file_type}:")
            for p in path:
                print(f"    - {p}")
        else:
            print(f"  {file_type}: {path}")
    
    print(f"\nSummary:")
    summary = result['summary']
    print(f"  Company: {summary.get('company_name')}")
    print(f"  Overall Score: {summary.get('overall_score')}")
    print(f"  Risk Level: {summary.get('risk_level')}")
    print(f"  Total Rules: {summary.get('total_rules')}")
    print(f"  Passed: {summary.get('passed_rules')}")
    print(f"  Failed: {summary.get('failed_rules')}")
    print(f"  Pass Rate: {summary.get('pass_rate')}%")


def example_2_from_dict():
    """Example 2: Generate report from dictionary."""
    print("\n" + "=" * 80)
    print("EXAMPLE 2: Generate Report from Dictionary")
    print("=" * 80)
    
    # Sample snapshot data
    snapshot = {
        "meta": {
            "version": "1.0.0",
            "generated_at": "2025-11-08T12:00:00Z"
        },
        "dashboard_summary": {
            "company": {
                "name": "Example Corp",
                "type": "Enterprise"
            },
            "overall_score": 65.5,
            "risk_level": "MEDIUM"
        },
        "key_metrics": {
            "total_rules_checked": 150,
            "rules_passed": 98,
            "rules_failed": 52
        },
        "framework_scores": [
            {
                "name": "CIS",
                "score": 68.0,
                "passed": 34,
                "total": 50,
                "risk_level": "MEDIUM"
            }
        ],
        "detailed_frameworks": {
            "CIS": {
                "overall": {
                    "total_rules": 50,
                    "compliance_percentage": 68.0
                },
                "critical_gaps": []
            }
        },
        "priority_issues": []
    }
    
    # Generate report
    result = generate_comprehensive_report(
        snapshot=snapshot,
        output_dir="reports/generated"
    )
    
    print(f"\n✅ Report Generated!")
    print(f"Run ID: {result['run_id']}")
    print(f"Summary: {result['summary'].get('company_name')} - {result['summary'].get('overall_score')}%")


def example_3_using_class():
    """Example 3: Using ReportGenerator class."""
    print("\n" + "=" * 80)
    print("EXAMPLE 3: Using ReportGenerator Class")
    print("=" * 80)
    
    # Initialize generator
    generator = ReportGenerator(output_dir="reports/generated")
    
    # Load audit data
    input_file = "reports/frontend_report_20251108_235939.json"
    
    # Generate report
    result = generator.generate_from_file(input_file)
    
    print(f"\n✅ Report Generated!")
    print(f"Run ID: {result['run_id']}")
    
    # Access summary data
    summary = result['summary']
    print(f"\nTop Gaps:")
    for i, gap in enumerate(summary.get('top_gaps', [])[:5], 1):
        print(f"  {i}. [{gap.get('severity')}] {gap.get('title')}")


def example_4_with_trend_analysis():
    """Example 4: Generate report with trend analysis."""
    print("\n" + "=" * 80)
    print("EXAMPLE 4: Report with Trend Analysis")
    print("=" * 80)
    
    # Load current and previous snapshots
    current_snapshot = {
        "dashboard_summary": {
            "company": {"name": "Example Corp"},
            "overall_score": 70.0
        },
        "key_metrics": {
            "total_rules_checked": 100,
            "rules_passed": 70,
            "rules_failed": 30
        },
        "detailed_frameworks": {},
        "priority_issues": []
    }
    
    previous_snapshot = {
        "dashboard_summary": {
            "company": {"name": "Example Corp"},
            "overall_score": 65.0
        },
        "key_metrics": {
            "total_rules_checked": 100,
            "rules_passed": 65,
            "rules_failed": 35
        },
        "detailed_frameworks": {},
        "priority_issues": []
    }
    
    # Generate report with trend analysis
    result = generate_comprehensive_report(
        snapshot=current_snapshot,
        output_dir="reports/generated",
        previous_snapshot=previous_snapshot
    )
    
    print(f"\n✅ Report with Trend Analysis Generated!")
    print(f"Run ID: {result['run_id']}")
    print(f"Current Score: 70.0%")
    print(f"Previous Score: 65.0%")
    print(f"Improvement: +5.0%")


if __name__ == "__main__":
    print("\n🎯 AuditEase Report Generator - Example Usage\n")
    
    # Check if audit file exists
    audit_file = Path("reports/frontend_report_20251108_235939.json")
    
    if audit_file.exists():
        # Run example with real data
        example_1_from_file()
        example_3_using_class()
    else:
        print(f"⚠️  Audit file not found: {audit_file}")
        print("Running examples with sample data instead...\n")
    
    # Run examples with sample data
    example_2_from_dict()
    example_4_with_trend_analysis()
    
    print("\n" + "=" * 80)
    print("✅ All Examples Complete!")
    print("=" * 80)
    print("\nCheck the 'reports/generated' directory for output files.")

