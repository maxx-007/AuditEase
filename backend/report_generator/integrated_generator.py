"""
Integrated Report Generator
===========================

Wraps existing report services and provides unified API for frontend integration.

Author: AuditEase Security Team
Version: 2.0.0
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.ultra_comprehensive_report_service import UltraComprehensiveReportService
from services.enhanced_pdf_service import EnhancedPDFService

logger = logging.getLogger(__name__)


def generate_and_return_summary(
    input_json_path: str,
    output_dir: str = "reports"
) -> Dict[str, Any]:
    """
    Generate comprehensive reports and return summary for frontend.
    
    This is the main entry point for report generation that the backend API should call.
    
    Args:
        input_json_path: Path to audit results JSON file
        output_dir: Directory to save generated reports
        
    Returns:
        Dictionary with:
        {
            "run_id": str,
            "summary": {...},
            "files": {
                "report_json": path,
                "excel": path,
                "pdf": path,
                "charts": [paths]
            }
        }
    """
    try:
        logger.info(f"📊 Generating comprehensive reports from: {input_json_path}")
        
        # Load audit data
        with open(input_json_path, 'r') as f:
            audit_data = json.load(f)
        
        # Generate run ID
        run_id = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Extract company name
        company_name = "Organization"
        if 'dashboard_summary' in audit_data:
            dash = audit_data['dashboard_summary']
            if 'company' in dash and 'name' in dash['company']:
                company_name = dash['company']['name']
        elif 'company_name' in audit_data:
            company_name = audit_data['company_name']
        
        # Initialize services
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        excel_service = UltraComprehensiveReportService(output_dir=str(output_path))
        pdf_service = EnhancedPDFService(output_dir=str(output_path))
        
        # Generate reports
        logger.info("📊 Generating Excel report...")
        excel_path = excel_service.generate_ultra_comprehensive_excel(
            audit_results=audit_data,
            system_name=company_name
        )
        
        logger.info("📄 Generating PDF report...")
        pdf_path = pdf_service.generate_comprehensive_pdf(
            audit_results=audit_data,
            company_name=company_name
        )
        
        # Save JSON report
        logger.info("💾 Saving JSON report...")
        json_path = output_path / f"report_{run_id}.json"
        with open(json_path, 'w') as f:
            json.dump(audit_data, f, indent=2)
        
        # Create summary JSON
        summary = _create_summary(audit_data, run_id)
        summary_path = output_path / f"report_summary_{run_id}.json"
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        # Collect chart paths
        charts_dir = output_path / "charts"
        chart_paths = []
        if charts_dir.exists():
            chart_paths = [str(p) for p in charts_dir.glob("*.png")]
        
        logger.info(f"✅ Report generation complete: {run_id}")
        
        return {
            "run_id": run_id,
            "summary": summary,
            "files": {
                "report_json": str(json_path),
                "report_summary": str(summary_path),
                "excel": str(excel_path),
                "pdf": str(pdf_path),
                "charts": chart_paths
            }
        }
        
    except Exception as e:
        logger.error(f"❌ Report generation failed: {e}", exc_info=True)
        return {
            "run_id": None,
            "error": str(e),
            "summary": {},
            "files": {}
        }


def _create_summary(audit_data: Dict[str, Any], run_id: str) -> Dict[str, Any]:
    """Create summary object for frontend."""
    
    # Extract key metrics
    key_metrics = audit_data.get('key_metrics', {})
    dashboard = audit_data.get('dashboard_summary', {})
    frameworks = audit_data.get('framework_scores', [])
    
    # Calculate summary statistics
    total_rules = key_metrics.get('total_rules_checked', 0)
    passed = key_metrics.get('rules_passed', 0)
    failed = key_metrics.get('rules_failed', 0)
    
    pass_rate = (passed / total_rules * 100) if total_rules > 0 else 0
    
    # Count issues by severity
    severity_dist = audit_data.get('severity_distribution', [])
    severity_counts = {item['severity']: item['count'] for item in severity_dist}
    
    # Framework summaries
    framework_summaries = []
    for fw in frameworks:
        framework_summaries.append({
            'name': fw.get('name', 'Unknown'),
            'score': fw.get('score', 0),
            'passed': fw.get('passed', 0),
            'total': fw.get('total', 0),
            'risk_level': fw.get('risk_level', 'UNKNOWN')
        })
    
    # Top gaps
    priority_issues = audit_data.get('priority_issues', [])[:10]
    top_gaps = []
    for issue in priority_issues:
        top_gaps.append({
            'rule_id': issue.get('id', ''),
            'title': issue.get('title', ''),
            'category': issue.get('category', ''),
            'severity': issue.get('severity', 'MEDIUM'),
            'remediation': issue.get('remediation', '')
        })
    
    return {
        'run_id': run_id,
        'generated_at': datetime.now().isoformat(),
        'company_name': dashboard.get('company', {}).get('name', 'Unknown'),
        'overall_score': dashboard.get('overall_score', 0),
        'risk_level': dashboard.get('risk_level', 'UNKNOWN'),
        'total_rules': total_rules,
        'passed_rules': passed,
        'failed_rules': failed,
        'pass_rate': round(pass_rate, 2),
        'critical_issues': severity_counts.get('CRITICAL', 0),
        'high_issues': severity_counts.get('HIGH', 0),
        'medium_issues': severity_counts.get('MEDIUM', 0),
        'low_issues': severity_counts.get('LOW', 0),
        'frameworks': framework_summaries,
        'top_gaps': top_gaps,
        'remediation_summary': audit_data.get('remediation_summary', {})
    }


def generate_comprehensive_report(
    snapshot: Dict[str, Any],
    output_dir: str = "reports",
    previous_snapshot: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Generate comprehensive report from snapshot dictionary.
    
    Args:
        snapshot: Compliance snapshot dictionary
        output_dir: Output directory for reports
        previous_snapshot: Optional previous snapshot for trend analysis
        
    Returns:
        Report generation result with file paths
    """
    try:
        # Save snapshot to temp file
        temp_path = Path(output_dir) / f"temp_snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        temp_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(temp_path, 'w') as f:
            json.dump(snapshot, f, indent=2)
        
        # Generate reports
        result = generate_and_return_summary(str(temp_path), output_dir)
        
        # Clean up temp file
        if temp_path.exists():
            temp_path.unlink()
        
        return result
        
    except Exception as e:
        logger.error(f"❌ Report generation failed: {e}", exc_info=True)
        return {
            "success": False,
            "error": str(e)
        }


# Convenience class wrapper
class ReportGenerator:
    """Report generator class for object-oriented usage."""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
    
    def generate(
        self,
        snapshot: Dict[str, Any],
        previous_snapshot: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Generate comprehensive report."""
        return generate_comprehensive_report(
            snapshot=snapshot,
            output_dir=self.output_dir,
            previous_snapshot=previous_snapshot
        )
    
    def generate_from_file(self, input_path: str) -> Dict[str, Any]:
        """Generate report from JSON file."""
        return generate_and_return_summary(input_path, self.output_dir)

