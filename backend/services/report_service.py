"""
Report Service Module
====================
Generates comprehensive compliance reports in multiple formats.
"""

from typing import Dict, Any, List
from pathlib import Path
import json
import yaml
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.units import inch
from utils.logger import setup_logger

logger = setup_logger("report_service")


class ReportService:
    """Comprehensive report generation service."""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize report service."""
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        
        self.reports_dir = Path(self.config['paths']['reports_dir'])
        self.reports_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        for subdir in ['json', 'pdf', 'excel', 'charts']:
            (self.reports_dir / subdir).mkdir(exist_ok=True)
    
    def generate_all_reports(
        self, 
        audit_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate all report formats.
        
        Args:
            audit_results: Comprehensive audit results
        
        Returns:
            Paths to generated reports
        """
        company_name = audit_results.get("company_name", "unknown")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        generated_reports = {
            "company_name": company_name,
            "generation_timestamp": datetime.now().isoformat(),
            "reports": {}
        }
        
        try:
            # 1. Frontend JSON (for React dashboard)
            logger.info("📱 Generating frontend JSON...")
            frontend_json = self._generate_frontend_json(audit_results)
            frontend_path = self.reports_dir / "json" / f"frontend_{company_name}_{timestamp}.json"
            with open(frontend_path, 'w') as f:
                json.dump(frontend_json, f, indent=2, default=str)
            generated_reports["reports"]["frontend_json"] = str(frontend_path)
            
            # 2. Excel Report
            logger.info("📊 Generating Excel report...")
            excel_path = self._generate_excel_report(audit_results, timestamp)
            generated_reports["reports"]["excel"] = str(excel_path)
            
            # 3. PDF Report
            logger.info("📄 Generating PDF report...")
            pdf_path = self._generate_pdf_report(audit_results, timestamp)
            generated_reports["reports"]["pdf"] = str(pdf_path)
            
            # 4. Charts and Visualizations
            logger.info("📈 Generating charts...")
            charts_paths = self._generate_charts(audit_results, timestamp)
            generated_reports["reports"]["charts"] = charts_paths
            
            logger.info(f"✓ All reports generated successfully")
            
        except Exception as e:
            logger.error(f"Report generation error: {e}", exc_info=True)
        
        return generated_reports
    
    def _generate_frontend_json(
        self, 
        audit_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate JSON optimized for React frontend consumption.
        
        This is the key format your React dashboard will use!
        """
        
        overall = audit_results["audit_results"].get("overall_compliance", {})
        frameworks = audit_results["audit_results"].get("frameworks", {})
        ml_prediction = audit_results.get("ml_prediction", {})
        
        # Dashboard Summary
        dashboard_summary = {
            "company": {
                "name": audit_results.get("company_name", "Unknown"),
                "type": audit_results.get("audit_results", {}).get("company_type", "Unknown")
            },
            "assessment_date": overall.get("assessment_date", datetime.now().isoformat()),
            "overall_score": overall.get("compliance_percentage", 0),
            "risk_level": overall.get("risk_level", "UNKNOWN"),
            "ml_prediction": {
                "status": ml_prediction.get("prediction", "Unknown"),
                "confidence": ml_prediction.get("confidence", 0),
                "probabilities": ml_prediction.get("class_probabilities", {})
            }
        }
        
        # Framework Scores (for radar/bar charts)
        framework_scores = []
        for fw_name, fw_data in frameworks.items():
            framework_scores.append({
                "name": fw_name,
                "score": fw_data["compliance_percentage"],
                "passed": fw_data["passed_rules"],
                "total": fw_data["total_rules"],
                "risk_level": fw_data["risk_level"]
            })
        
        # Category Breakdown (for heatmap/grouped bars)
        category_breakdown = []
        for fw_name, fw_data in frameworks.items():
            for category, stats in fw_data.get("category_breakdown", {}).items():
                category_breakdown.append({
                    "framework": fw_name,
                    "category": category,
                    "compliance_pct": stats["compliance_pct"],
                    "passed": stats["passed"],
                    "total": stats["total"]
                })
        
        # Severity Distribution (for pie chart)
        severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for fw_data in frameworks.values():
            for severity, count in fw_data.get("severity_breakdown", {}).items():
                severity_totals[severity] = severity_totals.get(severity, 0) + count
        
        severity_distribution = [
            {"severity": severity, "count": count}
            for severity, count in severity_totals.items()
        ]
        
        # Priority Issues (for table/list display)
        priority_issues = []
        for gap in overall.get("top_priority_gaps", []):
            priority_issues.append({
                "id": gap.get("rule_id", ""),
                "title": gap.get("description", ""),
                "category": gap.get("category", ""),
                "severity": gap.get("severity", ""),
                "current_status": gap.get("actual", ""),
                "required_status": gap.get("expected", ""),
                "remediation": gap.get("remediation", ""),
                "priority": "P0" if gap.get("severity") == "CRITICAL" else "P1"
            })
        
        # Compliance Trend (if historical data available - placeholder for now)
        compliance_trend = [
            {
                "date": (datetime.now().replace(day=1)).isoformat()[:10],
                "score": max(0, overall.get("compliance_percentage", 0) - 15)
            },
            {
                "date": (datetime.now().replace(day=15)).isoformat()[:10],
                "score": max(0, overall.get("compliance_percentage", 0) - 8)
            },
            {
                "date": datetime.now().isoformat()[:10],
                "score": overall.get("compliance_percentage", 0)
            }
        ]
        
        # Key Metrics (for stat cards)
        key_metrics = {
            "total_rules_checked": sum(fw["total_rules"] for fw in frameworks.values()),
            "rules_passed": sum(fw["passed_rules"] for fw in frameworks.values()),
            "rules_failed": sum(fw["failed_rules"] for fw in frameworks.values()),
            "critical_issues": overall.get("total_critical_issues", 0),
            "high_issues": overall.get("total_high_issues", 0),
            "frameworks_assessed": len(frameworks)
        }
        
        # Remediation Summary (actionable items)
        remediation_summary = {
            "immediate_actions": len([i for i in priority_issues if i["severity"] == "CRITICAL"]),
            "short_term_actions": len([i for i in priority_issues if i["severity"] == "HIGH"]),
            "estimated_effort": self._estimate_remediation_effort(priority_issues),
            "recommended_timeline": "30-60 days for critical items"
        }
        
        # Assemble complete frontend JSON
        return {
            "meta": {
                "version": "1.0.0",
                "generated_at": datetime.now().isoformat(),
                "data_validity": "current"
            },
            "dashboard_summary": dashboard_summary,
            "key_metrics": key_metrics,
            "framework_scores": framework_scores,
            "category_breakdown": category_breakdown,
            "severity_distribution": severity_distribution,
            "priority_issues": priority_issues,
            "compliance_trend": compliance_trend,
            "remediation_summary": remediation_summary,
            "detailed_frameworks": frameworks,  # Full framework data for drill-down
            "download_links": {
                "pdf_report": f"/api/reports/pdf/{audit_results.get('company_name', 'unknown')}",
                "excel_report": f"/api/reports/excel/{audit_results.get('company_name', 'unknown')}",
                "charts_package": f"/api/reports/charts/{audit_results.get('company_name', 'unknown')}"
            }
        }
    
    def _estimate_remediation_effort(self, issues: List[Dict]) -> str:
        """Estimate total remediation effort."""
        critical_count = len([i for i in issues if i["severity"] == "CRITICAL"])
        high_count = len([i for i in issues if i["severity"] == "HIGH"])
        
        # Rough estimation
        days = (critical_count * 3) + (high_count * 2)
        
        if days < 7:
            return "Low (< 1 week)"
        elif days < 30:
            return "Medium (1-4 weeks)"
        else:
            return "High (1-2 months)"
    
    def _generate_excel_report(
        self, 
        audit_results: Dict[str, Any],
        timestamp: str
    ) -> Path:
        """Generate comprehensive Excel report."""
        company_name = audit_results.get("company_name", "unknown")
        excel_path = self.reports_dir / "excel" / f"report_{company_name}_{timestamp}.xlsx"
        
        with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
            # Summary Sheet
            overall = audit_results["audit_results"].get("overall_compliance", {})
            summary_data = {
                "Company": [company_name],
                "Assessment Date": [overall.get("assessment_date", "")],
                "Overall Compliance": [overall.get("compliance_percentage", 0)],
                "Risk Level": [overall.get("risk_level", "")],
                "Critical Issues": [overall.get("total_critical_issues", 0)],
                "High Issues": [overall.get("total_high_issues", 0)]
            }
            pd.DataFrame(summary_data).to_excel(writer, sheet_name="Summary", index=False)
            
            # Framework Scores
            frameworks = audit_results["audit_results"].get("frameworks", {})
            framework_data = []
            for fw_name, fw_data in frameworks.items():
                framework_data.append({
                    "Framework": fw_name,
                    "Compliance %": fw_data["compliance_percentage"],
                    "Passed Rules": fw_data["passed_rules"],
                    "Total Rules": fw_data["total_rules"],
                    "Risk Level": fw_data["risk_level"],
                    "Critical Issues": fw_data["severity_breakdown"].get("CRITICAL", 0),
                    "High Issues": fw_data["severity_breakdown"].get("HIGH", 0)
                })
            pd.DataFrame(framework_data).to_excel(writer, sheet_name="Frameworks", index=False)
            
            # Priority Issues
            issues_data = []
            for gap in overall.get("top_priority_gaps", []):
                issues_data.append({
                    "Rule ID": gap.get("rule_id", ""),
                    "Description": gap.get("description", ""),
                    "Category": gap.get("category", ""),
                    "Severity": gap.get("severity", ""),
                    "Current": gap.get("actual", ""),
                    "Required": gap.get("expected", ""),
                    "Remediation": gap.get("remediation", "")
                })
            if issues_data:
                pd.DataFrame(issues_data).to_excel(writer, sheet_name="Priority Issues", index=False)
        
        logger.info(f"✓ Excel report saved: {excel_path}")
        return excel_path
    
    def _generate_pdf_report(
        self,
        audit_results: Dict[str, Any],
        timestamp: str
    ) -> Path:
        """Generate executive PDF report."""
        company_name = audit_results.get("company_name", "unknown")
        pdf_path = self.reports_dir / "pdf" / f"report_{company_name}_{timestamp}.pdf"
        
        doc = SimpleDocTemplate(str(pdf_path), pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        story.append(Paragraph(
            f"Compliance Assessment Report",
            styles['Title']
        ))
        story.append(Spacer(1, 20))
        
        # Company Info
        story.append(Paragraph(f"<b>Company:</b> {company_name}", styles['Normal']))
        story.append(Paragraph(
            f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d')}", 
            styles['Normal']
        ))
        story.append(Spacer(1, 20))
        
        # Overall Score
        overall = audit_results["audit_results"].get("overall_compliance", {})
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        story.append(Paragraph(
            f"<b>Overall Compliance Score:</b> {overall.get('compliance_percentage', 0):.1f}%",
            styles['Normal']
        ))
        story.append(Paragraph(
            f"<b>Risk Level:</b> {overall.get('risk_level', 'Unknown')}",
            styles['Normal']
        ))
        story.append(Spacer(1, 20))
        
        # Framework Table
        story.append(Paragraph("Framework Compliance", styles['Heading2']))
        
        frameworks = audit_results["audit_results"].get("frameworks", {})
        table_data = [["Framework", "Score", "Risk Level", "Passed/Total"]]
        
        for fw_name, fw_data in frameworks.items():
            table_data.append([
                fw_name,
                f"{fw_data['compliance_percentage']:.1f}%",
                fw_data['risk_level'],
                f"{fw_data['passed_rules']}/{fw_data['total_rules']}"
            ])
        
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
        
        # Build PDF
        doc.build(story)
        logger.info(f"✓ PDF report saved: {pdf_path}")
        return pdf_path
    
    def _generate_charts(
        self,
        audit_results: Dict[str, Any],
        timestamp: str
    ) -> Dict[str, str]:
        """Generate visualization charts."""
        company_name = audit_results.get("company_name", "unknown")
        charts_dir = self.reports_dir / "charts"
        
        charts = {}
        
        # 1. Framework Comparison Bar Chart
        frameworks = audit_results["audit_results"].get("frameworks", {})
        
        fig, ax = plt.subplots(figsize=(10, 6))
        fw_names = list(frameworks.keys())
        fw_scores = [frameworks[fw]["compliance_percentage"] for fw in fw_names]
        
        bars = ax.bar(fw_names, fw_scores, color=['#4CAF50', '#2196F3', '#FF9800'])
        ax.set_ylabel('Compliance Percentage (%)')
        ax.set_title(f'Framework Compliance - {company_name}')
        ax.set_ylim(0, 100)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{height:.1f}%', ha='center', va='bottom')
        
        chart_path = charts_dir / f"framework_comparison_{company_name}_{timestamp}.png"
        plt.tight_layout()
        plt.savefig(chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        charts["framework_comparison"] = str(chart_path)
        
        # 2. Severity Distribution Pie Chart
        overall = audit_results["audit_results"].get("overall_compliance", {})
        severity_data = {
            "CRITICAL": overall.get("total_critical_issues", 0),
            "HIGH": overall.get("total_high_issues", 0)
        }
        
        if sum(severity_data.values()) > 0:
            fig, ax = plt.subplots(figsize=(8, 8))
            colors_pie = ['#FF5252', '#FFC107']
            ax.pie(
                severity_data.values(), 
                labels=severity_data.keys(),
                autopct='%1.1f%%',
                colors=colors_pie,
                startangle=90
            )
            ax.set_title(f'Issue Severity Distribution - {company_name}')
            
            chart_path = charts_dir / f"severity_dist_{company_name}_{timestamp}.png"
            plt.tight_layout()
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            charts["severity_distribution"] = str(chart_path)
        
        logger.info(f"✓ Charts generated: {len(charts)}")
        return charts


# Example Frontend JSON Output Schema
FRONTEND_JSON_SCHEMA_EXAMPLE = """
{
  "meta": {
    "version": "1.0.0",
    "generated_at": "2025-01-15T10:30:00Z",
    "data_validity": "current"
  },
  "dashboard_summary": {
    "company": {
      "name": "SecureMax Industries",
      "type": "Financial Services"
    },
    "assessment_date": "2025-01-15T10:30:00Z",
    "overall_score": 87.5,
    "risk_level": "LOW",
    "ml_prediction": {
      "status": "Compliant",
      "confidence": 92.3,
      "probabilities": {
        "Compliant": 92.3,
        "Non-Compliant": 7.7
      }
    }
  },
  "key_metrics": {
    "total_rules_checked": 150,
    "rules_passed": 132,
    "rules_failed": 18,
    "critical_issues": 2,
    "high_issues": 5,
    "frameworks_assessed": 3
  },
  "framework_scores": [
    {
      "name": "ISO27001",
      "score": 89.2,
      "passed": 45,
      "total": 50,
      "risk_level": "LOW"
    },
    {
      "name": "CIS",
      "score": 85.0,
      "passed": 42,
      "total": 50,
      "risk_level": "MEDIUM"
    },
    {
      "name": "RBI",
      "score": 88.5,
      "passed": 44,
      "total": 50,
      "risk_level": "LOW"
    }
  ],
  "category_breakdown": [
    {
      "framework": "ISO27001",
      "category": "Access Control",
      "compliance_pct": 92.0,
      "passed": 11,
      "total": 12
    }
  ],
  "severity_distribution": [
    {"severity": "CRITICAL", "count": 2},
    {"severity": "HIGH", "count": 5},
    {"severity": "MEDIUM", "count": 8},
    {"severity": "LOW", "count": 3}
  ],
  "priority_issues": [
    {
      "id": "ISO-A.9.1.2",
      "title": "Access to networks and network services",
      "category": "Access Control",
      "severity": "CRITICAL",
      "current_status": "false",
      "required_status": "true",
      "remediation": "Implement network access controls...",
      "priority": "P0"
    }
  ],
  "compliance_trend": [
    {"date": "2025-01-01", "score": 72.5},
    {"date": "2025-01-15", "score": 79.8},
    {"date": "2025-01-30", "score": 87.5}
  ],
  "remediation_summary": {
    "immediate_actions": 2,
    "short_term_actions": 5,
    "estimated_effort": "Medium (2-4 weeks)",
    "recommended_timeline": "30-60 days for critical items"
  },
  "download_links": {
    "pdf_report": "/api/reports/pdf/securemax",
    "excel_report": "/api/reports/excel/securemax",
    "charts_package": "/api/reports/charts/securemax"
  }
}
"""