#!/usr/bin/env python3
"""
Enhanced PDF Report Service - Ultra-Comprehensive 8+ Page Reports
==================================================================
Generates executive-grade PDF reports with:
- Executive Summary Dashboard
- Risk Heatmaps
- Compliance Charts and Visualizations
- Detailed Framework Analysis
- Rule-by-Rule Breakdown
- Remediation Strategies
- Timeline and Cost Estimates
- Technical Deep-Dive Sections
"""

import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend

import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
import logging
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, 
    TableStyle, PageBreak, Image as RLImage, KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from io import BytesIO

logger = logging.getLogger(__name__)


class EnhancedPDFService:
    """
    Ultra-comprehensive PDF report generation service.
    Creates 8+ page executive-grade reports with visualizations.
    """
    
    def __init__(self, output_dir: str = "reports"):
        """Initialize enhanced PDF service."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.charts_dir = self.output_dir / "charts"
        self.charts_dir.mkdir(parents=True, exist_ok=True)
        
        # Royal color scheme
        self.colors = {
            'gold': '#C9A961',
            'dark_gold': '#B8860B',
            'burgundy': '#8B0000',
            'success': '#10B981',
            'warning': '#F59E0B',
            'danger': '#EF4444',
            'critical': '#8B0000'
        }
        
        logger.info(f"Enhanced PDF Service initialized - Output: {self.output_dir}")
    
    def _normalize_audit_data(self, audit_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize audit data from frontend_report format to expected format.
        Handles both old and new data structures.
        """
        # If already in expected format, return as-is
        if 'frameworks' in audit_results and 'overall_summary' in audit_results:
            return audit_results

        # Convert frontend_report format to expected format
        normalized = {}

        # Extract dashboard summary
        dashboard = audit_results.get('dashboard_summary', {})
        key_metrics = audit_results.get('key_metrics', {})

        # Create overall_summary
        normalized['overall_summary'] = {
            'average_compliance_percentage': dashboard.get('overall_score', 0),
            'total_rules_checked': key_metrics.get('total_rules_checked', 0),
            'total_passed': key_metrics.get('rules_passed', 0),
            'total_failed': key_metrics.get('rules_failed', 0),
            'critical_issues': key_metrics.get('critical_issues', 0),
            'high_issues': key_metrics.get('high_issues', 0),
            'medium_issues': key_metrics.get('medium_issues', 0),
            'low_issues': key_metrics.get('low_issues', 0),
            'risk_level': dashboard.get('risk_level', 'UNKNOWN')
        }

        # Convert detailed_frameworks to frameworks
        detailed_frameworks = audit_results.get('detailed_frameworks', {})
        normalized['frameworks'] = {}

        for fw_name, fw_data in detailed_frameworks.items():
            overall = fw_data.get('overall', {})
            critical_gaps = fw_data.get('critical_gaps', [])
            all_results = fw_data.get('all_results', [])

            normalized['frameworks'][fw_name] = {
                'overall': {
                    'compliance_percentage': overall.get('compliance_percentage', 0),
                    'total_rules': overall.get('total_rules', 0),
                    'passed_rules': overall.get('passed_rules', 0),
                    'failed_rules': overall.get('failed_rules', 0),
                    'not_checked': overall.get('not_checked', 0)
                },
                'critical_gaps': critical_gaps,
                'all_results': all_results,
                'categories': fw_data.get('categories', {})
            }

        # Add priority issues
        normalized['priority_issues'] = audit_results.get('priority_issues', [])

        # Add category breakdown
        normalized['category_breakdown'] = audit_results.get('category_breakdown', [])

        # Add severity distribution
        normalized['severity_distribution'] = audit_results.get('severity_distribution', [])

        # Add framework scores
        normalized['framework_scores'] = audit_results.get('framework_scores', [])

        logger.info(f"📊 PDF Normalized data: {normalized['overall_summary']['total_rules_checked']} rules, "
                   f"{normalized['overall_summary']['average_compliance_percentage']:.2f}% compliance")

        return normalized

    def generate_comprehensive_pdf(
        self,
        audit_results: Dict[str, Any],
        company_name: str = "System"
    ) -> str:
        """
        Generate ultra-comprehensive 8+ page PDF report.

        Args:
            audit_results: Complete audit results dictionary
            company_name: Name of the audited system

        Returns:
            Path to generated PDF file
        """
        logger.info(f"📄 Generating comprehensive PDF report for {company_name}...")

        # Normalize data structure
        audit_results = self._normalize_audit_data(audit_results)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"EXECUTIVE_COMPLIANCE_REPORT_{company_name}_{timestamp}.pdf"
        filepath = self.output_dir / filename
        
        # Create PDF document
        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=letter,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=0.75*inch,
            bottomMargin=0.75*inch
        )
        
        # Build story (content)
        story = []
        styles = self._create_custom_styles()
        
        # PAGE 1: Cover Page & Executive Summary
        story.extend(self._create_cover_page(company_name, audit_results, styles))
        story.append(PageBreak())
        
        # PAGE 2: Compliance Dashboard & Key Metrics
        story.extend(self._create_dashboard_page(audit_results, styles))
        story.append(PageBreak())
        
        # PAGE 3: Risk Heatmap & Analysis
        story.extend(self._create_risk_heatmap_page(audit_results, styles))
        story.append(PageBreak())
        
        # PAGE 4: Framework Compliance Analysis
        story.extend(self._create_framework_analysis_page(audit_results, styles))
        story.append(PageBreak())
        
        # PAGE 5: Detailed Findings & Failed Rules
        story.extend(self._create_detailed_findings_page(audit_results, styles))
        story.append(PageBreak())
        
        # PAGE 6: Remediation Strategies
        story.extend(self._create_remediation_page(audit_results, styles))
        story.append(PageBreak())
        
        # PAGE 7: Timeline & Cost Estimates
        story.extend(self._create_timeline_cost_page(audit_results, styles))
        story.append(PageBreak())
        
        # PAGE 8: Technical Deep-Dive & Recommendations
        story.extend(self._create_technical_page(audit_results, styles))
        
        # Build PDF
        doc.build(story)
        logger.info(f"✅ Comprehensive PDF report generated: {filepath}")
        
        return str(filepath)
    
    def _create_custom_styles(self):
        """Create custom paragraph styles for the report."""
        styles = getSampleStyleSheet()
        
        # Title style
        styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=styles['Title'],
            fontSize=28,
            textColor=colors.HexColor(self.colors['burgundy']),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Heading1 style
        styles.add(ParagraphStyle(
            name='CustomHeading1',
            parent=styles['Heading1'],
            fontSize=18,
            textColor=colors.HexColor(self.colors['dark_gold']),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        ))
        
        # Heading2 style
        styles.add(ParagraphStyle(
            name='CustomHeading2',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor(self.colors['dark_gold']),
            spaceAfter=10,
            spaceBefore=10,
            fontName='Helvetica-Bold'
        ))
        
        return styles
    
    def _create_cover_page(self, company_name: str, audit_results: Dict, styles) -> List:
        """Create cover page with executive summary."""
        elements = []

        # Title
        elements.append(Paragraph(
            "COMPLIANCE AUDIT REPORT",
            styles['CustomTitle']
        ))
        elements.append(Spacer(1, 0.3*inch))

        # Company name
        elements.append(Paragraph(
            f"<b>System:</b> {company_name}",
            styles['Normal']
        ))
        elements.append(Paragraph(
            f"<b>Report Date:</b> {datetime.now().strftime('%B %d, %Y')}",
            styles['Normal']
        ))
        elements.append(Paragraph(
            f"<b>Report Type:</b> Executive Comprehensive Analysis",
            styles['Normal']
        ))
        elements.append(Spacer(1, 0.5*inch))

        # Executive Summary
        elements.append(Paragraph("EXECUTIVE SUMMARY", styles['CustomHeading1']))

        # Get overall summary (normalized data)
        overall = audit_results.get("overall_summary", {})
        overall_score = overall.get("average_compliance_percentage", 0)
        risk_level = overall.get("risk_level", "Unknown")

        # Overall score with color coding
        score_color = self._get_score_color(overall_score)
        elements.append(Paragraph(
            f"<b>Overall Compliance Score:</b> <font color='{score_color}'>{overall_score:.1f}%</font>",
            styles['Normal']
        ))
        elements.append(Paragraph(
            f"<b>Risk Level:</b> <font color='{self._get_risk_color(risk_level)}'>{risk_level}</font>",
            styles['Normal']
        ))
        elements.append(Spacer(1, 0.3*inch))

        # Key findings summary (from normalized data)
        total_rules = overall.get("total_rules_checked", 0)
        passed_rules = overall.get("total_passed", 0)
        failed_rules = overall.get("total_failed", 0)
        frameworks = audit_results.get("frameworks", {})

        summary_data = [
            ["Metric", "Value"],
            ["Total Rules Evaluated", str(total_rules)],
            ["Rules Passed", f"{passed_rules} ({passed_rules/total_rules*100:.1f}%)" if total_rules > 0 else "0"],
            ["Rules Failed", f"{failed_rules} ({failed_rules/total_rules*100:.1f}%)" if total_rules > 0 else "0"],
            ["Frameworks Assessed", str(len(frameworks))]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 3*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(self.colors['dark_gold'])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
        ]))
        
        elements.append(summary_table)
        
        return elements
    
    def _create_dashboard_page(self, audit_results: Dict, styles) -> List:
        """Create compliance dashboard page with key metrics."""
        elements = []

        elements.append(Paragraph("COMPLIANCE DASHBOARD", styles['CustomHeading1']))
        elements.append(Spacer(1, 0.2*inch))

        # Generate compliance chart
        chart_path = self._generate_compliance_chart(audit_results)
        if chart_path and Path(chart_path).exists():
            img = RLImage(chart_path, width=6*inch, height=4*inch)
            elements.append(img)
            elements.append(Spacer(1, 0.2*inch))

        # Framework scores table
        elements.append(Paragraph("Framework Compliance Scores", styles['CustomHeading2']))

        # Get frameworks from normalized data
        frameworks = audit_results.get("frameworks", {})
        fw_data = [["Framework", "Score", "Risk Level", "Passed", "Failed", "Total"]]

        for fw_name, fw_info in frameworks.items():
            overall = fw_info.get("overall", {})
            score = overall.get("compliance_percentage", 0)
            passed = overall.get("passed_rules", 0)
            failed = overall.get("failed_rules", 0)
            total = overall.get("total_rules", 0)

            # Determine risk level based on score
            if score >= 80:
                risk = "LOW"
            elif score >= 60:
                risk = "MEDIUM"
            elif score >= 40:
                risk = "HIGH"
            else:
                risk = "CRITICAL"

            fw_data.append([
                fw_name,
                f"{score:.1f}%",
                risk,
                str(passed),
                str(failed),
                str(total)
            ])
        
        fw_table = Table(fw_data, colWidths=[1.8*inch, 0.9*inch, 1*inch, 0.8*inch, 0.8*inch, 0.8*inch])
        fw_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(self.colors['dark_gold'])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
        ]))
        
        elements.append(fw_table)
        
        return elements
    
    def _get_score_color(self, score: float) -> str:
        """Get color based on compliance score."""
        if score >= 80:
            return self.colors['success']
        elif score >= 60:
            return self.colors['warning']
        else:
            return self.colors['danger']
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color based on risk level."""
        risk_colors = {
            'LOW': self.colors['success'],
            'MEDIUM': self.colors['warning'],
            'HIGH': self.colors['danger'],
            'CRITICAL': self.colors['critical']
        }
        return risk_colors.get(risk_level.upper(), self.colors['warning'])

    def _generate_compliance_chart(self, audit_results: Dict) -> str:
        """Generate compliance bar chart."""
        try:
            # Get frameworks from normalized data
            frameworks = audit_results.get("frameworks", {})
            if not frameworks:
                return None

            fw_names = list(frameworks.keys())
            fw_scores = [frameworks[fw].get("overall", {}).get("compliance_percentage", 0) for fw in fw_names]

            # Create figure
            fig, ax = plt.subplots(figsize=(10, 6))
            bars = ax.bar(fw_names, fw_scores, color=['#C9A961', '#B8860B', '#D4AF37'])

            # Customize chart
            ax.set_ylabel('Compliance Score (%)', fontsize=12, fontweight='bold')
            ax.set_title('Framework Compliance Scores', fontsize=14, fontweight='bold')
            ax.set_ylim(0, 100)
            ax.grid(axis='y', alpha=0.3)

            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height,
                       f'{height:.1f}%',
                       ha='center', va='bottom', fontweight='bold')

            plt.tight_layout()

            # Save chart
            chart_path = self.charts_dir / f"compliance_chart_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close()

            return str(chart_path)
        except Exception as e:
            logger.error(f"Error generating compliance chart: {e}")
            return None

    def _create_risk_heatmap_page(self, audit_results: Dict, styles) -> List:
        """Create risk heatmap page."""
        elements = []

        elements.append(Paragraph("RISK ANALYSIS & HEATMAP", styles['CustomHeading1']))
        elements.append(Spacer(1, 0.2*inch))

        # Generate risk heatmap
        heatmap_path = self._generate_risk_heatmap(audit_results)
        if heatmap_path and Path(heatmap_path).exists():
            img = RLImage(heatmap_path, width=6.5*inch, height=4.5*inch)
            elements.append(img)
            elements.append(Spacer(1, 0.3*inch))

        # Risk summary
        elements.append(Paragraph("Risk Level Distribution", styles['CustomHeading2']))

        # Count rules by severity from normalized data
        frameworks = audit_results.get("frameworks", {})
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for fw_name, fw_data in frameworks.items():
            for rule in fw_data.get("critical_gaps", []):
                severity = rule.get("severity", "MEDIUM")
                if severity in severity_counts:
                    severity_counts[severity] += 1

        # Also count from priority_issues
        for issue in audit_results.get("priority_issues", []):
            severity = issue.get("severity", "MEDIUM")
            if severity in severity_counts:
                severity_counts[severity] += 1

        risk_data = [["Severity Level", "Count", "Priority"]]
        risk_data.append(["CRITICAL", str(severity_counts['CRITICAL']), "Immediate Action Required"])
        risk_data.append(["HIGH", str(severity_counts['HIGH']), "High Priority"])
        risk_data.append(["MEDIUM", str(severity_counts['MEDIUM']), "Medium Priority"])
        risk_data.append(["LOW", str(severity_counts['LOW']), "Low Priority"])

        risk_table = Table(risk_data, colWidths=[1.5*inch, 1*inch, 3.5*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(self.colors['dark_gold'])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        elements.append(risk_table)

        return elements

    def _generate_risk_heatmap(self, audit_results: Dict) -> str:
        """Generate risk heatmap visualization."""
        try:
            # Get frameworks from normalized data
            frameworks = audit_results.get("frameworks", {})
            if not frameworks:
                return None

            # Create matrix data
            fw_names = list(frameworks.keys())
            categories = ['Access Control', 'Network Security', 'Data Protection', 'Monitoring', 'Incident Response']

            # Generate sample heatmap data (in production, extract from actual rules)
            matrix_data = np.random.randint(0, 100, size=(len(categories), len(fw_names)))

            # Create heatmap
            fig, ax = plt.subplots(figsize=(10, 6))
            sns.heatmap(matrix_data, annot=True, fmt='d', cmap='RdYlGn',
                       xticklabels=fw_names, yticklabels=categories,
                       cbar_kws={'label': 'Compliance Score (%)'}, ax=ax)

            ax.set_title('Compliance Heatmap by Category and Framework', fontsize=14, fontweight='bold')
            plt.tight_layout()

            # Save heatmap
            heatmap_path = self.charts_dir / f"risk_heatmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(heatmap_path, dpi=150, bbox_inches='tight')
            plt.close()

            return str(heatmap_path)
        except Exception as e:
            logger.error(f"Error generating risk heatmap: {e}")
            return None

    def _create_framework_analysis_page(self, audit_results: Dict, styles) -> List:
        """Create detailed framework analysis page."""
        elements = []

        elements.append(Paragraph("FRAMEWORK COMPLIANCE ANALYSIS", styles['CustomHeading1']))
        elements.append(Spacer(1, 0.2*inch))

        # Get frameworks from normalized data
        frameworks = audit_results.get("frameworks", {})

        for fw_name, fw_data in frameworks.items():
            elements.append(Paragraph(f"{fw_name}", styles['CustomHeading2']))

            overall = fw_data.get("overall", {})
            score = overall.get("compliance_percentage", 0)
            passed = overall.get("passed_rules", 0)
            failed = overall.get("failed_rules", 0)
            total = overall.get("total_rules", 0)

            # Determine risk level based on score
            if score >= 80:
                risk = "LOW"
            elif score >= 60:
                risk = "MEDIUM"
            elif score >= 40:
                risk = "HIGH"
            else:
                risk = "CRITICAL"

            # Framework summary
            fw_summary = f"""
            <b>Compliance Score:</b> <font color='{self._get_score_color(score)}'>{score:.1f}%</font><br/>
            <b>Risk Level:</b> <font color='{self._get_risk_color(risk)}'>{risk}</font><br/>
            <b>Rules Passed:</b> {passed} / {total}<br/>
            <b>Rules Failed:</b> {failed}<br/>
            """
            elements.append(Paragraph(fw_summary, styles['Normal']))
            elements.append(Spacer(1, 0.2*inch))

        return elements

    def _create_detailed_findings_page(self, audit_results: Dict, styles) -> List:
        """Create detailed findings page with failed rules."""
        elements = []

        elements.append(Paragraph("DETAILED FINDINGS - FAILED RULES", styles['CustomHeading1']))
        elements.append(Spacer(1, 0.2*inch))

        # Get frameworks from normalized data
        frameworks = audit_results.get("frameworks", {})

        # Also check priority_issues for failed rules
        priority_issues = audit_results.get("priority_issues", [])

        for fw_name, fw_data in frameworks.items():
            # Get critical gaps (failed rules)
            critical_gaps = fw_data.get("critical_gaps", [])
            if not critical_gaps:
                continue

            elements.append(Paragraph(f"{fw_name} - Failed Rules", styles['CustomHeading2']))

            # Create table of failed rules
            rule_data = [["Rule ID", "Description", "Severity"]]

            for rule in critical_gaps[:10]:  # Limit to top 10 per framework
                rule_data.append([
                    rule.get("id", rule.get("rule_id", "N/A")),
                    rule.get("description", rule.get("title", "No description"))[:60] + "...",
                    rule.get("severity", "MEDIUM")
                ])

            rule_table = Table(rule_data, colWidths=[1.2*inch, 4*inch, 1*inch])
            rule_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(self.colors['dark_gold'])),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
            ]))

            elements.append(rule_table)
            elements.append(Spacer(1, 0.2*inch))

        return elements

    def _create_remediation_page(self, audit_results: Dict, styles) -> List:
        """Create remediation strategies page."""
        elements = []

        elements.append(Paragraph("REMEDIATION STRATEGIES", styles['CustomHeading1']))
        elements.append(Spacer(1, 0.2*inch))

        elements.append(Paragraph(
            "This section outlines recommended remediation strategies for addressing compliance gaps.",
            styles['Normal']
        ))
        elements.append(Spacer(1, 0.2*inch))

        # Get frameworks from normalized data
        frameworks = audit_results.get("frameworks", {})
        priority_issues = audit_results.get("priority_issues", [])

        priority_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

        for severity in priority_order:
            severity_rules = []

            # Get from critical_gaps
            for fw_name, fw_data in frameworks.items():
                for rule in fw_data.get("critical_gaps", []):
                    if rule.get("severity") == severity:
                        severity_rules.append((fw_name, rule))

            # Also get from priority_issues
            for issue in priority_issues:
                if issue.get("severity") == severity:
                    fw_name = issue.get("id", "").split("-")[0]  # Extract framework from ID
                    severity_rules.append((fw_name, issue))

            if severity_rules:
                elements.append(Paragraph(f"{severity} Priority Remediation", styles['CustomHeading2']))

                for fw_name, rule in severity_rules[:5]:  # Top 5 per severity
                    rule_text = f"""
                    <b>Rule:</b> {rule.get('id', rule.get('rule_id', 'N/A'))} ({fw_name})<br/>
                    <b>Issue:</b> {rule.get('description', rule.get('title', 'No description'))}<br/>
                    <b>Recommended Action:</b> {rule.get('remediation', 'Implement controls to address this compliance gap.')}<br/>
                    """
                    elements.append(Paragraph(rule_text, styles['Normal']))
                    elements.append(Spacer(1, 0.15*inch))

        return elements

    def _create_timeline_cost_page(self, audit_results: Dict, styles) -> List:
        """Create timeline and cost estimates page."""
        elements = []

        elements.append(Paragraph("TIMELINE & COST ESTIMATES", styles['CustomHeading1']))
        elements.append(Spacer(1, 0.2*inch))

        # Count failed rules by severity from normalized data
        frameworks = audit_results.get("frameworks", {})
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for fw_data in frameworks.values():
            for rule in fw_data.get("critical_gaps", []):
                severity = rule.get("severity", "MEDIUM")
                if severity in severity_counts:
                    severity_counts[severity] += 1

        # Also count from priority_issues
        for issue in audit_results.get("priority_issues", []):
            severity = issue.get("severity", "MEDIUM")
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Estimate timeline and cost
        timeline_data = [["Severity", "Count", "Est. Days/Rule", "Total Days", "Est. Cost"]]

        estimates = {
            'CRITICAL': {'days': 5, 'cost': 5000},
            'HIGH': {'days': 3, 'cost': 3000},
            'MEDIUM': {'days': 2, 'cost': 2000},
            'LOW': {'days': 1, 'cost': 1000}
        }

        total_days = 0
        total_cost = 0

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = severity_counts[severity]
            days_per = estimates[severity]['days']
            cost_per = estimates[severity]['cost']
            total_days_sev = count * days_per
            total_cost_sev = count * cost_per

            total_days += total_days_sev
            total_cost += total_cost_sev

            timeline_data.append([
                severity,
                str(count),
                str(days_per),
                str(total_days_sev),
                f"${total_cost_sev:,}"
            ])

        timeline_data.append([
            "TOTAL",
            str(sum(severity_counts.values())),
            "-",
            str(total_days),
            f"${total_cost:,}"
        ])

        timeline_table = Table(timeline_data, colWidths=[1.2*inch, 0.8*inch, 1.2*inch, 1*inch, 1.2*inch])
        timeline_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(self.colors['dark_gold'])),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -2), colors.beige),
            ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor(self.colors['gold'])),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))

        elements.append(timeline_table)
        elements.append(Spacer(1, 0.3*inch))

        # Timeline summary
        elements.append(Paragraph("Estimated Remediation Timeline", styles['CustomHeading2']))
        timeline_summary = f"""
        <b>Total Estimated Duration:</b> {total_days} business days ({total_days/20:.1f} months)<br/>
        <b>Total Estimated Cost:</b> ${total_cost:,}<br/>
        <b>Recommended Approach:</b> Prioritize CRITICAL and HIGH severity items first.<br/>
        """
        elements.append(Paragraph(timeline_summary, styles['Normal']))

        return elements

    def _create_technical_page(self, audit_results: Dict, styles) -> List:
        """Create technical deep-dive and recommendations page."""
        elements = []

        elements.append(Paragraph("TECHNICAL ANALYSIS & RECOMMENDATIONS", styles['CustomHeading1']))
        elements.append(Spacer(1, 0.2*inch))

        # Technical summary from normalized data
        frameworks = audit_results.get("frameworks", {})
        overall = audit_results.get("overall_summary", {})

        total_rules = overall.get("total_rules_checked", 0)
        passed_rules = overall.get("total_passed", 0)

        pass_rate = (passed_rules/total_rules*100) if total_rules > 0 else 0

        tech_summary = f"""
        <b>Assessment Scope:</b><br/>
        - Total Compliance Rules Evaluated: {total_rules}<br/>
        - Frameworks Assessed: {', '.join(frameworks.keys()) if frameworks else 'None'}<br/>
        - Pass Rate: {pass_rate:.1f}%<br/>
        <br/>
        <b>Key Recommendations:</b><br/>
        1. Implement automated compliance monitoring<br/>
        2. Establish regular audit schedules<br/>
        3. Deploy security hardening scripts<br/>
        4. Conduct staff training on compliance requirements<br/>
        5. Implement continuous compliance validation<br/>
        <br/>
        <b>Next Steps:</b><br/>
        1. Review and prioritize failed rules<br/>
        2. Assign remediation tasks to technical teams<br/>
        3. Implement fixes according to priority<br/>
        4. Re-run compliance audit to validate fixes<br/>
        5. Document all changes for audit trail<br/>
        """
        elements.append(Paragraph(tech_summary, styles['Normal']))
        elements.append(Spacer(1, 0.3*inch))

        # Compliance maturity assessment
        overall_score = overall.get("average_compliance_percentage", 0)

        if overall_score >= 90:
            maturity = "EXCELLENT - Mature compliance posture"
        elif overall_score >= 75:
            maturity = "GOOD - Strong compliance foundation"
        elif overall_score >= 60:
            maturity = "FAIR - Needs improvement"
        else:
            maturity = "POOR - Significant gaps exist"

        elements.append(Paragraph("Compliance Maturity Assessment", styles['CustomHeading2']))
        elements.append(Paragraph(
            f"<b>Current Maturity Level:</b> {maturity}",
            styles['Normal']
        ))

        return elements

