#!/usr/bin/env python3
"""
Enhanced Professional Compliance Audit Engine
Supports CIS, ISO27001, and RBI frameworks with comprehensive reporting
"""

import os
import json

import argparse
import logging
from datetime import datetime, timedelta
from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.patches import Rectangle
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.offline as pyo
from reportlab.lib.pagesizes import landscape, A4, letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('compliance_audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class EnhancedComplianceAuditor:
    """Enhanced Professional Compliance Audit Engine"""
    
    def __init__(self, config_dir="config", output_dir="compliance_output", historical_dir="historical_data"):
        self.config_dir = Path(config_dir)
        self.output_dir = Path(output_dir)
        self.historical_dir = Path(historical_dir)
        self.charts_dir = self.output_dir / "charts"
        self.scripts_dir = self.output_dir / "remediation_scripts"
        
        # Create directories
        for dir_path in [self.config_dir, self.output_dir, self.historical_dir, self.charts_dir, self.scripts_dir]:
            dir_path.mkdir(exist_ok=True)
        
        self.rules = {}
        self.companies = {}
        self.results = {}
        self.risk_levels = {
            'CRITICAL': {'min_weight': 90, 'color': '#8B0000', 'range': (0, 25)},
            'HIGH': {'min_weight': 70, 'color': '#FF4444', 'range': (25, 50)},
            'MEDIUM': {'min_weight': 50, 'color': '#FFA500', 'range': (50, 75)},
            'LOW': {'min_weight': 30, 'color': '#FFD700', 'range': (75, 85)},
            'EXCELLENT': {'min_weight': 10, 'color': '#4CAF50', 'range': (85, 100)}
        }
        
        # Enhanced remediation templates
        self.remediation_scripts = {
            'linux': {
                'firewall_enable': '''#!/bin/bash
# Enable and configure UFW firewall
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw --force enable
sudo ufw status verbose''',
                
                'patch_management': '''#!/bin/bash
# Automated patch management setup
sudo apt update
sudo apt install -y unattended-upgrades
echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
sudo systemctl enable unattended-upgrades
sudo systemctl start unattended-upgrades''',
                
                'secure_ssh': '''#!/bin/bash
# Secure SSH configuration
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo systemctl restart sshd''',
                
                'log_management': '''#!/bin/bash
# Setup centralized logging
sudo apt install -y rsyslog
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
echo "*.* @@logserver:514" >> /etc/rsyslog.conf
sudo systemctl restart rsyslog''',
                
                'vulnerability_scan': '''#!/bin/bash
# Install and run vulnerability scanner
sudo apt update
sudo apt install -y lynis
sudo lynis audit system
sudo lynis show report''',
                
                'antivirus_setup': '''#!/bin/bash
# Install and configure ClamAV
sudo apt update
sudo apt install -y clamav clamav-daemon
sudo freshclam
sudo systemctl enable clamav-freshclam
sudo systemctl start clamav-freshclam''',
                
                'backup_setup': '''#!/bin/bash
# Setup automated backup
sudo apt install -y rsync
mkdir -p /backup
echo "0 2 * * * rsync -av --delete /important-data/ /backup/" | sudo crontab -
sudo service cron restart'''
            }
        }
    
    def load_frameworks(self):
        """Load compliance frameworks from JSON files"""
        framework_files = {
            'CIS': 'cis_controls.json',
            'ISO27001': 'iso27001_controls.json',
            'RBI': 'rbi_guidelines.json'
        }
        
        for framework, filename in framework_files.items():
            file_path = self.config_dir / filename
            if file_path.exists():
                with open(file_path, 'r') as f:
                    self.rules[framework] = json.load(f)
                logger.info(f"Loaded {len(self.rules[framework])} rules for {framework}")
            else:
                logger.error(f"Framework file not found: {file_path}")
    
    def load_companies(self, company_files=None):
        """Load company configurations"""
        if company_files is None:
            company_files = list(self.config_dir.glob("company_*.json"))
        
        for file_path in company_files:
            if isinstance(file_path, str):
                file_path = Path(file_path)
            
            company_name = file_path.stem.replace('company_', '')
            with open(file_path, 'r') as f:
                self.companies[company_name] = json.load(f)
            logger.info(f"Loaded configuration for company: {company_name}")
    
    def get_field_value(self, data, field_path):
        """Safely extract nested field values"""
        parts = field_path.split(".")
        value = data
        try:
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part, None)
                elif isinstance(value, list) and part.isdigit():
                    value = value[int(part)] if int(part) < len(value) else None
                else:
                    return None
            return value
        except Exception as e:
            logger.debug(f"Error accessing field {field_path}: {e}")
            return None
    
    def get_enhanced_remediation(self, rule, status):
        """Get enhanced remediation guidance with scripts"""
        base_remediation = rule.get('remediation', 'No remediation provided')
        
        remediation_data = {
            'description': base_remediation,
            'impact': self._get_impact_description(rule),
            'priority': self._get_priority_level(rule),
            'effort': self._get_effort_estimate(rule),
            'scripts': [],
            'references': rule.get('references', []),
            'business_justification': self._get_business_justification(rule)
        }
        
        # Add relevant scripts
        rule_id = rule.get('id', '').lower()
        if 'firewall' in rule_id or 'network' in rule_id:
            remediation_data['scripts'].append({
                'type': 'linux',
                'name': 'firewall_enable.sh',
                'content': self.remediation_scripts['linux']['firewall_enable']
            })
        elif 'patch' in rule_id or 'update' in rule_id:
            remediation_data['scripts'].append({
                'type': 'linux',
                'name': 'patch_management.sh',
                'content': self.remediation_scripts['linux']['patch_management']
            })
        elif 'ssh' in rule_id or 'remote' in rule_id:
            remediation_data['scripts'].append({
                'type': 'linux',
                'name': 'secure_ssh.sh',
                'content': self.remediation_scripts['linux']['secure_ssh']
            })
        elif 'log' in rule_id or 'audit' in rule_id:
            remediation_data['scripts'].append({
                'type': 'linux',
                'name': 'log_management.sh',
                'content': self.remediation_scripts['linux']['log_management']
            })
        elif 'vulnerability' in rule_id or 'scan' in rule_id:
            remediation_data['scripts'].append({
                'type': 'linux',
                'name': 'vulnerability_scan.sh',
                'content': self.remediation_scripts['linux']['vulnerability_scan']
            })
        elif 'antivirus' in rule_id or 'malware' in rule_id:
            remediation_data['scripts'].append({
                'type': 'linux',
                'name': 'antivirus_setup.sh',
                'content': self.remediation_scripts['linux']['antivirus_setup']
            })
        elif 'backup' in rule_id:
            remediation_data['scripts'].append({
                'type': 'linux',
                'name': 'backup_setup.sh',
                'content': self.remediation_scripts['linux']['backup_setup']
            })
        
        return remediation_data
    
    def _get_impact_description(self, rule):
        """Get impact description based on rule severity"""
        severity = rule.get('severity', 'MEDIUM')
        category = rule.get('category', 'General')
        
        impact_map = {
            'CRITICAL': f"Critical security vulnerability in {category}. Immediate exploitation risk with potential for complete system compromise.",
            'HIGH': f"High-risk security gap in {category}. Significant potential for unauthorized access or data breach.",
            'MEDIUM': f"Moderate security concern in {category}. May lead to information disclosure or limited system access.",
            'LOW': f"Low-impact security issue in {category}. Minimal risk but should be addressed for best practices."
        }
        
        return impact_map.get(severity, "Unknown impact level")
    
    def _get_priority_level(self, rule):
        """Get priority level for remediation"""
        severity = rule.get('severity', 'MEDIUM')
        weight = rule.get('weight', 1)
        
        if severity == 'CRITICAL' or weight >= 9:
            return 'P0 - Critical (Fix immediately)'
        elif severity == 'HIGH' or weight >= 7:
            return 'P1 - High (Fix within 24 hours)'
        elif severity == 'MEDIUM' or weight >= 5:
            return 'P2 - Medium (Fix within 1 week)'
        else:
            return 'P3 - Low (Fix within 1 month)'
    
    def _get_effort_estimate(self, rule):
        """Get effort estimate for remediation"""
        category = rule.get('category', 'General')
        
        effort_map = {
            'Access Control': 'Medium (4-8 hours)',
            'Asset Management': 'High (1-2 days)',
            'Configuration Management': 'Low (1-2 hours)',
            'Network Security': 'Medium (4-8 hours)',
            'Logging and Monitoring': 'High (1-2 days)',
            'Vulnerability Management': 'Medium (2-4 hours)',
            'Incident Response': 'High (2-3 days)',
            'Business Continuity': 'Very High (1-2 weeks)'
        }
        
        return effort_map.get(category, 'Medium (4-8 hours)')
    
    def _get_business_justification(self, rule):
        """Get business justification for remediation"""
        category = rule.get('category', 'General')
        severity = rule.get('severity', 'MEDIUM')
        
        justifications = {
            'Access Control': 'Prevents unauthorized access to sensitive systems and data, reducing risk of data breaches and regulatory penalties.',
            'Asset Management': 'Ensures visibility and control over all organizational assets, critical for security monitoring and compliance.',
            'Network Security': 'Protects against network-based attacks and unauthorized access, maintaining business operations integrity.',
            'Logging and Monitoring': 'Enables detection of security incidents and provides audit trail for compliance requirements.',
            'Vulnerability Management': 'Reduces attack surface and prevents exploitation of known vulnerabilities.',
            'Configuration Management': 'Ensures systems are securely configured according to best practices and compliance requirements.'
        }
        
        base_justification = justifications.get(category, 'Improves overall security posture and compliance standing.')
        
        if severity in ['CRITICAL', 'HIGH']:
            return f"{base_justification} High priority due to significant risk exposure."
        else:
            return base_justification
    
    def evaluate_rule(self, rule, data):
        """Evaluate a single compliance rule with enhanced details"""
        field = rule["field"]
        operator = rule["operator"]
        expected = rule["expected_value"]
        weight = rule.get("weight", 1)
        severity = rule.get("severity", "MEDIUM")
        
        actual = self.get_field_value(data, field)
        
        if actual is None:
            remediation = self.get_enhanced_remediation(rule, 'MISSING_DATA')
            return {
                'score': 0,
                'status': 'MISSING_DATA',
                'message': f"Missing field: {field}",
                'severity': severity,
                'weight': weight,
                'remediation': remediation,
                'field': field,
                'expected_value': expected,
                'actual_value': 'N/A'
            }
        
        try:
            passed = self._evaluate_condition(actual, operator, expected)
            status = 'PASS' if passed else 'FAIL'
            remediation = self.get_enhanced_remediation(rule, status)
            
            return {
                'score': weight if passed else 0,
                'status': status,
                'message': f"Expected {operator} {expected}, got {actual}" if not passed else "Compliant",
                'severity': severity,
                'weight': weight,
                'actual_value': actual,
                'expected_value': expected,
                'remediation': remediation,
                'field': field
            }
        except Exception as e:
            remediation = self.get_enhanced_remediation(rule, 'ERROR')
            return {
                'score': 0,
                'status': 'ERROR',
                'message': f"Evaluation error: {str(e)}",
                'severity': severity,
                'weight': weight,
                'remediation': remediation,
                'field': field,
                'expected_value': expected,
                'actual_value': str(actual)
            }
    
    def _evaluate_condition(self, actual, operator, expected):
        """Evaluate different types of conditions"""
        if operator == "==":
            return actual == expected
        elif operator == "!=":
            return actual != expected
        elif operator == ">=":
            return float(actual) >= float(expected)
        elif operator == "<=":
            return float(actual) <= float(expected)
        elif operator == ">":
            return float(actual) > float(expected)
        elif operator == "<":
            return float(actual) < float(expected)
        elif operator == "contains":
            return expected in actual if isinstance(actual, (list, str)) else False
        elif operator == "not_contains":
            return expected not in actual if isinstance(actual, (list, str)) else True
        elif operator == "in":
            return actual in expected if isinstance(expected, list) else False
        elif operator == "not_in":
            return actual not in expected if isinstance(expected, list) else True
        elif operator == "regex":
            import re
            return bool(re.match(expected, str(actual)))
        else:
            raise ValueError(f"Unsupported operator: {operator}")
    
    def evaluate_company(self, company_name, company_data):
        """Evaluate all rules for a company with enhanced metrics"""
        company_results = {}
        
        for framework, rules in self.rules.items():
            framework_results = {
                'total_rules': len(rules),
                'passed_rules': 0,
                'failed_rules': 0,
                'missing_data_rules': 0,
                'error_rules': 0,
                'total_weight': 0,
                'achieved_weight': 0,
                'compliance_percentage': 0,
                'risk_level': 'CRITICAL',
                'rule_details': [],
                'category_breakdown': {},
                'severity_breakdown': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
            }
            
            for rule in rules:
                result = self.evaluate_rule(rule, company_data)
                result.update({
                    'rule_id': rule['id'],
                    'description': rule['description'],
                    'category': rule.get('category', 'General')
                })
                
                framework_results['rule_details'].append(result)
                framework_results['total_weight'] += result['weight']
                framework_results['achieved_weight'] += result['score']
                
                # Count by status
                if result['status'] == 'PASS':
                    framework_results['passed_rules'] += 1
                elif result['status'] == 'FAIL':
                    framework_results['failed_rules'] += 1
                elif result['status'] == 'MISSING_DATA':
                    framework_results['missing_data_rules'] += 1
                elif result['status'] == 'ERROR':
                    framework_results['error_rules'] += 1
                
                # Category breakdown
                category = result['category']
                if category not in framework_results['category_breakdown']:
                    framework_results['category_breakdown'][category] = {
                        'total': 0, 'passed': 0, 'failed': 0, 'compliance_pct': 0
                    }
                
                framework_results['category_breakdown'][category]['total'] += 1
                if result['status'] == 'PASS':
                    framework_results['category_breakdown'][category]['passed'] += 1
                else:
                    framework_results['category_breakdown'][category]['failed'] += 1
                
                # Severity breakdown
                severity = result['severity']
                if severity in framework_results['severity_breakdown']:
                    framework_results['severity_breakdown'][severity] += 1
            
            # Calculate category compliance percentages
            for category, stats in framework_results['category_breakdown'].items():
                if stats['total'] > 0:
                    stats['compliance_pct'] = round((stats['passed'] / stats['total']) * 100, 2)
            
            # Calculate compliance percentage
            if framework_results['total_weight'] > 0:
                framework_results['compliance_percentage'] = round(
                    (framework_results['achieved_weight'] / framework_results['total_weight']) * 100, 2
                )
            
            # Determine risk level
            framework_results['risk_level'] = self._calculate_risk_level(
                framework_results['compliance_percentage']
            )
            
            company_results[framework] = framework_results
        
        # Calculate overall metrics
        overall_compliance = np.mean([
            fw['compliance_percentage'] for fw in company_results.values()
        ])
        
        company_results['overall'] = {
            'compliance_percentage': round(overall_compliance, 2),
            'risk_level': self._calculate_risk_level(overall_compliance),
            'evaluation_date': datetime.now().isoformat(),
            'total_critical_issues': sum(fw['severity_breakdown'].get('CRITICAL', 0) for fw in company_results.values()),
            'total_high_issues': sum(fw['severity_breakdown'].get('HIGH', 0) for fw in company_results.values()),
            'frameworks_count': len(company_results),
            'average_framework_compliance': round(overall_compliance, 2)
        }
        
        return company_results
    
    def _calculate_risk_level(self, compliance_percentage):
        """Calculate enhanced risk level based on compliance percentage"""
        for level, config in self.risk_levels.items():
            min_comp, max_comp = config['range']
            if min_comp <= compliance_percentage <= max_comp:
                return level
        return 'CRITICAL'
    
    def generate_enhanced_visualizations(self):
        """Generate comprehensive visualizations using both matplotlib and plotly"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 1. Enhanced Compliance Heatmap
        self._generate_enhanced_heatmap(timestamp)
        
        # 2. Risk Level Distribution
        self._generate_risk_distribution(timestamp)
        
        # 3. Category-wise Compliance Analysis
        self._generate_category_analysis(timestamp)
        
        # 4. Severity Breakdown
        self._generate_severity_breakdown(timestamp)
        
        # 5. Company Comparison Radar Chart
        self._generate_radar_comparison(timestamp)
        
        # 6. Trend Analysis (Enhanced)
        self._generate_enhanced_trends(timestamp)
        
        # 7. Interactive Dashboard
        self._generate_interactive_dashboard(timestamp)
        
        # 8. Framework Performance Matrix
        self._generate_framework_matrix(timestamp)
    
    def _generate_enhanced_heatmap(self, timestamp):
        """Generate enhanced compliance heatmap with annotations"""
        frameworks = list(self.rules.keys())
        companies = list(self.companies.keys())
        
        # Create heatmap data
        heatmap_data = np.zeros((len(frameworks), len(companies)))
        annotations = []
        
        for i, framework in enumerate(frameworks):
            for j, company in enumerate(companies):
                compliance_pct = self.results[company][framework]['compliance_percentage']
                heatmap_data[i, j] = compliance_pct
                
                # Color coding based on risk level
                risk_level = self.results[company][framework]['risk_level']
                risk_color = self.risk_levels[risk_level]['color']
                
                annotations.append({
                    'text': f"{compliance_pct:.1f}%\n{risk_level}",
                    'x': j, 'y': i,
                    'color': 'white' if compliance_pct < 50 else 'black'
                })
        
        # Create enhanced heatmap
        fig, ax = plt.subplots(figsize=(14, 10))
        
        # Custom colormap
        colors_list = ['#8B0000', '#FF4444', '#FFA500', '#FFD700', '#4CAF50']
        n_bins = 100
        cmap = plt.cm.colors.LinearSegmentedColormap.from_list('custom', colors_list, N=n_bins)
        
        im = ax.imshow(heatmap_data, cmap=cmap, aspect='auto', vmin=0, vmax=100)
        
        # Add annotations
        for ann in annotations:
            ax.text(ann['x'], ann['y'], ann['text'], 
                   ha='center', va='center', color=ann['color'], 
                   fontsize=10, fontweight='bold')
        
        # Customize axes
        ax.set_xticks(range(len(companies)))
        ax.set_yticks(range(len(frameworks)))
        ax.set_xticklabels(companies, rotation=45, ha='right')
        ax.set_yticklabels(frameworks)
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax)
        cbar.set_label('Compliance Percentage (%)', rotation=270, labelpad=20)
        
        # Add title and labels
        plt.title('Enhanced Compliance Heatmap\nFramework vs Company Performance', 
                 fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('Companies', fontsize=12, fontweight='bold')
        plt.ylabel('Compliance Frameworks', fontsize=12, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(self.charts_dir / f"enhanced_heatmap_{timestamp}.png", 
                   dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
    
    def _generate_risk_distribution(self, timestamp):
        """Generate risk level distribution charts"""
        # Collect risk data
        risk_data = []
        for company, frameworks in self.results.items():
            for framework, metrics in frameworks.items():
                if framework != 'overall':
                    risk_data.append({
                        'company': company,
                        'framework': framework,
                        'risk_level': metrics['risk_level'],
                        'compliance_pct': metrics['compliance_percentage']
                    })
        
        df_risk = pd.DataFrame(risk_data)
        
        # Create subplot
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        
        # 1. Risk Level Distribution (Overall)
        risk_counts = df_risk['risk_level'].value_counts()
        colors = [self.risk_levels[level]['color'] for level in risk_counts.index]
        
        wedges, texts, autotexts = ax1.pie(risk_counts.values, labels=risk_counts.index, 
                                          autopct='%1.1f%%', colors=colors, startangle=90)
        ax1.set_title('Overall Risk Distribution', fontsize=14, fontweight='bold')
        
        # 2. Company Risk Profile
        company_risk = df_risk.groupby(['company', 'risk_level']).size().unstack(fill_value=0)
        company_risk.plot(kind='bar', ax=ax2, color=[self.risk_levels[col]['color'] for col in company_risk.columns])
        ax2.set_title('Risk Profile by Company', fontsize=14, fontweight='bold')
        ax2.set_xlabel('Companies')
        ax2.set_ylabel('Number of Frameworks')
        ax2.legend(title='Risk Level')
        plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        # 3. Framework Risk Profile
        framework_risk = df_risk.groupby(['framework', 'risk_level']).size().unstack(fill_value=0)
        framework_risk.plot(kind='bar', ax=ax3, color=[self.risk_levels[col]['color'] for col in framework_risk.columns])
        ax3.set_title('Risk Profile by Framework', fontsize=14, fontweight='bold')
        ax3.set_xlabel('Frameworks')
        ax3.set_ylabel('Number of Companies')
        ax3.legend(title='Risk Level')
        plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        # 4. Compliance Distribution
        ax4.hist(df_risk['compliance_pct'], bins=20, alpha=0.7, color='skyblue', edgecolor='black')
        ax4.axvline(df_risk['compliance_pct'].mean(), color='red', linestyle='--', 
                   label=f'Average: {df_risk["compliance_pct"].mean():.1f}%')
        ax4.set_title('Compliance Score Distribution', fontsize=14, fontweight='bold')
        ax4.set_xlabel('Compliance Percentage (%)')
        ax4.set_ylabel('Frequency')
        ax4.legend()
        
        plt.tight_layout()
        plt.savefig(self.charts_dir / f"risk_distribution_{timestamp}.png", 
                   dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
    
    def _generate_category_analysis(self, timestamp):
        """Generate detailed category-wise analysis"""
        # Collect category data
        category_data = []
        for company, frameworks in self.results.items():
            for framework, metrics in frameworks.items():
                if framework != 'overall':
                    for category, stats in metrics['category_breakdown'].items():
                        category_data.append({
                            'company': company,
                            'framework': framework,
                            'category': category,
                            'total': stats['total'],
                            'passed': stats['passed'],
                            'failed': stats['failed'],
                            'compliance_pct': stats['compliance_pct']
                        })
        
        if not category_data:
            return
        
        df_cat = pd.DataFrame(category_data)
        
        # Create category analysis chart
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(18, 14))
        
        # 1. Category Performance Heatmap
        cat_pivot = df_cat.pivot_table(values='compliance_pct', 
                                      index='category', 
                                      columns='company', 
                                      aggfunc='mean', 
                                      fill_value=0)
        
        sns.heatmap(cat_pivot, annot=True, fmt='.1f', cmap='RdYlGn', 
                   ax=ax1, cbar_kws={'label': 'Compliance %'})
        ax1.set_title('Category Performance by Company', fontsize=14, fontweight='bold')
        
        # 2. Average Category Performance
        avg_cat = df_cat.groupby('category')['compliance_pct'].mean().sort_values(ascending=True)
        bars = ax2.barh(range(len(avg_cat)), avg_cat.values)
        ax2.set_yticks(range(len(avg_cat)))
        ax2.set_yticklabels(avg_cat.index)
        ax2.set_xlabel('Average Compliance Percentage (%)')
        ax2.set_title('Average Performance by Category', fontsize=14, fontweight='bold')
        
        # Color bars based on performance
        for i, (bar, val) in enumerate(zip(bars, avg_cat.values)):
            if val >= 85:
                bar.set_color('#4CAF50')
            elif val >= 65:
                bar.set_color('#FFA500')
            else:
                bar.set_color('#FF4444')
            
            # Add value labels
            ax2.text(val + 1, i, f'{val:.1f}%', va='center')
        
        # 3. Category Rule Distribution
        cat_rules = df_cat.groupby('category')[['total', 'passed', 'failed']].sum()
        cat_rules.plot(kind='bar', ax=ax3, color=['lightblue', 'green', 'red'])
        ax3.set_title('Rule Distribution by Category', fontsize=14, fontweight='bold')
        ax3.set_xlabel('Categories')
        ax3.set_ylabel('Number of Rules')
        ax3.legend(['Total Rules', 'Passed Rules', 'Failed Rules'])
        plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        # 4. Framework vs Category Performance
        fw_cat_pivot = df_cat.pivot_table(values='compliance_pct', 
                                         index='framework', 
                                         columns='category', 
                                         aggfunc='mean', 
                                         fill_value=0)
        
        sns.heatmap(fw_cat_pivot, annot=True, fmt='.1f', cmap='RdYlGn', 
                   ax=ax4, cbar_kws={'label': 'Compliance %'})
        ax4.set_title('Framework vs Category Performance', fontsize=14, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(self.charts_dir / f"category_analysis_{timestamp}.png", 
                   dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
    
    def _generate_severity_breakdown(self, timestamp):
        """Generate severity-based breakdown analysis"""
        # Collect severity data
        severity_data = []
        for company, frameworks in self.results.items():
            for framework, metrics in frameworks.items():
                if framework != 'overall':
                    for severity, count in metrics['severity_breakdown'].items():
                        if count > 0:
                            severity_data.append({
                                'company': company,
                                'framework': framework,
                                'severity': severity,
                                'count': count
                            })
        
        if not severity_data:
            return
        
        df_sev = pd.DataFrame(severity_data)
        
        # Create severity analysis
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        
        # 1. Severity Distribution by Company
        sev_company = df_sev.groupby(['company', 'severity'])['count'].sum().unstack(fill_value=0)
        sev_company.plot(kind='bar', ax=ax1, stacked=True, 
                        color=['#8B0000', '#FF4444', '#FFA500', '#FFD700'])
        ax1.set_title('Severity Distribution by Company', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Companies')
        ax1.set_ylabel('Number of Issues')
        ax1.legend(title='Severity Level')
        plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        # 2. Severity Distribution by Framework
        sev_framework = df_sev.groupby(['framework', 'severity'])['count'].sum().unstack(fill_value=0)
        sev_framework.plot(kind='bar', ax=ax2, 
                          color=['#8B0000', '#FF4444', '#FFA500', '#FFD700'])
        ax2.set_title('Severity Distribution by Framework', fontsize=14, fontweight='bold')
        ax2.set_xlabel('Frameworks')
        ax2.set_ylabel('Number of Issues')
        ax2.legend(title='Severity Level')
        plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45, ha='right')
        
        # 3. Critical Issues Focus
        critical_data = df_sev[df_sev['severity'].isin(['CRITICAL', 'HIGH'])]
        if not critical_data.empty:
            critical_pivot = critical_data.pivot_table(values='count', 
                                                      index='company', 
                                                      columns='framework', 
                                                      aggfunc='sum', 
                                                      fill_value=0)
            
            sns.heatmap(critical_pivot, annot=True, fmt='d', cmap='Reds', 
                       ax=ax3, cbar_kws={'label': 'Critical/High Issues'})
            ax3.set_title('Critical & High Severity Issues Heatmap', fontsize=14, fontweight='bold')
        
        # 4. Overall Severity Summary
        total_severity = df_sev.groupby('severity')['count'].sum().sort_values(ascending=False)
        colors = ['#8B0000', '#FF4444', '#FFA500', '#FFD700']
        severity_colors = {sev: colors[i] for i, sev in enumerate(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])}
        bar_colors = [severity_colors.get(sev, 'gray') for sev in total_severity.index]
        
        bars = ax4.bar(total_severity.index, total_severity.values, color=bar_colors)
        ax4.set_title('Overall Severity Distribution', fontsize=14, fontweight='bold')
        ax4.set_xlabel('Severity Level')
        ax4.set_ylabel('Total Issues')
        
        # Add value labels on bars
        for bar, val in zip(bars, total_severity.values):
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(val)}', ha='center', va='bottom', fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(self.charts_dir / f"severity_breakdown_{timestamp}.png", 
                   dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
    
    def _generate_radar_comparison(self, timestamp):
        """Generate radar chart for company comparison"""
        frameworks = list(self.rules.keys())
        companies = list(self.companies.keys())
        
        # Set up the radar chart
        fig, ax = plt.subplots(figsize=(12, 12), subplot_kw=dict(projection='polar'))
        
        # Number of variables
        N = len(frameworks)
        
        # Angle for each axis
        angles = [n / float(N) * 2 * np.pi for n in range(N)]
        angles += angles[:1]  # Complete the circle
        
        # Colors for each company
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD']
        
        # Plot data for each company
        for i, company in enumerate(companies):
            values = []
            for framework in frameworks:
                compliance_pct = self.results[company][framework]['compliance_percentage']
                values.append(compliance_pct)
            
            values += values[:1]  # Complete the circle
            
            ax.plot(angles, values, 'o-', linewidth=2, 
                   label=company, color=colors[i % len(colors)])
            ax.fill(angles, values, alpha=0.25, color=colors[i % len(colors)])
        
        # Add labels
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(frameworks, fontsize=12)
        ax.set_ylim(0, 100)
        ax.set_yticks([20, 40, 60, 80, 100])
        ax.set_yticklabels(['20%', '40%', '60%', '80%', '100%'])
        ax.grid(True)
        
        # Add title and legend
        plt.title('Company Compliance Comparison\nRadar Chart', size=16, fontweight='bold', pad=30)
        plt.legend(loc='upper right', bbox_to_anchor=(1.2, 1.0))
        
        plt.tight_layout()
        plt.savefig(self.charts_dir / f"radar_comparison_{timestamp}.png", 
                   dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
    
    def _generate_enhanced_trends(self, timestamp):
        """Generate enhanced trend analysis with better visualization"""
        historical_files = list(self.historical_dir.glob("audit_*.json"))
        
        if len(historical_files) < 2:
            logger.info("Insufficient historical data for trend analysis")
            return
        
        trend_data = []
        
        for file_path in sorted(historical_files):
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Support both new (metadata.timestamp) and legacy (top-level timestamp) formats
            timestamp_str = data.get('timestamp') or data.get('metadata', {}).get('timestamp')
            if not timestamp_str:
                logger.warning(f"Historical file missing timestamp: {file_path.name}")
                continue
            timestamp_dt = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
            
            for company, frameworks in data['results'].items():
                for framework, metrics in frameworks.items():
                    if framework != 'overall':
                        trend_data.append({
                            'date': timestamp_dt,
                            'company': company,
                            'framework': framework,
                            'compliance_percentage': metrics['compliance_percentage'],
                            'risk_level': metrics['risk_level']
                        })
        
        if not trend_data:
            return
        
        df_trend = pd.DataFrame(trend_data)
        
        # Create enhanced trend visualization
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(20, 16))
        
        # 1. Individual Company Trends
        for company in df_trend['company'].unique():
            company_data = df_trend[df_trend['company'] == company]
            
            # Calculate overall trend per date for this company
            company_trend = company_data.groupby('date')['compliance_percentage'].mean().reset_index()
            
            ax1.plot(company_trend['date'], company_trend['compliance_percentage'], 
                    marker='o', linewidth=3, markersize=8, label=company)
        
        ax1.set_title('Company Compliance Trends Over Time', fontsize=14, fontweight='bold')
        ax1.set_xlabel('Date')
        ax1.set_ylabel('Average Compliance Percentage (%)')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        ax1.tick_params(axis='x', rotation=45)
        
        # 2. Framework-specific trends
        for framework in df_trend['framework'].unique():
            framework_data = df_trend[df_trend['framework'] == framework]
            framework_trend = framework_data.groupby('date')['compliance_percentage'].mean().reset_index()
            
            ax2.plot(framework_trend['date'], framework_trend['compliance_percentage'], 
                    marker='s', linewidth=3, markersize=8, label=framework)
        
        ax2.set_title('Framework Compliance Trends Over Time', fontsize=14, fontweight='bold')
        ax2.set_xlabel('Date')
        ax2.set_ylabel('Average Compliance Percentage (%)')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        ax2.tick_params(axis='x', rotation=45)
        
        # 3. Risk Level Evolution
        risk_evolution = df_trend.groupby(['date', 'risk_level']).size().unstack(fill_value=0)
        risk_evolution.plot(kind='area', ax=ax3, stacked=True, alpha=0.7,
                           color=[self.risk_levels[level]['color'] for level in risk_evolution.columns])
        ax3.set_title('Risk Level Evolution Over Time', fontsize=14, fontweight='bold')
        ax3.set_xlabel('Date')
        ax3.set_ylabel('Number of Assessments')
        ax3.legend(title='Risk Level')
        ax3.tick_params(axis='x', rotation=45)
        
        # 4. Improvement/Deterioration Analysis
        if len(df_trend['date'].unique()) >= 2:
            latest_date = df_trend['date'].max()
            previous_date = df_trend['date'].unique()[-2]
            
            latest_data = df_trend[df_trend['date'] == latest_date]
            previous_data = df_trend[df_trend['date'] == previous_date]
            
            # Calculate changes
            changes = []
            for _, latest_row in latest_data.iterrows():
                company = latest_row['company']
                framework = latest_row['framework']
                
                previous_row = previous_data[
                    (previous_data['company'] == company) & 
                    (previous_data['framework'] == framework)
                ]
                
                if not previous_row.empty:
                    change = latest_row['compliance_percentage'] - previous_row.iloc[0]['compliance_percentage']
                    changes.append({
                        'entity': f"{company}-{framework}",
                        'change': change
                    })
            
            if changes:
                df_changes = pd.DataFrame(changes).sort_values('change')
                colors = ['red' if x < 0 else 'green' for x in df_changes['change']]
                
                bars = ax4.barh(range(len(df_changes)), df_changes['change'], color=colors)
                ax4.set_yticks(range(len(df_changes)))
                ax4.set_yticklabels(df_changes['entity'], fontsize=10)
                ax4.set_xlabel('Change in Compliance Percentage (%)')
                ax4.set_title('Latest Period Change Analysis', fontsize=14, fontweight='bold')
                ax4.axvline(x=0, color='black', linestyle='-', alpha=0.5)
                
                # Add value labels
                for i, (bar, val) in enumerate(zip(bars, df_changes['change'])):
                    ax4.text(val + (0.5 if val >= 0 else -0.5), i, f'{val:.1f}%', 
                            va='center', ha='left' if val >= 0 else 'right')
        
        plt.tight_layout()
        plt.savefig(self.charts_dir / f"enhanced_trends_{timestamp}.png", 
                   dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
    
    def _generate_interactive_dashboard(self, timestamp):
        """Generate interactive HTML dashboard using Plotly"""
        # Create subplot structure
        fig = make_subplots(
            rows=3, cols=2,
            subplot_titles=('Compliance Overview', 'Risk Distribution', 
                           'Framework Comparison', 'Category Performance',
                           'Severity Analysis', 'Company Rankings'),
            specs=[[{"type": "scatter"}, {"type": "pie"}],
                   [{"type": "bar"}, {"type": "heatmap"}],
                   [{"type": "bar"}, {"type": "bar"}]]
        )
        
        # Prepare data
        companies = list(self.companies.keys())
        frameworks = list(self.rules.keys())
        
        # 1. Compliance Overview (Scatter)
        for framework in frameworks:
            x_vals = []
            y_vals = []
            texts = []
            colors = []
            
            for company in companies:
                compliance = self.results[company][framework]['compliance_percentage']
                risk_level = self.results[company][framework]['risk_level']
                x_vals.append(company)
                y_vals.append(compliance)
                texts.append(f"{company}<br>{framework}<br>{compliance:.1f}%<br>{risk_level}")
                colors.append(self.risk_levels[risk_level]['color'])
            
            fig.add_trace(
                go.Scatter(x=x_vals, y=y_vals, mode='markers+text',
                          name=framework, text=[f"{y:.1f}%" for y in y_vals],
                          textposition="top center",
                          marker=dict(size=15, color=colors, line=dict(width=2, color='black')),
                          hovertext=texts),
                row=1, col=1
            )
        
        # 2. Risk Distribution (Pie)
        risk_counts = {}
        for company, frameworks_data in self.results.items():
            for framework, metrics in frameworks_data.items():
                if framework != 'overall':
                    risk_level = metrics['risk_level']
                    risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        fig.add_trace(
            go.Pie(labels=list(risk_counts.keys()), values=list(risk_counts.values()),
                   marker_colors=[self.risk_levels[level]['color'] for level in risk_counts.keys()]),
            row=1, col=2
        )
        
        # 3. Framework Comparison (Bar)
        framework_avg = {}
        for framework in frameworks:
            total_compliance = 0
            count = 0
            for company in companies:
                total_compliance += self.results[company][framework]['compliance_percentage']
                count += 1
            framework_avg[framework] = total_compliance / count if count > 0 else 0
        
        fig.add_trace(
            go.Bar(x=list(framework_avg.keys()), y=list(framework_avg.values()),
                   name="Average Compliance",
                   marker_color=['#4ECDC4', '#45B7D1', '#96CEB4']),
            row=2, col=1
        )
        
        # 4. Company Rankings (Bar)
        company_overall = {}
        for company in companies:
            company_overall[company] = self.results[company]['overall']['compliance_percentage']
        
        sorted_companies = sorted(company_overall.items(), key=lambda x: x[1], reverse=True)
        
        fig.add_trace(
            go.Bar(x=[c[0] for c in sorted_companies], y=[c[1] for c in sorted_companies],
                   name="Overall Compliance",
                   marker_color='lightcoral'),
            row=3, col=2
        )
        
        # Update layout
        fig.update_layout(
            title_text="Interactive Compliance Dashboard",
            title_x=0.5,
            height=1200,
            showlegend=True
        )
        
        # Save as HTML
        html_file = self.charts_dir / f"interactive_dashboard_{timestamp}.html"
        fig.write_html(str(html_file))
        
        logger.info(f"Interactive dashboard saved to: {html_file}")
    
    def _generate_framework_matrix(self, timestamp):
        """Generate framework performance matrix"""
        frameworks = list(self.rules.keys())
        companies = list(self.companies.keys())
        
        # Create performance matrix
        fig, ax = plt.subplots(figsize=(16, 12))
        
        # Prepare data for matrix visualization
        matrix_data = []
        for i, framework in enumerate(frameworks):
            row_data = []
            for j, company in enumerate(companies):
                compliance = self.results[company][framework]['compliance_percentage']
                row_data.append(compliance)
            matrix_data.append(row_data)
        
        # Create heatmap with detailed annotations
        im = ax.imshow(matrix_data, cmap='RdYlGn', aspect='auto', vmin=0, vmax=100)
        
        # Add detailed annotations
        for i in range(len(frameworks)):
            for j in range(len(companies)):
                framework = frameworks[i]
                company = companies[j]
                compliance = self.results[company][framework]['compliance_percentage']
                risk_level = self.results[company][framework]['risk_level']
                passed_rules = self.results[company][framework]['passed_rules']
                total_rules = self.results[company][framework]['total_rules']
                
                text = f"{compliance:.1f}%\n{risk_level}\n{passed_rules}/{total_rules}"
                color = 'white' if compliance < 50 else 'black'
                
                ax.text(j, i, text, ha='center', va='center', 
                       color=color, fontsize=10, fontweight='bold')
        
        # Customize axes
        ax.set_xticks(range(len(companies)))
        ax.set_yticks(range(len(frameworks)))
        ax.set_xticklabels(companies, rotation=45, ha='right')
        ax.set_yticklabels(frameworks)
        
        # Add colorbar
        cbar = plt.colorbar(im, ax=ax, shrink=0.8)
        cbar.set_label('Compliance Percentage (%)', rotation=270, labelpad=20)
        
        # Add title
        plt.title('Framework Performance Matrix\n(Compliance % | Risk Level | Passed/Total Rules)', 
                 fontsize=16, fontweight='bold', pad=20)
        
        plt.tight_layout()
        plt.savefig(self.charts_dir / f"framework_matrix_{timestamp}.png", 
                   dpi=300, bbox_inches='tight', facecolor='white')
        plt.close()
    
    def generate_enhanced_excel_reports(self):
        """Generate comprehensive Excel reports with multiple detailed sheets"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        excel_file = self.output_dir / f"comprehensive_compliance_report_{timestamp}.xlsx"
        
        # Prepare all data structures
        summary_data = []
        detailed_data = []
        remediation_data = []
        category_data = []
        severity_data = []
        risk_analysis_data = []
        trend_data = []
        
        for company, frameworks in self.results.items():
            # Overall company summary
            summary_data.append({
                'Company': company,
                'Overall_Compliance': frameworks['overall']['compliance_percentage'],
                'Overall_Risk_Level': frameworks['overall']['risk_level'],
                'Total_Critical_Issues': frameworks['overall']['total_critical_issues'],
                'Total_High_Issues': frameworks['overall']['total_high_issues'],
                'Evaluation_Date': frameworks['overall']['evaluation_date'],
                'CIS_Compliance': frameworks.get('CIS', {}).get('compliance_percentage', 0),
                'CIS_Risk': frameworks.get('CIS', {}).get('risk_level', 'N/A'),
                'ISO27001_Compliance': frameworks.get('ISO27001', {}).get('compliance_percentage', 0),
                'ISO27001_Risk': frameworks.get('ISO27001', {}).get('risk_level', 'N/A'),
                'RBI_Compliance': frameworks.get('RBI', {}).get('compliance_percentage', 0),
                'RBI_Risk': frameworks.get('RBI', {}).get('risk_level', 'N/A')
            })
            
            for framework, metrics in frameworks.items():
                if framework != 'overall':
                    # Risk analysis data
                    risk_analysis_data.append({
                        'Company': company,
                        'Framework': framework,
                        'Compliance_Percentage': metrics['compliance_percentage'],
                        'Risk_Level': metrics['risk_level'],
                        'Total_Rules': metrics['total_rules'],
                        'Passed_Rules': metrics['passed_rules'],
                        'Failed_Rules': metrics['failed_rules'],
                        'Missing_Data_Rules': metrics['missing_data_rules'],
                        'Error_Rules': metrics['error_rules'],
                        'Critical_Severity_Count': metrics['severity_breakdown'].get('CRITICAL', 0),
                        'High_Severity_Count': metrics['severity_breakdown'].get('HIGH', 0),
                        'Medium_Severity_Count': metrics['severity_breakdown'].get('MEDIUM', 0),
                        'Low_Severity_Count': metrics['severity_breakdown'].get('LOW', 0)
                    })
                    
                    # Category breakdown
                    for category, cat_stats in metrics['category_breakdown'].items():
                        category_data.append({
                            'Company': company,
                            'Framework': framework,
                            'Category': category,
                            'Total_Rules': cat_stats['total'],
                            'Passed_Rules': cat_stats['passed'],
                            'Failed_Rules': cat_stats['failed'],
                            'Compliance_Percentage': cat_stats['compliance_pct'],
                            'Risk_Assessment': self._calculate_risk_level(cat_stats['compliance_pct'])
                        })
                    
                    # Severity breakdown
                    for severity, count in metrics['severity_breakdown'].items():
                        if count > 0:
                            severity_data.append({
                                'Company': company,
                                'Framework': framework,
                                'Severity': severity,
                                'Count': count,
                                'Percentage_of_Total': round((count / metrics['total_rules']) * 100, 2)
                            })
                    
                    # Detailed rule analysis
                    for rule in metrics['rule_details']:
                        # Basic rule data
                        rule_data = {
                            'Company': company,
                            'Framework': framework,
                            'Rule_ID': rule['rule_id'],
                            'Category': rule['category'],
                            'Description': rule['description'],
                            'Status': rule['status'],
                            'Severity': rule['severity'],
                            'Weight': rule['weight'],
                            'Score': rule['score'],
                            'Field_Checked': rule['field'],
                            'Expected_Value': rule['expected_value'],
                            'Actual_Value': rule['actual_value'],
                            'Status_Message': rule['message']
                        }
                        
                        # Enhanced remediation data
                        if 'remediation' in rule and isinstance(rule['remediation'], dict):
                            rem = rule['remediation']
                            rule_data.update({
                                'Remediation_Description': rem.get('description', ''),
                                'Impact_Analysis': rem.get('impact', ''),
                                'Priority_Level': rem.get('priority', ''),
                                'Effort_Estimate': rem.get('effort', ''),
                                'Business_Justification': rem.get('business_justification', ''),
                                'Has_Automation_Scripts': 'Yes' if rem.get('scripts') else 'No',
                                'Script_Count': len(rem.get('scripts', [])),
                                'References': '; '.join(rem.get('references', []))
                            })
                        else:
                            rule_data.update({
                                'Remediation_Description': rule.get('remediation', ''),
                                'Impact_Analysis': '',
                                'Priority_Level': '',
                                'Effort_Estimate': '',
                                'Business_Justification': '',
                                'Has_Automation_Scripts': 'No',
                                'Script_Count': 0,
                                'References': ''
                            })
                        
                        detailed_data.append(rule_data)
                        
                        # Remediation planning data (for failed rules)
                        if rule['status'] in ['FAIL', 'MISSING_DATA', 'ERROR']:
                            remediation_entry = {
                                'Company': company,
                                'Framework': framework,
                                'Rule_ID': rule['rule_id'],
                                'Category': rule['category'],
                                'Description': rule['description'],
                                'Current_Status': rule['status'],
                                'Severity': rule['severity'],
                                'Priority_Score': self._calculate_priority_score(rule),
                                'Remediation_Description': rule_data['Remediation_Description'],
                                'Impact_Analysis': rule_data['Impact_Analysis'],
                                'Effort_Estimate': rule_data['Effort_Estimate'],
                                'Business_Justification': rule_data['Business_Justification'],
                                'Recommended_Timeline': self._get_remediation_timeline(rule),
                                'Assigned_Team': self._get_recommended_team(rule),
                                'Cost_Category': self._get_cost_category(rule),
                                'Compliance_Frameworks_Affected': framework,
                                'Has_Automation_Scripts': rule_data['Has_Automation_Scripts']
                            }
                            
                            remediation_data.append(remediation_entry)
        
        # Write to Excel with multiple sheets
        with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
            # Executive Summary Sheet
            pd.DataFrame(summary_data).to_excel(
                writer, sheet_name='Executive_Summary', index=False
            )
            
            # Risk Analysis Sheet
            pd.DataFrame(risk_analysis_data).to_excel(
                writer, sheet_name='Risk_Analysis', index=False
            )
            
            # Detailed Results Sheet
            pd.DataFrame(detailed_data).to_excel(
                writer, sheet_name='Detailed_Results', index=False
            )
            
            # Remediation Plan Sheet (sorted by priority)
            remediation_df = pd.DataFrame(remediation_data)
            if not remediation_df.empty:
                remediation_df.sort_values(['Priority_Score', 'Company'], ascending=[False, True]).to_excel(
                    writer, sheet_name='Remediation_Plan', index=False
                )
            
            # Category Analysis Sheet
            pd.DataFrame(category_data).to_excel(
                writer, sheet_name='Category_Analysis', index=False
            )
            
            # Severity Analysis Sheet
            pd.DataFrame(severity_data).to_excel(
                writer, sheet_name='Severity_Analysis', index=False
            )
            
            # Failed Rules Focus Sheet
            failed_rules = [rule for rule in detailed_data if rule['Status'] in ['FAIL', 'MISSING_DATA', 'ERROR']]
            if failed_rules:
                pd.DataFrame(failed_rules).to_excel(
                    writer, sheet_name='Failed_Rules_Analysis', index=False
                )
            
            # Passed Rules Analysis Sheet
            passed_rules = [rule for rule in detailed_data if rule['Status'] == 'PASS']
            if passed_rules:
                pd.DataFrame(passed_rules).to_excel(
                    writer, sheet_name='Passed_Rules_Analysis', index=False
                )
            
            # Company Comparison Sheet
            comparison_data = []
            for framework in self.rules.keys():
                for company in self.companies.keys():
                    metrics = self.results[company][framework]
                    comparison_data.append({
                        'Framework': framework,
                        'Company': company,
                        'Compliance_Pct': metrics['compliance_percentage'],
                        'Risk_Level': metrics['risk_level'],
                        'Passed_Rules': metrics['passed_rules'],
                        'Total_Rules': metrics['total_rules'],
                        'Pass_Rate': round((metrics['passed_rules'] / metrics['total_rules']) * 100, 2)
                    })
            
            pd.DataFrame(comparison_data).to_excel(
                writer, sheet_name='Company_Comparison', index=False
            )
        
        logger.info(f"Comprehensive Excel report saved to: {excel_file}")
        return excel_file
    
    def _calculate_priority_score(self, rule):
        """Calculate priority score for remediation planning"""
        severity_scores = {'CRITICAL': 100, 'HIGH': 75, 'MEDIUM': 50, 'LOW': 25}
        weight_multiplier = rule.get('weight', 1)
        severity = rule.get('severity', 'MEDIUM')
        
        base_score = severity_scores.get(severity, 50)
        return base_score + (weight_multiplier * 5)
    
    def _get_remediation_timeline(self, rule):
        """Get recommended timeline for remediation"""
        severity = rule.get('severity', 'MEDIUM')
        timeline_map = {
            'CRITICAL': 'Immediate (24 hours)',
            'HIGH': 'Urgent (1 week)',
            'MEDIUM': 'Standard (1 month)',
            'LOW': 'Planned (3 months)'
        }
        return timeline_map.get(severity, 'Standard (1 month)')
    
    def _get_recommended_team(self, rule):
        """Get recommended team for remediation"""
        category = rule.get('category', 'General')
        team_map = {
            'Access Control': 'Security Team',
            'Asset Management': 'IT Operations',
            'Configuration Management': 'System Administration',
            'Network Security': 'Network Team',
            'Logging and Monitoring': 'SOC Team',
            'Vulnerability Management': 'Security Team',
            'Incident Response': 'Security Team',
            'Business Continuity': 'Risk Management'
        }
        return team_map.get(category, 'IT Team')
    
    def _get_cost_category(self, rule):
        """Get estimated cost category for remediation"""
        category = rule.get('category', 'General')
        severity = rule.get('severity', 'MEDIUM')
        
        if severity in ['CRITICAL', 'HIGH']:
            return 'High Priority ($$)'
        elif category in ['Asset Management', 'Logging and Monitoring', 'Business Continuity']:
            return 'Medium-High ($-$$)'
        elif category in ['Configuration Management']:
            return 'Low ($)'
        else:
            return 'Medium ($)'
    
    def generate_remediation_scripts(self):
        """Generate actual remediation scripts for failed rules"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scripts_generated = []
        
        for company, frameworks in self.results.items():
            company_dir = self.scripts_dir / company
            company_dir.mkdir(exist_ok=True)
            
            for framework, metrics in frameworks.items():
                if framework != 'overall':
                    framework_dir = company_dir / framework
                    framework_dir.mkdir(exist_ok=True)
                    
                    for rule in metrics['rule_details']:
                        if rule['status'] in ['FAIL', 'MISSING_DATA'] and 'remediation' in rule:
                            remediation = rule['remediation']
                            if isinstance(remediation, dict) and remediation.get('scripts'):
                                for script in remediation['scripts']:
                                    script_file = framework_dir / script['name']
                                    with open(script_file, 'w') as f:
                                        f.write("#!/bin/bash\n")
                                        f.write(f"# Remediation script for Rule: {rule['rule_id']}\n")
                                        f.write(f"# Description: {rule['description']}\n")
                                        f.write(f"# Company: {company}\n")
                                        f.write(f"# Framework: {framework}\n")
                                        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                                        f.write(script['content'])
                                    
                                    # Make script executable
                                    script_file.chmod(0o755)
                                    
                                    scripts_generated.append({
                                        'company': company,
                                        'framework': framework,
                                        'rule_id': rule['rule_id'],
                                        'script_path': str(script_file)
                                    })
        
        # Generate master remediation script
        if scripts_generated:
            master_script = self.scripts_dir / f"run_all_remediation_{timestamp}.sh"
            with open(master_script, 'w') as f:
                f.write("#!/bin/bash\n")
                f.write("# Master Remediation Script\n")
                f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write("echo 'Starting compliance remediation...'\n\n")
                
                for script_info in scripts_generated:
                    f.write(f"echo 'Running remediation for {script_info['company']} - {script_info['framework']} - {script_info['rule_id']}'\n")
                    f.write(f"bash {script_info['script_path']}\n")
                    f.write("echo 'Completed.'\n\n")
                
                f.write("echo 'All remediation scripts completed!'\n")
            
            master_script.chmod(0o755)
        
        logger.info(f"Generated {len(scripts_generated)} remediation scripts")
        return scripts_generated
    
    def generate_enhanced_pdf_report(self):
        """Generate comprehensive PDF report with enhanced formatting"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_file = self.output_dir / f"professional_compliance_report_{timestamp}.pdf"
        
        doc = SimpleDocTemplate(
            str(pdf_file),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        styles = getSampleStyleSheet()
        story = []
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor('#1f4e79'),
            spaceAfter=30,
            alignment=1  # Center alignment
        )
        
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2E75B6'),
            spaceAfter=20
        )
        
        section_style = ParagraphStyle(
            'SectionHeading',
            parent=styles['Heading3'],
            fontSize=14,
            textColor=colors.HexColor('#1f4e79'),
            spaceAfter=15,
            spaceBefore=20
        )
        
        # Title Page
        story.append(Paragraph("COMPREHENSIVE COMPLIANCE AUDIT REPORT", title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph(f"Assessment Date: {datetime.now().strftime('%B %d, %Y')}", styles['Normal']))
        story.append(Paragraph(f"Report Generated: {datetime.now().strftime('%I:%M %p')}", styles['Normal']))
        story.append(Spacer(1, 30))
        
        # Executive Summary
        story.append(Paragraph("EXECUTIVE SUMMARY", subtitle_style))
        
        total_companies = len(self.companies)
        critical_risk_companies = sum(1 for comp in self.results.values() 
                                    if comp['overall']['risk_level'] in ['CRITICAL', 'HIGH'])
        avg_compliance = np.mean([comp['overall']['compliance_percentage'] for comp in self.results.values()])
        total_critical_issues = sum(comp['overall']['total_critical_issues'] for comp in self.results.values())
        total_high_issues = sum(comp['overall']['total_high_issues'] for comp in self.results.values())
        
        summary_text = f"""
        <b>Assessment Overview:</b><br/>
        This comprehensive compliance assessment evaluated <b>{total_companies} organizations</b> against three critical 
        security frameworks: CIS Controls, ISO 27001, and RBI Guidelines. The assessment identifies significant 
        security gaps requiring immediate attention.<br/><br/>
        
        <b>Key Findings:</b><br/>
        • <b>{critical_risk_companies} out of {total_companies}</b> organizations classified as CRITICAL or HIGH risk<br/>
        • Average compliance across all frameworks: <b>{avg_compliance:.1f}%</b><br/>
        • <b>{total_critical_issues}</b> critical security issues identified<br/>
        • <b>{total_high_issues}</b> high-priority security gaps requiring immediate remediation<br/>
        • Comprehensive remediation guidance provided with automation scripts<br/><br/>
        
        <b>Strategic Recommendations:</b><br/>
        1. Immediate action required for organizations with compliance below 50%<br/>
        2. Implementation of automated security controls and monitoring<br/>
        3. Regular compliance assessments to track improvement progress<br/>
        4. Investment in security awareness training and policy enforcement
        """
        
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Risk Assessment Matrix
        story.append(Paragraph("ORGANIZATIONAL RISK MATRIX", section_style))
        
        # Create detailed risk table
        risk_table_data = [['Organization', 'Overall Risk', 'Compliance %', 'CIS', 'ISO 27001', 'RBI', 'Critical Issues', 'Remediation Priority']]
        
        for company, results in self.results.items():
            critical_count = results['overall']['total_critical_issues']
            priority = 'P0 - Immediate' if critical_count > 5 else 'P1 - High' if critical_count > 2 else 'P2 - Medium'
            
            row = [
                company.upper(),
                results['overall']['risk_level'],
                f"{results['overall']['compliance_percentage']:.1f}%",
                f"{results['CIS']['compliance_percentage']:.1f}%",
                f"{results['ISO27001']['compliance_percentage']:.1f}%",
                f"{results['RBI']['compliance_percentage']:.1f}%",
                str(critical_count),
                priority
            ]
            risk_table_data.append(row)
        
        risk_table = Table(risk_table_data, colWidths=[1.2*inch, 0.8*inch, 0.8*inch, 0.6*inch, 0.8*inch, 0.6*inch, 0.8*inch, 1.2*inch])
        
        # Enhanced table styling
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f4e79')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 8)
        ]))
        
        # Color code risk levels
        for i, row in enumerate(risk_table_data[1:], 1):
            risk_level = row[1]
            if risk_level in ['CRITICAL', 'HIGH']:
                risk_table.setStyle(TableStyle([
                    ('BACKGROUND', (1, i), (1, i), colors.HexColor('#FFB6C1'))
                ]))
        
        story.append(risk_table)
        story.append(PageBreak())
        
        # Framework Analysis Section
        story.append(Paragraph("FRAMEWORK COMPLIANCE ANALYSIS", subtitle_style))
        
        for framework in self.rules.keys():
            story.append(Paragraph(f"{framework} Framework Analysis", section_style))
            
            framework_data = []
            for company, results in self.results.items():
                fw_result = results[framework]
                framework_data.append([
                    company,
                    f"{fw_result['compliance_percentage']:.1f}%",
                    fw_result['risk_level'],
                    f"{fw_result['passed_rules']}/{fw_result['total_rules']}",
                    fw_result['severity_breakdown'].get('CRITICAL', 0),
                    fw_result['severity_breakdown'].get('HIGH', 0)
                ])
            
            fw_table_data = [['Company', 'Compliance', 'Risk Level', 'Rules (Pass/Total)', 'Critical Issues', 'High Issues']] + framework_data
            
            fw_table = Table(fw_table_data, colWidths=[1.5*inch, 1*inch, 1*inch, 1.2*inch, 1*inch, 1*inch])
            fw_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2E75B6')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 9)
            ]))
            
            story.append(fw_table)
            story.append(Spacer(1, 15))
        
        story.append(PageBreak())
        
        # Critical Issues and Remediation
        story.append(Paragraph("CRITICAL ISSUES & REMEDIATION ROADMAP", subtitle_style))
        
        # Get all critical and high issues
        critical_issues = []
        for company, frameworks in self.results.items():
            for framework, metrics in frameworks.items():
                if framework != 'overall':
                    for rule in metrics['rule_details']:
                        if rule['status'] == 'FAIL' and rule['severity'] in ['CRITICAL', 'HIGH']:
                            critical_issues.append({
                                'company': company,
                                'framework': framework,
                                'rule': rule,
                                'priority_score': self._calculate_priority_score(rule)
                            })
        
        # Sort by priority
        critical_issues.sort(key=lambda x: x['priority_score'], reverse=True)
        
        # Display top 15 critical issues
        story.append(Paragraph("TOP PRIORITY SECURITY GAPS", section_style))
        
        for i, issue in enumerate(critical_issues[:15], 1):
            rule = issue['rule']
            remediation = rule.get('remediation', {})
            
            issue_text = f"""
            <b>{i}. {rule['description']}</b><br/>
            <i>Organization:</i> {issue['company']} | <i>Framework:</i> {issue['framework']} | 
            <i>Severity:</i> {rule['severity']}<br/>
            <i>Current Status:</i> {rule['message']}<br/>
            <i>Impact:</i> {remediation.get('impact', 'Security risk identified')}<br/>
            <i>Remediation:</i> {remediation.get('description', 'See detailed remediation plan')}<br/>
            <i>Timeline:</i> {self._get_remediation_timeline(rule)} | 
            <i>Estimated Effort:</i> {remediation.get('effort', 'Medium effort')}<br/>
            <i>Automation Available:</i> {'Yes' if remediation.get('scripts') else 'No'}
            """
            
            story.append(KeepTogether([
                Paragraph(issue_text, styles['Normal']),
                Spacer(1, 10)
            ]))
        
        story.append(PageBreak())
        
        # Implementation Roadmap
        story.append(Paragraph("IMPLEMENTATION ROADMAP", subtitle_style))
        
        roadmap_text = """
        <b>Phase 1: Immediate Actions (0-30 days)</b><br/>
        • Address all CRITICAL severity issues<br/>
        • Implement basic security controls (firewall, patching)<br/>
        • Establish incident response procedures<br/>
        • Begin security awareness training<br/><br/>
        
        <b>Phase 2: Short-term Improvements (1-6 months)</b><br/>
        • Deploy automated monitoring and logging<br/>
        • Implement vulnerability management program<br/>
        • Strengthen access controls and authentication<br/>
        • Establish regular compliance assessments<br/><br/>
        
        <b>Phase 3: Long-term Maturity (6-12 months)</b><br/>
        • Advanced threat detection and response<br/>
        • Comprehensive security metrics and reporting<br/>
        • Third-party security assessments<br/>
        • Continuous compliance monitoring<br/><br/>
        
        <b>Success Metrics:</b><br/>
        • Target: 85%+ compliance across all frameworks<br/>
        • Zero critical security issues<br/>
        • Automated remediation for 70%+ of common issues<br/>
        • Monthly compliance assessments with trend analysis
        """
        
        story.append(Paragraph(roadmap_text, styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Footer information
        footer_text = f"""
        <i>This report was generated by the Enhanced Compliance Audit Engine on {datetime.now().strftime('%B %d, %Y')}. 
        For detailed remediation scripts and technical implementation guidance, refer to the accompanying 
        Excel reports and automation scripts.</i>
        """
        story.append(Paragraph(footer_text, styles['Italic']))
        
        # Build PDF
        doc.build(story)
        logger.info(f"Enhanced PDF report saved to: {pdf_file}")
        
        return pdf_file
    
    def run_comprehensive_audit(self, company_files=None):
        """Run complete enhanced compliance audit with all features"""
        logger.info("Starting comprehensive compliance audit...")
        
        # Load configurations
        self.load_frameworks()
        self.load_companies(company_files)
        
        if not self.companies:
            logger.error("No company configurations loaded!")
            return None
        
        # Evaluate each company
        for company_name, company_data in self.companies.items():
            logger.info(f"Evaluating company: {company_name}")
            self.results[company_name] = self.evaluate_company(company_name, company_data)
        
        # Save results
        self._save_results()
        
        # Generate all visualizations
        logger.info("Generating comprehensive visualizations...")
        self.generate_enhanced_visualizations()
        
        # Generate enhanced reports
        logger.info("Generating enhanced Excel reports...")
        excel_file = self.generate_enhanced_excel_reports()
        
        logger.info("Generating remediation scripts...")
        scripts = self.generate_remediation_scripts()
        
        logger.info("Generating professional PDF report...")
        pdf_file = self.generate_enhanced_pdf_report()
        
        # Generate summary
        self._print_comprehensive_summary()
        
        logger.info("Comprehensive audit completed successfully!")
        
        return {
            'results': self.results,
            'excel_report': excel_file,
            'pdf_report': pdf_file,
            'remediation_scripts': scripts,
            'charts_directory': self.charts_dir
        }
    
    def _save_results(self):
        """Save audit results to JSON with enhanced metadata"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Enhanced results with metadata
        enhanced_results = {
            'metadata': {
                'timestamp': timestamp,
                'generation_time': datetime.now().isoformat(),
                'total_companies': len(self.companies),
                'frameworks_assessed': list(self.rules.keys()),
                'total_rules_evaluated': sum(len(rules) for rules in self.rules.values()),
                'assessment_summary': {
                    'high_risk_companies': sum(1 for comp in self.results.values() 
                                             if comp['overall']['risk_level'] in ['CRITICAL', 'HIGH']),
                    'average_compliance': round(np.mean([comp['overall']['compliance_percentage'] 
                                                        for comp in self.results.values()]), 2),
                    'total_critical_issues': sum(comp['overall']['total_critical_issues'] 
                                                for comp in self.results.values()),
                    'total_high_issues': sum(comp['overall']['total_high_issues'] 
                                           for comp in self.results.values())
                }
            },
            'results': self.results
        }
        
        # Save current results
        results_file = self.output_dir / f"comprehensive_results_{timestamp}.json"
        with open(results_file, 'w') as f:
            json.dump(enhanced_results, f, indent=2, default=str)
        
        # Save to historical data
        historical_file = self.historical_dir / f"audit_{timestamp}.json"
        with open(historical_file, 'w') as f:
            json.dump(enhanced_results, f, indent=2, default=str)
        
        logger.info(f"Enhanced results saved to: {results_file}")
    
    def send_alerts(self, email_config):
        """Send email alerts for critical issues"""
        try:
            # Get critical issues
            critical_issues = []
            for company, frameworks in self.results.items():
                for framework, metrics in frameworks.items():
                    if framework != 'overall':
                        for rule in metrics['rule_details']:
                            if rule['status'] == 'FAIL' and rule['severity'] in ['CRITICAL', 'HIGH']:
                                critical_issues.append({
                                    'company': company,
                                    'framework': framework,
                                    'rule_id': rule['rule_id'],
                                    'description': rule['description'],
                                    'severity': rule['severity']
                                })
            
            if not critical_issues:
                logger.info("No critical issues found for alerting")
                return
            
            # Prepare email content
            subject = f"CRITICAL: {len(critical_issues)} High-Priority Security Issues Detected"
            
            body = f"""
            CRITICAL SECURITY ALERT
            
            {len(critical_issues)} high-priority security issues have been identified across {len(self.companies)} organizations.
            
            TOP CRITICAL ISSUES:
            """
            
            for i, issue in enumerate(critical_issues[:10], 1):
                body += f"\n{i}. {issue['description']}"
                body += f"\n   Organization: {issue['company']}"
                body += f"\n   Framework: {issue['framework']}"
                body += f"\n   Severity: {issue['severity']}"
                body += f"\n   Rule ID: {issue['rule_id']}\n"
            
            if len(critical_issues) > 10:
                body += f"\n... and {len(critical_issues) - 10} more critical issues."
            
            body += f"\n\nPlease review the detailed compliance report for complete remediation guidance."
            body += f"\n\nGenerated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            
            # Send email
            msg = MIMEMultipart()
            msg['From'] = email_config.get('from_email')
            msg['To'] = email_config.get('to_email')
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect to SMTP server
            server = smtplib.SMTP(email_config.get('smtp_server'), email_config.get('smtp_port', 587))
            server.starttls()
            server.login(email_config.get('username'), email_config.get('password'))
            
            text = msg.as_string()
            server.sendmail(email_config.get('from_email'), email_config.get('to_email'), text)
            server.quit()
            
            logger.info(f"Critical alert email sent successfully to {email_config.get('to_email')}")
            
        except Exception as e:
            logger.error(f"Failed to send alert email: {e}")

    def _print_comprehensive_summary(self):
        """Print detailed summary of audit results"""
        print("\n" + "="*80)
        print("COMPREHENSIVE COMPLIANCE AUDIT COMPLETED SUCCESSFULLY")
        print("="*80)
        
        # Overall statistics
        total_companies = len(self.companies)
        avg_compliance = np.mean([comp['overall']['compliance_percentage'] for comp in self.results.values()])
        high_risk_count = sum(1 for comp in self.results.values() 
                             if comp['overall']['risk_level'] in ['CRITICAL', 'HIGH'])
        
        print(f"\n📊 ASSESSMENT OVERVIEW:")
        print(f"   Companies Assessed: {total_companies}")
        print(f"   Average Compliance: {avg_compliance:.1f}%")
        print(f"   High-Risk Organizations: {high_risk_count}/{total_companies}")
        print(f"   Frameworks: {', '.join(self.rules.keys())}")
        
        # Company-wise summary
        print(f"\n🏢 COMPANY RISK PROFILE:")
        for company, results in sorted(self.results.items()):
            overall = results['overall']
            risk_emoji = {'CRITICAL': '🚨', 'HIGH': '⚠️', 'MEDIUM': '⚡', 'LOW': '✅', 'EXCELLENT': '🌟'}
            
            print(f"   {risk_emoji.get(overall['risk_level'], '❓')} {company.upper()}")
            print(f"      Overall: {overall['compliance_percentage']:.1f}% ({overall['risk_level']})")
            print(f"      Critical Issues: {overall['total_critical_issues']}")
            print(f"      High Issues: {overall['total_high_issues']}")
            
            framework_summary = []
            for fw in ['CIS', 'ISO27001', 'RBI']:
                if fw in results:
                    framework_summary.append(f"{fw}: {results[fw]['compliance_percentage']:.1f}%")
            
            print(f"      Frameworks: {' | '.join(framework_summary)}")
        
        # Critical issues summary
        total_critical = sum(comp['overall']['total_critical_issues'] for comp in self.results.values())
        total_high = sum(comp['overall']['total_high_issues'] for comp in self.results.values())
        
        print(f"\n🚨 SECURITY ISSUES SUMMARY:")
        print(f"   Critical Severity: {total_critical} issues")
        print(f"   High Severity: {total_high} issues")
        print(f"   Total Priority Issues: {total_critical + total_high}")
        
        # Generated outputs
        print(f"\n📋 GENERATED OUTPUTS:")
        print(f"   📊 Charts & Visualizations: {self.charts_dir}")
        print(f"   📝 Excel Reports: {self.output_dir}")
        print(f"   📄 PDF Executive Report: {self.output_dir}")
        print(f"   🔧 Remediation Scripts: {self.scripts_dir}")
        
        print(f"\n✨ Next Steps:")
        print(f"   1. Review the executive PDF report for strategic overview")
        print(f"   2. Use Excel reports for detailed technical analysis")
        print(f"   3. Execute remediation scripts for automated fixes")
        print(f"   4. Schedule follow-up assessment in 30-90 days")
        
        print("\n" + "="*80)


def main():
    """Enhanced main function for CLI execution"""
    parser = argparse.ArgumentParser(description='Enhanced Professional Compliance Audit Engine')
    parser.add_argument('--input', '-i', help='Input company JSON file or directory')
    parser.add_argument('--output', '-o', default='compliance_output', help='Output directory')
    parser.add_argument('--config', '-c', default='config', help='Configuration directory')
    parser.add_argument('--alerts', '-a', action='store_true', help='Send email alerts for critical issues')
    parser.add_argument('--email-config', help='Email configuration JSON file')
    parser.add_argument('--historical', default='historical_data', help='Historical data directory')
    parser.add_argument('--generate-sample', action='store_true', help='Generate sample configuration files')
    
    args = parser.parse_args()
    
    # Generate sample configurations if requested
    if args.generate_sample:
        generate_sample_configs(args.config)
        return
    
    # Initialize enhanced auditor
    auditor = EnhancedComplianceAuditor(
        config_dir=args.config,
        output_dir=args.output,
        historical_dir=args.historical
    )
    
    # Determine company files to process
    company_files = None
    if args.input:
        input_path = Path(args.input)
        if input_path.is_file():
            company_files = [input_path]
        elif input_path.is_dir():
            company_files = list(input_path.glob("*.json"))
    
    # Run comprehensive audit
    try:
        results = auditor.run_comprehensive_audit(company_files)
        
        # Send alerts if configured
        if args.alerts and args.email_config:
            try:
                with open(args.email_config, 'r') as f:
                    email_config = json.load(f)
                auditor.send_alerts(email_config)
            except Exception as e:
                logger.error(f"Failed to send alerts: {e}")
        
        return results
        
    except Exception as e:
        logger.error(f"Enhanced audit failed: {e}")
        raise


def generate_sample_configs(config_dir):
    """Generate sample configuration files for testing"""
    config_path = Path(config_dir)
    config_path.mkdir(exist_ok=True)
    
    # Sample CIS controls
    cis_controls = [
        {
            "id": "CIS-1.1",
            "description": "Maintain Inventory of Authorized Software",
            "category": "Asset Management",
            "field": "software_inventory.authorized_list",
            "operator": "!=",
            "expected_value": None,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Implement automated software inventory tools and maintain updated catalog of authorized software",
            "references": ["https://www.cisecurity.org/controls/inventory-and-control-of-software-assets"]
        },
        {
            "id": "CIS-4.1",
            "description": "Establish Secure Configurations for Network Devices",
            "category": "Configuration Management",
            "field": "network.secure_config",
            "operator": "==",
            "expected_value": True,
            "weight": 7,
            "severity": "HIGH",
            "remediation": "Apply security baselines to all network devices including firewalls, routers, and switches"
        }
    ]
    
    with open(config_path / "cis_controls.json", 'w') as f:
        json.dump(cis_controls, f, indent=2)
    
    # Sample ISO27001 controls
    iso_controls = [
        {
            "id": "ISO-A.9.1.1",
            "description": "Access Control Policy",
            "category": "Access Control",
            "field": "access_control.policy_exists",
            "operator": "==",
            "expected_value": True,
            "weight": 6,
            "severity": "MEDIUM",
            "remediation": "Develop and implement comprehensive access control policy"
        }
    ]
    
    with open(config_path / "iso27001_controls.json", 'w') as f:
        json.dump(iso_controls, f, indent=2)
    
    # Sample RBI guidelines
    rbi_controls = [
        {
            "id": "RBI-2.1",
            "description": "Information Security Governance",
            "category": "Governance",
            "field": "governance.security_committee",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Establish information security governance committee with board oversight"
        }
    ]
    
    with open(config_path / "rbi_guidelines.json", 'w') as f:
        json.dump(rbi_controls, f, indent=2)
    
    # Sample company configurations
    sample_companies = [
        {
            "name": "techcorp",
            "data": {
                "software_inventory": {"authorized_list": ["approved_software"]},
                "network": {"secure_config": True},
                "access_control": {"policy_exists": True},
                "governance": {"security_committee": True}
            }
        },
        {
            "name": "finservices",
            "data": {
                "software_inventory": {"authorized_list": None},
                "network": {"secure_config": False},
                "access_control": {"policy_exists": False},
                "governance": {"security_committee": False}
            }
        }
    ]
    
    for company in sample_companies:
        with open(config_path / f"company_{company['name']}.json", 'w') as f:
            json.dump(company['data'], f, indent=2)
    
    print(f"Sample configuration files generated in: {config_path}")


if __name__ == "__main__":
    main()