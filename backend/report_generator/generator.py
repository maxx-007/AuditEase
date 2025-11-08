"""
Main Report Generator Module
============================

Production-ready compliance report generator with comprehensive analysis,
remediation guidance, and multi-format output.

Author: AuditEase Security Team
Version: 2.0.0
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
import uuid

from .schema import (
    RuleStatus, Priority, Severity, Framework,
    RuleResult, FrameworkSummary, CategorySummary,
    ReportMetadata, ReportSchema, RemediationStep,
    RemediationCommand, CVEReference, validate_input_snapshot
)
from .visuals import VisualizationGenerator
from .xlsx_writer import ExcelReportWriter
from .pdf_report import PDFReportGenerator

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Production-ready compliance report generator.
    
    Generates comprehensive reports with:
    - Detailed rule-by-rule analysis
    - Evidence and remediation for every control
    - Multi-format outputs (JSON, Excel, PDF)
    - Visualizations and charts
    - Historical trend analysis
    """
    
    # Comprehensive remediation database
    REMEDIATION_DATABASE = {
        "password_policy": {
            "title": "Implement Strong Password Policy",
            "description": "Configure system to enforce strong password requirements including length, complexity, history, and expiration",
            "steps": [
                "Set minimum password length to 12-16 characters",
                "Require complexity (uppercase, lowercase, numbers, special characters)",
                "Enable password history to prevent reuse of last 10-24 passwords",
                "Set maximum password age to 60-90 days",
                "Configure account lockout after 5 failed attempts",
                "Implement password expiration warnings (14 days before expiry)",
                "Enable multi-factor authentication (MFA) for privileged accounts"
            ],
            "commands": [
                RemediationCommand(
                    platform="windows",
                    commands=[
                        "# Set minimum password length",
                        "net accounts /minpwlen:12",
                        "# Set maximum password age (90 days)",
                        "net accounts /maxpwage:90",
                        "# Set password history",
                        "net accounts /uniquepw:10",
                        "# Configure via Group Policy",
                        "secedit /configure /db secedit.sdb /cfg password_policy.inf"
                    ],
                    description="Windows password policy configuration"
                ),
                RemediationCommand(
                    platform="linux",
                    commands=[
                        "# Install password quality library",
                        "sudo apt-get install libpam-pwquality",
                        "# Configure password requirements",
                        "echo 'password requisite pam_pwquality.so minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1' | sudo tee -a /etc/pam.d/common-password",
                        "# Set password aging",
                        "sudo chage -M 90 -m 1 -W 14 <username>",
                        "# Enable password history",
                        "echo 'password required pam_pwhistory.so remember=10' | sudo tee -a /etc/pam.d/common-password"
                    ],
                    description="Linux password policy configuration"
                ),
                RemediationCommand(
                    platform="macos",
                    commands=[
                        "# Set password policy via pwpolicy",
                        "sudo pwpolicy -setglobalpolicy 'minChars=12 requiresAlpha=1 requiresNumeric=1 requiresSymbol=1'",
                        "# Set password expiration",
                        "sudo pwpolicy -setglobalpolicy 'maxMinutesUntilChangePassword=129600'  # 90 days"
                    ],
                    description="macOS password policy configuration"
                )
            ],
            "estimated_effort_hours": 2.0,
            "cost_estimate": "$500 - $2,000",
            "priority": Priority.CRITICAL,
            "validation_command": "net accounts  # Windows\nchage -l <username>  # Linux",
            "references": [
                "CIS Controls v8: 5.2, 5.3",
                "ISO 27001: A.9.4.3",
                "NIST 800-53: IA-5",
                "RBI Guidelines: Section 3.2.1"
            ]
        },
        "firewall_enabled": {
            "title": "Enable and Configure Host-Based Firewall",
            "description": "Activate and properly configure host-based firewall with default-deny policy and explicit allow rules",
            "steps": [
                "Enable firewall service on all systems",
                "Configure default deny policy for incoming traffic",
                "Create explicit allow rules for required services only",
                "Enable firewall logging for denied connections",
                "Configure firewall to start automatically on boot",
                "Document all firewall rules and exceptions",
                "Review and audit firewall rules quarterly"
            ],
            "commands": [
                RemediationCommand(
                    platform="windows",
                    commands=[
                        "# Enable Windows Firewall for all profiles",
                        "netsh advfirewall set allprofiles state on",
                        "# Set default inbound action to block",
                        "netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound",
                        "# Enable logging",
                        "netsh advfirewall set allprofiles logging filename %systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log",
                        "netsh advfirewall set allprofiles logging maxfilesize 4096",
                        "netsh advfirewall set allprofiles logging droppedconnections enable"
                    ],
                    description="Windows Firewall configuration"
                ),
                RemediationCommand(
                    platform="linux",
                    commands=[
                        "# Install and enable UFW (Ubuntu/Debian)",
                        "sudo apt-get install ufw",
                        "sudo ufw default deny incoming",
                        "sudo ufw default allow outgoing",
                        "# Allow SSH (if needed)",
                        "sudo ufw allow 22/tcp",
                        "# Enable firewall",
                        "sudo ufw enable",
                        "# Enable logging",
                        "sudo ufw logging on"
                    ],
                    description="Linux UFW firewall configuration"
                ),
                RemediationCommand(
                    platform="macos",
                    commands=[
                        "# Enable macOS firewall",
                        "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                        "# Enable logging",
                        "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on",
                        "# Enable stealth mode",
                        "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
                    ],
                    description="macOS firewall configuration"
                )
            ],
            "estimated_effort_hours": 3.0,
            "cost_estimate": "$1,000 - $3,000",
            "priority": Priority.CRITICAL,
            "validation_command": "netsh advfirewall show allprofiles  # Windows\nsudo ufw status verbose  # Linux",
            "references": [
                "CIS Controls v8: 4.4, 4.5",
                "ISO 27001: A.13.1.1",
                "NIST 800-53: SC-7",
                "RBI Guidelines: Section 4.1"
            ]
        },
        "antivirus_enabled": {
            "title": "Deploy and Configure Anti-Malware Protection",
            "description": "Install, configure, and maintain enterprise anti-malware solution with real-time protection and automatic updates",
            "steps": [
                "Deploy enterprise anti-malware solution to all endpoints",
                "Enable real-time protection and scanning",
                "Configure automatic signature updates (daily minimum)",
                "Enable cloud-based protection and behavioral analysis",
                "Schedule full system scans (weekly minimum)",
                "Configure quarantine and remediation policies",
                "Enable centralized logging and alerting",
                "Implement application whitelisting for critical systems"
            ],
            "commands": [
                RemediationCommand(
                    platform="windows",
                    commands=[
                        "# Enable Windows Defender (built-in)",
                        "Set-MpPreference -DisableRealtimeMonitoring $false",
                        "# Enable cloud protection",
                        "Set-MpPreference -MAPSReporting Advanced",
                        "Set-MpPreference -SubmitSamplesConsent SendAllSamples",
                        "# Configure scan schedule",
                        "Set-MpPreference -ScanScheduleDay Everyday",
                        "# Update signatures",
                        "Update-MpSignature",
                        "# Run quick scan",
                        "Start-MpScan -ScanType QuickScan"
                    ],
                    description="Windows Defender configuration"
                ),
                RemediationCommand(
                    platform="linux",
                    commands=[
                        "# Install ClamAV",
                        "sudo apt-get install clamav clamav-daemon",
                        "# Update virus definitions",
                        "sudo freshclam",
                        "# Configure automatic updates",
                        "sudo systemctl enable clamav-freshclam",
                        "sudo systemctl start clamav-freshclam",
                        "# Run scan",
                        "sudo clamscan -r /home --infected --remove"
                    ],
                    description="ClamAV installation and configuration"
                ),
                RemediationCommand(
                    platform="macos",
                    commands=[
                        "# Enable XProtect (built-in)",
                        "sudo spctl --master-enable",
                        "# Enable Gatekeeper",
                        "sudo spctl --enable",
                        "# Update XProtect definitions",
                        "sudo softwareupdate --install --all"
                    ],
                    description="macOS malware protection"
                )
            ],
            "estimated_effort_hours": 4.0,
            "cost_estimate": "$5,000 - $20,000 (enterprise solution)",
            "priority": Priority.CRITICAL,
            "validation_command": "Get-MpComputerStatus  # Windows\nsudo systemctl status clamav-daemon  # Linux",
            "references": [
                "CIS Controls v8: 10.1, 10.2",
                "ISO 27001: A.12.2.1",
                "NIST 800-53: SI-3",
                "RBI Guidelines: Section 5.1"
            ]
        }
    }

    def __init__(self, output_dir: str = "reports", config: Optional[Dict[str, Any]] = None):
        """
        Initialize report generator.

        Args:
            output_dir: Base directory for report outputs
            config: Optional configuration dictionary
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Configuration
        self.config = config or {}
        self.category_weights = self.config.get('category_weights', {})
        self.severity_thresholds = self.config.get('severity_thresholds', {
            'critical': 90,
            'high': 70,
            'medium': 50,
            'low': 30
        })
        self.include_remediation_scripts = self.config.get('include_remediation_scripts', True)
        self.max_top_gaps = self.config.get('max_top_gaps', 10)

        # Initialize sub-generators
        self.viz_generator = None
        self.excel_writer = None
        self.pdf_generator = None

    def generate_comprehensive_report(
        self,
        snapshot: Dict[str, Any],
        previous_snapshot: Optional[Dict[str, Any]] = None,
        run_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report from snapshot.

        Args:
            snapshot: Current compliance snapshot
            previous_snapshot: Optional previous snapshot for trend analysis
            run_id: Optional run identifier

        Returns:
            Dictionary containing report data and file paths
        """
        try:
            # Validate input
            snapshot = validate_input_snapshot(snapshot)

            # Generate run ID
            if not run_id:
                run_id = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

            logger.info(f"🎯 Generating comprehensive report: {run_id}")

            # Create run directory
            run_dir = self.output_dir / run_id
            run_dir.mkdir(parents=True, exist_ok=True)

            # Initialize generators
            self.viz_generator = VisualizationGenerator(run_dir)
            self.excel_writer = ExcelReportWriter(run_dir)
            self.pdf_generator = PDFReportGenerator(run_dir)

            # Extract metadata
            metadata = self._extract_metadata(snapshot, run_id)

            # Analyze snapshot and generate rule results
            logger.info("📊 Analyzing compliance data...")
            rule_results = self._analyze_snapshot(snapshot)

            # Generate framework summaries
            logger.info("📈 Generating framework summaries...")
            framework_summaries = self._generate_framework_summaries(rule_results)

            # Generate category summaries
            logger.info("📋 Generating category summaries...")
            category_summaries = self._generate_category_summaries(rule_results)

            # Calculate overall scores
            logger.info("🎯 Calculating overall scores...")
            overall_scores = self._calculate_overall_scores(framework_summaries, rule_results)

            # Identify top gaps
            logger.info("⚠️ Identifying critical gaps...")
            top_gaps = self._identify_top_gaps(rule_results, self.max_top_gaps)

            # Generate remediation summary
            logger.info("🔧 Generating remediation summary...")
            remediation_summary = self._generate_remediation_summary(rule_results)

            # Trend analysis if previous snapshot provided
            trend_data = None
            if previous_snapshot:
                logger.info("📉 Performing trend analysis...")
                trend_data = self._analyze_trends(snapshot, previous_snapshot)

            # Build complete report structure
            report = {
                'metadata': metadata.to_dict(),
                'summary_scores': overall_scores,
                'frameworks': {fw: summary.to_dict() for fw, summary in framework_summaries.items()},
                'categories': [cat.to_dict() for cat in category_summaries],
                'rules': [rule.to_dict() for rule in rule_results],
                'top_gaps': top_gaps,
                'remediation_summary': remediation_summary,
                'trend_data': trend_data,
                'aggregations': self._generate_aggregations(rule_results, framework_summaries)
            }

            # Generate outputs
            logger.info("💾 Generating output files...")
            output_files = self._generate_all_outputs(report, run_dir)

            # Create summary for API response
            summary = self._create_api_summary(report, output_files)

            logger.info(f"✅ Report generation complete: {run_id}")

            return {
                'success': True,
                'run_id': run_id,
                'summary': summary,
                'files': output_files,
                'report_data': report
            }

        except Exception as e:
            logger.error(f"❌ Report generation failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'run_id': run_id
            }

    def _extract_metadata(self, snapshot: Dict[str, Any], run_id: str) -> ReportMetadata:
        """Extract metadata from snapshot."""
        company_name = "Unknown Organization"
        assessment_date = datetime.now()

        # Try to extract from various locations
        if 'dashboard_summary' in snapshot:
            dash = snapshot['dashboard_summary']
            if 'company' in dash and 'name' in dash['company']:
                company_name = dash['company']['name']
            if 'assessment_date' in dash:
                try:
                    assessment_date = datetime.fromisoformat(dash['assessment_date'].replace('Z', '+00:00'))
                except:
                    pass

        return ReportMetadata(
            run_id=run_id,
            generated_at=datetime.now(),
            dataset_source=snapshot.get('meta', {}).get('version', 'unknown'),
            company_name=company_name,
            assessment_date=assessment_date
        )

    def _analyze_snapshot(self, snapshot: Dict[str, Any]) -> List[RuleResult]:
        """
        Analyze snapshot and generate rule results.

        Args:
            snapshot: Compliance snapshot

        Returns:
            List of RuleResult objects
        """
        rule_results = []

        # Extract detailed frameworks data
        detailed_frameworks = snapshot.get('detailed_frameworks', {})

        for framework_name, framework_data in detailed_frameworks.items():
            # Get critical gaps (failed rules)
            critical_gaps = framework_data.get('critical_gaps', [])

            for gap in critical_gaps:
                rule_result = self._create_rule_result_from_gap(gap, framework_name)
                rule_results.append(rule_result)

        # Also check priority_issues from main snapshot
        priority_issues = snapshot.get('priority_issues', [])
        for issue in priority_issues:
            # Avoid duplicates
            rule_id = issue.get('id', '')
            if not any(r.rule_id == rule_id for r in rule_results):
                rule_result = self._create_rule_result_from_issue(issue)
                rule_results.append(rule_result)

        logger.info(f"✓ Analyzed {len(rule_results)} rule results")
        return rule_results

    def _create_rule_result_from_gap(self, gap: Dict[str, Any], framework: str) -> RuleResult:
        """Create RuleResult from a critical gap."""
        rule_id = gap.get('rule_id', 'UNKNOWN')

        # Determine status
        actual = gap.get('actual')
        expected = gap.get('expected')

        if actual is None:
            status = RuleStatus.SKIPPED
            reason = f"Data not available for field: {gap.get('field', 'unknown')}"
        elif actual == expected:
            status = RuleStatus.MET
            reason = "Control requirement met"
        else:
            status = RuleStatus.UNMET
            reason = f"Expected {expected}, but found {actual}"

        # Map severity
        severity_str = gap.get('severity', 'MEDIUM').upper()
        try:
            severity = Severity[severity_str]
        except KeyError:
            severity = Severity.MEDIUM

        # Get or create remediation
        remediation = self._get_remediation_for_rule(rule_id, gap)

        # Determine priority
        priority = self._determine_priority(severity, gap.get('weight', 1))

        return RuleResult(
            rule_id=rule_id,
            framework=framework,
            title=gap.get('description', 'Unknown Control'),
            description=gap.get('description', ''),
            category=gap.get('category', 'General'),
            status=status,
            severity=severity,
            weight=gap.get('weight', 1),
            expected=expected,
            actual=actual,
            evidence=self._format_evidence(gap),
            reason=reason,
            remediation=remediation,
            priority=priority,
            estimated_effort_hours=remediation.estimated_effort_hours if remediation else 0.0,
            field_path=gap.get('field'),
            last_checked=datetime.now()
        )

    def _create_rule_result_from_issue(self, issue: Dict[str, Any]) -> RuleResult:
        """Create RuleResult from a priority issue."""
        rule_id = issue.get('id', 'UNKNOWN')

        # Extract framework from rule_id (e.g., "CIS-1.1" -> "CIS")
        framework = rule_id.split('-')[0] if '-' in rule_id else 'UNKNOWN'

        # Determine status
        current = issue.get('current_status')
        required = issue.get('required_status')

        if current is None:
            status = RuleStatus.SKIPPED
            reason = "Data not collected"
        elif current == required:
            status = RuleStatus.MET
            reason = "Control requirement met"
        else:
            status = RuleStatus.UNMET
            reason = f"Expected {required}, but found {current}"

        # Map severity
        severity_str = issue.get('severity', 'MEDIUM').upper()
        try:
            severity = Severity[severity_str]
        except KeyError:
            severity = Severity.MEDIUM

        # Get remediation
        remediation_text = issue.get('remediation', '')
        remediation = self._create_basic_remediation(rule_id, remediation_text, severity)

        priority = self._determine_priority(severity, 1)

        return RuleResult(
            rule_id=rule_id,
            framework=framework,
            title=issue.get('title', 'Unknown Control'),
            description=issue.get('title', ''),
            category=issue.get('category', 'General'),
            status=status,
            severity=severity,
            weight=1,
            expected=required,
            actual=current,
            evidence=f"Current: {current}, Required: {required}",
            reason=reason,
            remediation=remediation,
            priority=priority,
            estimated_effort_hours=remediation.estimated_effort_hours if remediation else 0.0,
            last_checked=datetime.now()
        )

    def _get_remediation_for_rule(self, rule_id: str, gap: Dict[str, Any]) -> Optional[RemediationStep]:
        """Get detailed remediation for a rule."""
        # Check if we have a predefined remediation
        remediation_key = self._map_rule_to_remediation_key(rule_id, gap)

        if remediation_key and remediation_key in self.REMEDIATION_DATABASE:
            rem_data = self.REMEDIATION_DATABASE[remediation_key]
            return RemediationStep(
                title=rem_data['title'],
                description=rem_data['description'],
                steps=rem_data['steps'],
                commands=rem_data['commands'],
                estimated_effort_hours=rem_data['estimated_effort_hours'],
                cost_estimate=rem_data['cost_estimate'],
                priority=rem_data['priority'],
                validation_command=rem_data.get('validation_command'),
                references=rem_data.get('references', [])
            )

        # Create basic remediation from gap data
        remediation_text = gap.get('remediation', 'Review and remediate this control')
        severity_str = gap.get('severity', 'MEDIUM').upper()
        try:
            severity = Severity[severity_str]
        except KeyError:
            severity = Severity.MEDIUM

        return self._create_basic_remediation(rule_id, remediation_text, severity)

