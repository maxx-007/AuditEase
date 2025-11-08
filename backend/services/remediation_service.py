#!/usr/bin/env python3
"""
Remediation Service - Production-Grade Automated Remediation Module
===================================================================
Provides comprehensive remediation guidance, automated script generation,
playbook creation, and remediation tracking capabilities.

Features:
- Automated remediation script generation (Linux/Windows/macOS)
- Detailed remediation guidance with impact analysis
- Priority scoring and effort estimation
- Remediation playbooks (PDF/HTML/Markdown)
- Cost estimation and timeline planning
- Stakeholder identification and dependency tracking
- Testing procedures and rollback plans
- Business justification and compliance notes
"""

import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import json
from dataclasses import dataclass, asdict
from enum import Enum
import shutil

# Setup logger
logger = logging.getLogger(__name__)


class Priority(Enum):
    """Remediation priority levels."""
    P0_CRITICAL = "P0 - Critical (Fix immediately - 24-48 hours)"
    P1_HIGH = "P1 - High (Fix within 1 week)"
    P2_MEDIUM = "P2 - Medium (Fix within 1 month)"
    P3_LOW = "P3 - Low (Fix within 3 months)"


class Platform(Enum):
    """Supported platforms for script generation."""
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"


@dataclass
class RemediationGuidance:
    """Structured remediation guidance."""
    rule_id: str
    description: str
    severity: str
    priority: str
    impact_analysis: str
    remediation_steps: List[str]
    effort_estimate: str
    timeline: str
    cost_category: str
    business_justification: str
    success_criteria: List[str]
    testing_procedures: List[str]
    rollback_plan: str
    compliance_notes: Dict[str, str]
    dependencies: List[str]
    stakeholders: List[str]
    automation_available: bool
    scripts: List[Dict[str, str]]


class RemediationService:
    """
    Production-grade remediation service for compliance issues.
    
    Generates automated remediation scripts, detailed guidance,
    playbooks, and tracking capabilities.
    """
    
    def __init__(self, output_dir: str = "remediation", templates_dir: Optional[str] = None):
        """
        Initialize the Remediation Service.

        Args:
            output_dir: Directory to save remediation outputs
            templates_dir: Optional directory containing script templates
        """
        self.output_dir = Path(output_dir)
        self.scripts_dir = self.output_dir / "scripts"
        self.playbooks_dir = self.output_dir / "playbooks"
        self.templates_dir = Path(templates_dir) if templates_dir else self.output_dir / "templates"

        # Get absolute path to hardening scripts directory
        # Try multiple possible locations
        possible_paths = [
            Path(__file__).parent.parent.parent / "os-hardening scripts",  # From backend/services/
            Path.cwd() / "os-hardening scripts",  # From current working directory
            Path("os-hardening scripts")  # Relative path fallback
        ]

        self.hardening_scripts_dir = None
        for path in possible_paths:
            if path.exists() and path.is_dir():
                self.hardening_scripts_dir = path
                logger.info(f"✅ Found hardening scripts directory: {path}")
                break

        if not self.hardening_scripts_dir:
            logger.warning(f"⚠️ Hardening scripts directory not found. Tried: {possible_paths}")
            self.hardening_scripts_dir = Path("os-hardening scripts")  # Fallback
        
        # Create directories
        for dir_path in [self.output_dir, self.scripts_dir, self.playbooks_dir, self.templates_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Load script templates
        self.script_templates = self._load_script_templates()
        
        logger.info(f"Remediation Service initialized - Output: {self.output_dir}")
    
    def _load_script_templates(self) -> Dict[str, Dict[str, str]]:
        """Load remediation script templates for different platforms."""
        return {
            Platform.LINUX.value: {
                'firewall_enable': '''#!/bin/bash
# Enable and configure firewall
# Rule: {rule_id}
# Description: {description}

set -e

echo "Configuring firewall..."

# Enable UFW firewall
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH
sudo ufw allow ssh

# Allow HTTP/HTTPS if needed
# sudo ufw allow 80/tcp
# sudo ufw allow 443/tcp

# Enable firewall
sudo ufw --force enable

# Verify status
sudo ufw status verbose

echo "✅ Firewall configured successfully"
''',
                'patch_management': '''#!/bin/bash
# Setup automated patch management
# Rule: {rule_id}
# Description: {description}

set -e

echo "Setting up automated patch management..."

# Update package lists
sudo apt update

# Install unattended-upgrades
sudo apt install -y unattended-upgrades apt-listchanges

# Configure automatic updates
cat <<EOF | sudo tee /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

# Enable automatic updates
cat <<EOF | sudo tee /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

# Start and enable service
sudo systemctl enable unattended-upgrades
sudo systemctl start unattended-upgrades

echo "✅ Automated patch management configured"
''',
                'ssh_hardening': '''#!/bin/bash
# Harden SSH configuration
# Rule: {rule_id}
# Description: {description}

set -e

echo "Hardening SSH configuration..."

# Backup original config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d_%H%M%S)

# Apply secure SSH settings
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sudo sed -i 's/#X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
sudo sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config

# Set strong ciphers
echo "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" | sudo tee -a /etc/ssh/sshd_config

# Test configuration
sudo sshd -t

# Restart SSH service
sudo systemctl restart sshd

echo "✅ SSH hardened successfully"
echo "⚠️  Make sure you have SSH key authentication set up before logging out!"
''',
                'logging_setup': '''#!/bin/bash
# Setup centralized logging
# Rule: {rule_id}
# Description: {description}

set -e

echo "Setting up centralized logging..."

# Install rsyslog
sudo apt update
sudo apt install -y rsyslog

# Configure rsyslog
cat <<EOF | sudo tee /etc/rsyslog.d/50-default.conf
# Log all kernel messages
kern.*                          /var/log/kern.log

# Log authentication messages
auth,authpriv.*                 /var/log/auth.log

# Log system messages
*.*;auth,authpriv.none          /var/log/syslog

# Emergency messages to all users
*.emerg                         :omusrmsg:*
EOF

# Enable and start rsyslog
sudo systemctl enable rsyslog
sudo systemctl restart rsyslog

# Setup log rotation
cat <<EOF | sudo tee /etc/logrotate.d/rsyslog
/var/log/syslog
/var/log/auth.log
/var/log/kern.log
{
    rotate 7
    daily
    missingok
    notifempty
    compress
    delaycompress
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF

echo "✅ Centralized logging configured"
''',
                'antivirus_setup': '''#!/bin/bash
# Install and configure ClamAV antivirus
# Rule: {rule_id}
# Description: {description}

set -e

echo "Installing ClamAV antivirus..."

# Install ClamAV
sudo apt update
sudo apt install -y clamav clamav-daemon clamav-freshclam

# Stop services for initial setup
sudo systemctl stop clamav-freshclam
sudo systemctl stop clamav-daemon

# Update virus definitions
sudo freshclam

# Configure automatic updates
sudo sed -i 's/^Checks.*/Checks 24/' /etc/clamav/freshclam.conf

# Start services
sudo systemctl start clamav-freshclam
sudo systemctl enable clamav-freshclam
sudo systemctl start clamav-daemon
sudo systemctl enable clamav-daemon

# Setup daily scan cron job
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/bin/clamscan -r /home --log=/var/log/clamav/daily-scan.log") | crontab -

echo "✅ ClamAV antivirus installed and configured"
echo "Daily scans scheduled for 2 AM"
''',
                'backup_setup': '''#!/bin/bash
# Setup automated backup system
# Rule: {rule_id}
# Description: {description}

set -e

echo "Setting up automated backup system..."

# Install required tools
sudo apt update
sudo apt install -y rsync

# Create backup directory
sudo mkdir -p /backup
sudo chmod 700 /backup

# Create backup script
cat <<'SCRIPT' | sudo tee /usr/local/bin/backup.sh
#!/bin/bash
BACKUP_DIR="/backup"
DATE=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/backup.log"

echo "[$DATE] Starting backup..." >> $LOG_FILE

# Backup important directories
rsync -av --delete /etc/ $BACKUP_DIR/etc_$DATE/ >> $LOG_FILE 2>&1
rsync -av --delete /home/ $BACKUP_DIR/home_$DATE/ >> $LOG_FILE 2>&1
rsync -av --delete /var/www/ $BACKUP_DIR/www_$DATE/ >> $LOG_FILE 2>&1

# Keep only last 7 days of backups
find $BACKUP_DIR -type d -mtime +7 -exec rm -rf {} +

echo "[$DATE] Backup completed" >> $LOG_FILE
SCRIPT

sudo chmod +x /usr/local/bin/backup.sh

# Setup daily backup cron job
(crontab -l 2>/dev/null; echo "0 1 * * * /usr/local/bin/backup.sh") | crontab -

echo "✅ Automated backup configured"
echo "Daily backups scheduled for 1 AM"
''',
                'access_control': '''#!/bin/bash
# Configure access control and user permissions
# Rule: {rule_id}
# Description: {description}

set -e

echo "Configuring access control..."

# Set secure umask
echo "umask 027" | sudo tee -a /etc/profile

# Configure password policies
sudo apt install -y libpam-pwquality

cat <<EOF | sudo tee /etc/security/pwquality.conf
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
EOF

# Set password aging
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
sudo sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs

# Disable unused accounts
sudo usermod -L nobody
sudo usermod -L guest

echo "✅ Access control configured"
''',
                'encryption_setup': '''#!/bin/bash
# Setup encryption for data at rest
# Rule: {rule_id}
# Description: {description}

set -e

echo "Setting up encryption..."

# Install cryptsetup
sudo apt update
sudo apt install -y cryptsetup

# Enable LUKS encryption for new volumes
# Note: This is a template - adjust for your specific volumes

echo "✅ Encryption tools installed"
echo "⚠️  Manual configuration required for specific volumes"
echo "Refer to: https://wiki.archlinux.org/title/Dm-crypt/Device_encryption"
''',
            },
            Platform.WINDOWS.value: {
                'firewall_enable': '''# PowerShell script to enable Windows Firewall
# Rule: {rule_id}
# Description: {description}

Write-Host "Configuring Windows Firewall..." -ForegroundColor Green

# Enable Windows Firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Set default inbound action to Block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# Set default outbound action to Allow
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Enable logging
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True

Write-Host "✅ Windows Firewall configured successfully" -ForegroundColor Green
''',
                'patch_management': '''# PowerShell script for Windows Update configuration
# Rule: {rule_id}
# Description: {description}

Write-Host "Configuring Windows Update..." -ForegroundColor Green

# Enable automatic updates
$AutoUpdate = (New-Object -ComObject Microsoft.Update.AutoUpdate)
$AutoUpdate.Settings.NotificationLevel = 4  # Auto download and install

# Configure update settings
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update" -Name "AUOptions" -Value 4

# Install PSWindowsUpdate module
Install-Module PSWindowsUpdate -Force -Confirm:$false

# Check for updates
Get-WindowsUpdate

Write-Host "✅ Windows Update configured" -ForegroundColor Green
''',
                'antivirus_check': '''# PowerShell script to verify Windows Defender
# Rule: {rule_id}
# Description: {description}

Write-Host "Checking Windows Defender..." -ForegroundColor Green

# Enable Windows Defender
Set-MpPreference -DisableRealtimeMonitoring $false

# Update definitions
Update-MpSignature

# Run quick scan
Start-MpScan -ScanType QuickScan

# Enable cloud protection
Set-MpPreference -MAPSReporting Advanced

Write-Host "✅ Windows Defender configured" -ForegroundColor Green
''',
            }
        }
    
    def generate_remediation_guidance(
        self,
        finding: Dict[str, Any],
        framework: str = "CIS"
    ) -> RemediationGuidance:
        """
        Generate comprehensive remediation guidance for a finding.

        Args:
            finding: The compliance finding/rule that failed
            framework: The compliance framework (CIS, ISO27001, RBI)

        Returns:
            RemediationGuidance object with complete guidance
        """
        try:
            # Validate input
            if not finding:
                raise ValueError("Finding cannot be None or empty")

            if not isinstance(finding, dict):
                raise ValueError(f"Finding must be a dictionary, got {type(finding)}")

            # Extract fields with safe defaults
            rule_id = finding.get('rule_id', 'UNKNOWN')
            if not rule_id or rule_id == 'UNKNOWN':
                logger.warning(f"Finding missing rule_id: {finding}")

            severity = finding.get('severity', 'MEDIUM')
            # Normalize severity to uppercase
            severity = severity.upper() if severity else 'MEDIUM'
            if severity not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                logger.warning(f"Invalid severity '{severity}' for {rule_id}, defaulting to MEDIUM")
                severity = 'MEDIUM'

            category = finding.get('category', 'General')
            if not category:
                category = 'General'
            
            # Calculate priority
            priority = self._calculate_priority(severity, finding.get('weight', 1))
            
            # Generate impact analysis
            impact = self._generate_impact_analysis(finding, framework)
            
            # Generate remediation steps
            steps = self._generate_remediation_steps(finding)
            
            # Estimate effort and timeline
            effort = self._estimate_effort(category, severity)
            timeline = self._estimate_timeline(severity)
            
            # Get cost category
            cost = self._estimate_cost(severity, category)
            
            # Generate business justification
            justification = self._generate_business_justification(finding, framework)
            
            # Generate success criteria
            success_criteria = self._generate_success_criteria(finding)
            
            # Generate testing procedures
            testing = self._generate_testing_procedures(finding)
            
            # Generate rollback plan
            rollback = self._generate_rollback_plan(finding)
            
            # Generate compliance notes
            compliance_notes = self._generate_compliance_notes(finding, framework)
            
            # Identify dependencies
            dependencies = self._identify_dependencies(finding)
            
            # Identify stakeholders
            stakeholders = self._identify_stakeholders(category)
            
            # Get applicable scripts
            scripts = self._get_applicable_scripts(finding)
            
            guidance = RemediationGuidance(
                rule_id=rule_id,
                description=finding.get('description', 'N/A'),
                severity=severity,
                priority=priority,
                impact_analysis=impact,
                remediation_steps=steps,
                effort_estimate=effort,
                timeline=timeline,
                cost_category=cost,
                business_justification=justification,
                success_criteria=success_criteria,
                testing_procedures=testing,
                rollback_plan=rollback,
                compliance_notes=compliance_notes,
                dependencies=dependencies,
                stakeholders=stakeholders,
                automation_available=len(scripts) > 0,
                scripts=scripts
            )
            
            logger.debug(f"Generated remediation guidance for {rule_id}")
            return guidance
            
        except Exception as e:
            logger.error(f"Error generating remediation guidance: {e}", exc_info=True)
            raise
    
    def generate_remediation_scripts(
        self,
        findings: List[Dict[str, Any]],
        platform: Platform = Platform.LINUX
    ) -> Dict[str, Path]:
        """
        Generate automated remediation scripts for findings.
        
        Args:
            findings: List of compliance findings
            platform: Target platform for scripts
            
        Returns:
            Dictionary mapping rule_id to script file path
        """
        try:
            logger.info(f"Generating remediation scripts for {platform.value}...")
            
            generated_scripts = {}
            platform_dir = self.scripts_dir / platform.value
            platform_dir.mkdir(parents=True, exist_ok=True)
            
            for finding in findings:
                if finding.get('status') not in ['FAIL', 'MISSING_DATA']:
                    continue
                
                rule_id = finding.get('rule_id', 'UNKNOWN')
                category = finding.get('category', 'General').lower()
                
                # Find matching template
                template_key = self._match_template(category, finding)
                
                if template_key and platform.value in self.script_templates:
                    template = self.script_templates[platform.value].get(template_key)
                    
                    if template:
                        # Generate script from template
                        script_content = template.format(
                            rule_id=rule_id,
                            description=finding.get('description', 'N/A')
                        )
                        
                        # Save script
                        script_file = platform_dir / f"{rule_id.replace('.', '_')}_{template_key}.sh"
                        script_file.write_text(script_content)
                        script_file.chmod(0o755)  # Make executable
                        
                        generated_scripts[rule_id] = script_file
                        logger.debug(f"Generated script for {rule_id}: {script_file}")
            
            # Generate master script
            if generated_scripts:
                self._generate_master_script(generated_scripts, platform_dir, platform)
            
            logger.info(f"✅ Generated {len(generated_scripts)} remediation scripts")
            return generated_scripts
            
        except Exception as e:
            logger.error(f"Error generating scripts: {e}", exc_info=True)
            raise

    def get_comprehensive_hardening_script(self, platform: Platform) -> Path:
        """Get the comprehensive hardening script for the platform."""
        script_mapping = {
            Platform.LINUX: "linux_hardening_compliance.sh",
            Platform.WINDOWS: "Windows_Hardening_Compliance.ps1", 
            Platform.MACOS: "macos_hardening_compliance.sh"
        }
        
        script_name = script_mapping.get(platform)
        if not script_name:
            raise ValueError(f"No hardening script available for platform: {platform.value}")
            
        source_script = self.hardening_scripts_dir / script_name
        if not source_script.exists():
            raise FileNotFoundError(f"Hardening script not found: {source_script}")
            
        return source_script

    def generate_remediation_scripts_zip(self, platform: Platform) -> Path:
        """Generate a ZIP file containing both template-based and comprehensive hardening scripts."""
        try:
            logger.info(f"Generating remediation scripts ZIP for {platform.value}...")

            # Validate platform
            if not isinstance(platform, Platform):
                raise ValueError(f"Invalid platform type: {type(platform)}")

            # Create platform directory
            platform_dir = self.scripts_dir / platform.value
            platform_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created platform directory: {platform_dir}")

            # Copy comprehensive hardening script
            try:
                hardening_script = self.get_comprehensive_hardening_script(platform)
                dest_hardening = platform_dir / hardening_script.name
                shutil.copy2(hardening_script, dest_hardening)
                logger.info(f"✅ Added comprehensive hardening script: {dest_hardening.name}")
            except FileNotFoundError as e:
                logger.error(f"Hardening script not found: {e}")
                raise FileNotFoundError(
                    f"Hardening script for {platform.value} not found in os-hardening scripts/ directory"
                )

            # Create ZIP file
            zip_path = self.scripts_dir / f"remediation_scripts_{platform.value}.zip"

            # Remove old ZIP if exists
            if zip_path.exists():
                zip_path.unlink()
                logger.debug(f"Removed old ZIP file: {zip_path}")

            # Create new ZIP
            shutil.make_archive(str(zip_path.with_suffix('')), 'zip', platform_dir)

            if not zip_path.exists():
                raise FileNotFoundError(f"Failed to create ZIP file: {zip_path}")

            logger.info(f"✅ Generated ZIP file: {zip_path} ({zip_path.stat().st_size} bytes)")
            return zip_path

        except Exception as e:
            logger.error(f"❌ Failed to generate scripts ZIP for {platform.value}: {e}", exc_info=True)
            raise

    def _generate_master_script(
        self,
        scripts: Dict[str, Path],
        output_dir: Path,
        platform: Platform
    ):
        """Generate a master script to run all remediation scripts."""
        try:
            master_script = output_dir / "run_all_remediation.sh"
            
            content = f"""#!/bin/bash
# Master Remediation Script
# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# Platform: {platform.value}

set -e

echo "========================================"
echo "Starting Compliance Remediation"
echo "========================================"
echo ""

"""
            
            for rule_id, script_path in scripts.items():
                content += f"""
echo "Running remediation for {rule_id}..."
bash {script_path.name}
echo "✅ Completed {rule_id}"
echo ""
"""
            
            content += """
echo "========================================"
echo "All Remediation Scripts Completed"
echo "========================================"
"""
            
            master_script.write_text(content)
            master_script.chmod(0o755)
            
            logger.debug(f"Master script generated: {master_script}")
            
        except Exception as e:
            logger.error(f"Error generating master script: {e}", exc_info=True)
    
    # Helper methods
    def _calculate_priority(self, severity: str, weight: int) -> str:
        """Calculate remediation priority."""
        if severity == 'CRITICAL' or weight >= 9:
            return Priority.P0_CRITICAL.value
        elif severity == 'HIGH' or weight >= 7:
            return Priority.P1_HIGH.value
        elif severity == 'MEDIUM' or weight >= 5:
            return Priority.P2_MEDIUM.value
        else:
            return Priority.P3_LOW.value
    
    def _generate_impact_analysis(self, finding: Dict[str, Any], framework: str) -> str:
        """Generate impact analysis for the finding."""
        severity = finding.get('severity', 'MEDIUM')
        category = finding.get('category', 'General')
        
        impact_templates = {
            'CRITICAL': f"Critical security vulnerability in {category}. Immediate exploitation risk with potential for complete system compromise. Non-compliance with {framework} framework exposes organization to significant regulatory penalties.",
            'HIGH': f"High-risk security gap in {category}. Significant potential for unauthorized access or data breach. Failure to address violates {framework} requirements and increases audit risk.",
            'MEDIUM': f"Moderate security concern in {category}. May lead to information disclosure or limited system access. Partial compliance with {framework} framework.",
            'LOW': f"Low-impact security issue in {category}. Minimal risk but should be addressed for best practices and full {framework} compliance."
        }
        
        return impact_templates.get(severity, "Security issue requiring attention.")
    
    def _generate_remediation_steps(self, finding: Dict[str, Any]) -> List[str]:
        """Generate detailed remediation steps."""
        category = finding.get('category', 'General')
        
        # Generic steps - can be enhanced with category-specific logic
        steps = [
            "Review current configuration and document baseline",
            "Identify affected systems and components",
            "Plan remediation during maintenance window",
            "Implement required changes following change management process",
            "Verify changes through testing",
            "Update documentation and compliance records",
            "Monitor for any issues post-implementation"
        ]
        
        return steps
    
    def _estimate_effort(self, category: str, severity: str) -> str:
        """Estimate effort required for remediation."""
        effort_map = {
            ('CRITICAL', 'Access Control'): 'High (16-24 hours)',
            ('CRITICAL', 'Network Security'): 'High (16-24 hours)',
            ('HIGH', 'Access Control'): 'Medium (8-16 hours)',
            ('HIGH', 'Network Security'): 'Medium (8-16 hours)',
            ('MEDIUM', 'Configuration Management'): 'Low (2-4 hours)',
            ('LOW', 'Configuration Management'): 'Low (1-2 hours)',
        }
        
        return effort_map.get((severity, category), 'Medium (4-8 hours)')
    
    def _estimate_timeline(self, severity: str) -> str:
        """Estimate timeline for remediation."""
        timeline_map = {
            'CRITICAL': '24-48 hours',
            'HIGH': '1 week',
            'MEDIUM': '1 month',
            'LOW': '3 months'
        }
        return timeline_map.get(severity, '1 month')
    
    def _estimate_cost(self, severity: str, category: str) -> str:
        """Estimate cost category for remediation."""
        if severity in ['CRITICAL', 'HIGH']:
            return 'High Priority ($$-$$$)'
        elif category in ['Asset Management', 'Logging and Monitoring']:
            return 'Medium-High ($-$$)'
        else:
            return 'Medium ($)'
    
    def _generate_business_justification(self, finding: Dict[str, Any], framework: str) -> str:
        """Generate business justification for remediation."""
        category = finding.get('category', 'General')
        severity = finding.get('severity', 'MEDIUM')
        
        justification = f"Addressing this {severity.lower()} severity issue in {category} is critical for maintaining {framework} compliance and reducing organizational risk. "
        
        if severity in ['CRITICAL', 'HIGH']:
            justification += "Immediate action prevents potential security breaches, regulatory penalties, and reputational damage. "
        
        justification += "Investment in remediation demonstrates due diligence and strengthens overall security posture."
        
        return justification
    
    def _generate_success_criteria(self, finding: Dict[str, Any]) -> List[str]:
        """Generate success criteria for remediation."""
        return [
            "Configuration change successfully implemented",
            "Compliance check passes validation",
            "No adverse impact on system functionality",
            "Documentation updated and approved",
            "Stakeholders notified of completion"
        ]
    
    def _generate_testing_procedures(self, finding: Dict[str, Any]) -> List[str]:
        """Generate testing procedures for remediation."""
        return [
            "Verify configuration changes in test environment",
            "Run compliance validation checks",
            "Perform functional testing of affected systems",
            "Conduct security testing to confirm fix",
            "Validate with compliance framework requirements"
        ]
    
    def _generate_rollback_plan(self, finding: Dict[str, Any]) -> str:
        """Generate rollback plan for remediation."""
        return "If issues arise: 1) Document the problem, 2) Restore from configuration backup, 3) Review and adjust remediation approach, 4) Re-test in isolated environment before re-attempting."
    
    def _generate_compliance_notes(self, finding: Dict[str, Any], framework: str) -> Dict[str, str]:
        """Generate compliance-specific notes."""
        return {
            framework: f"Addresses {framework} requirement {finding.get('rule_id', 'N/A')}",
            "Audit_Trail": "Maintain documentation of all changes for audit purposes",
            "Verification": "Re-run compliance scan after implementation to verify fix"
        }
    
    def _identify_dependencies(self, finding: Dict[str, Any]) -> List[str]:
        """Identify dependencies for remediation."""
        category = finding.get('category', 'General')
        
        dependency_map = {
            'Network Security': ['Firewall configuration', 'Network topology', 'Security groups'],
            'Access Control': ['User directory', 'Authentication system', 'Authorization policies'],
            'Logging and Monitoring': ['Log aggregation system', 'SIEM platform', 'Storage capacity'],
        }
        
        return dependency_map.get(category, ['System configuration', 'Change management approval'])
    
    def _identify_stakeholders(self, category: str) -> List[str]:
        """Identify stakeholders for remediation."""
        stakeholder_map = {
            'Access Control': ['Security Team', 'Identity Management', 'Compliance Officer'],
            'Network Security': ['Network Team', 'Security Team', 'Infrastructure'],
            'Logging and Monitoring': ['SOC Team', 'Security Team', 'IT Operations'],
            'Configuration Management': ['System Administrators', 'DevOps Team'],
        }
        
        return stakeholder_map.get(category, ['IT Team', 'Security Team', 'Compliance Officer'])
    
    def _get_applicable_scripts(self, finding: Dict[str, Any]) -> List[Dict[str, str]]:
        """Get applicable automation scripts for the finding."""
        category = finding.get('category', 'General').lower()
        rule_id = finding.get('rule_id', '').lower()
        
        scripts = []
        
        # Map categories to script templates
        if 'firewall' in category or 'network' in category:
            scripts.append({'name': 'firewall_enable.sh', 'platform': 'linux', 'type': 'firewall_enable'})
        elif 'patch' in rule_id or 'update' in rule_id:
            scripts.append({'name': 'patch_management.sh', 'platform': 'linux', 'type': 'patch_management'})
        elif 'ssh' in rule_id or 'remote' in category:
            scripts.append({'name': 'ssh_hardening.sh', 'platform': 'linux', 'type': 'ssh_hardening'})
        elif 'log' in category or 'audit' in category:
            scripts.append({'name': 'logging_setup.sh', 'platform': 'linux', 'type': 'logging_setup'})
        elif 'antivirus' in rule_id or 'malware' in rule_id:
            scripts.append({'name': 'antivirus_setup.sh', 'platform': 'linux', 'type': 'antivirus_setup'})
        elif 'backup' in category:
            scripts.append({'name': 'backup_setup.sh', 'platform': 'linux', 'type': 'backup_setup'})
        elif 'access' in category:
            scripts.append({'name': 'access_control.sh', 'platform': 'linux', 'type': 'access_control'})
        elif 'encrypt' in rule_id:
            scripts.append({'name': 'encryption_setup.sh', 'platform': 'linux', 'type': 'encryption_setup'})
        
        return scripts
    
    def _match_template(self, category: str, finding: Dict[str, Any]) -> Optional[str]:
        """Match finding to script template."""
        rule_id = finding.get('rule_id', '').lower()
        
        if 'firewall' in category or 'firewall' in rule_id:
            return 'firewall_enable'
        elif 'patch' in rule_id or 'update' in rule_id:
            return 'patch_management'
        elif 'ssh' in rule_id:
            return 'ssh_hardening'
        elif 'log' in category:
            return 'logging_setup'
        elif 'antivirus' in rule_id:
            return 'antivirus_setup'
        elif 'backup' in category:
            return 'backup_setup'
        elif 'access' in category:
            return 'access_control'
        elif 'encrypt' in rule_id:
            return 'encryption_setup'
        
        return None


# Export main class
__all__ = ['RemediationService', 'RemediationGuidance', 'Priority', 'Platform']

