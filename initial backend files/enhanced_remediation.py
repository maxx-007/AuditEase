#!/usr/bin/env python3
"""
Enhanced Remediation Module for Compliance Audit Engine
Provides detailed remediation guidance and automated script generation
"""

import os
import json
import logging
from pathlib import Path
from datetime import datetime
import re
import shutil
import subprocess
from typing import Dict, List, Any, Optional, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EnhancedRemediation:
    """
    Enhanced Remediation Module for Compliance Audit Engine
    Provides detailed remediation guidance and automated script generation
    """
    
    def __init__(self, output_dir="compliance_output", templates_dir=None):
        """
        Initialize the remediation module
        
        Args:
            output_dir: Directory to save remediation outputs
            templates_dir: Directory containing remediation script templates
        """
        self.output_dir = Path(output_dir)
        self.scripts_dir = self.output_dir / "remediation_scripts"
        self.templates_dir = Path(templates_dir) if templates_dir else Path(__file__).parent / "templates"
        
        # Create output directories
        self.output_dir.mkdir(exist_ok=True)
        self.scripts_dir.mkdir(exist_ok=True)
        
        # Risk levels and their weights
        self.risk_levels = {
            'CRITICAL': {'weight': 100, 'color': '#FF0000', 'timeframe': '24 hours'},
            'HIGH': {'weight': 75, 'color': '#FF9900', 'timeframe': '1 week'},
            'MEDIUM': {'weight': 50, 'color': '#FFFF00', 'timeframe': '1 month'},
            'LOW': {'weight': 25, 'color': '#00FF00', 'timeframe': '3 months'}
        }
        
        # Load remediation templates
        self.remediation_templates = self._load_remediation_templates()
        
        # Category-specific remediation guidance
        self.category_guidance = {
            'Access Control': {
                'impact': 'Unauthorized access to systems and data, potential data breaches',
                'verification': 'Access control audit, privilege review',
                'business_justification': 'Prevents unauthorized access to sensitive systems and data, reducing risk of data breaches and regulatory penalties.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 1.2
            },
            'Asset Management': {
                'impact': 'Inability to track and secure organizational assets',
                'verification': 'Asset inventory verification',
                'business_justification': 'Ensures visibility and control over all organizational assets, critical for security monitoring and compliance.',
                'effort': 'High (1-2 days)',
                'priority_modifier': 1.0
            },
            'Configuration Management': {
                'impact': 'System vulnerabilities due to insecure configurations',
                'verification': 'Configuration review, security scanning',
                'business_justification': 'Ensures systems are securely configured according to best practices and compliance requirements.',
                'effort': 'Low (1-2 hours)',
                'priority_modifier': 1.1
            },
            'Network Security': {
                'impact': 'Network-based attacks and unauthorized access',
                'verification': 'Network scanning, firewall rule review',
                'business_justification': 'Protects against network-based attacks and unauthorized access, maintaining business operations integrity.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 1.3
            },
            'Logging and Monitoring': {
                'impact': 'Inability to detect and respond to security incidents',
                'verification': 'Log review, monitoring system check',
                'business_justification': 'Enables detection of security incidents and provides audit trail for compliance requirements.',
                'effort': 'High (1-2 days)',
                'priority_modifier': 1.2
            },
            'Vulnerability Management': {
                'impact': 'Exploitation of known vulnerabilities',
                'verification': 'Vulnerability scanning',
                'business_justification': 'Reduces attack surface and prevents exploitation of known vulnerabilities.',
                'effort': 'Medium (2-4 hours)',
                'priority_modifier': 1.4
            },
            'Incident Response': {
                'impact': 'Delayed or ineffective response to security incidents',
                'verification': 'Incident response drill',
                'business_justification': 'Enables rapid and effective response to security incidents, minimizing impact.',
                'effort': 'High (2-3 days)',
                'priority_modifier': 1.3
            },
            'Business Continuity': {
                'impact': 'Extended downtime and data loss during incidents',
                'verification': 'Business continuity test',
                'business_justification': 'Ensures business operations can continue during and after security incidents.',
                'effort': 'Very High (1-2 weeks)',
                'priority_modifier': 1.1
            },
            'Data Protection': {
                'impact': 'Data breaches and regulatory non-compliance',
                'verification': 'Data protection assessment',
                'business_justification': 'Protects sensitive data from unauthorized access and ensures regulatory compliance.',
                'effort': 'High (1-2 days)',
                'priority_modifier': 1.5
            },
            'Physical Security': {
                'impact': 'Unauthorized physical access to systems and data',
                'verification': 'Physical security assessment',
                'business_justification': 'Prevents unauthorized physical access to critical systems and data.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 1.0
            },
            'Information Security Policies': {
                'impact': 'Inconsistent security practices and regulatory non-compliance',
                'verification': 'Policy review',
                'business_justification': 'Provides framework for consistent security practices and regulatory compliance.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 0.9
            },
            'Human Resource Security': {
                'impact': 'Insider threats and unauthorized access',
                'verification': 'HR process review',
                'business_justification': 'Reduces risk of insider threats and ensures personnel understand security responsibilities.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 0.9
            },
            'Cryptography': {
                'impact': 'Data exposure and integrity issues',
                'verification': 'Cryptographic implementation review',
                'business_justification': 'Protects confidentiality and integrity of sensitive data.',
                'effort': 'High (1-2 days)',
                'priority_modifier': 1.2
            },
            'Operations Security': {
                'impact': 'Operational disruptions and security incidents',
                'verification': 'Operational procedures review',
                'business_justification': 'Ensures secure and reliable operation of information processing facilities.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 1.0
            },
            'Email and Web Browser Protection': {
                'impact': 'Malware infections and phishing attacks',
                'verification': 'Email and browser security review',
                'business_justification': 'Protects against common attack vectors like phishing and malware.',
                'effort': 'Low (1-2 hours)',
                'priority_modifier': 1.1
            },
            'Malware Defense': {
                'impact': 'Malware infections and data compromise',
                'verification': 'Anti-malware system review',
                'business_justification': 'Prevents malware infections that could compromise systems and data.',
                'effort': 'Medium (2-4 hours)',
                'priority_modifier': 1.3
            },
            'Data Recovery': {
                'impact': 'Data loss and extended recovery time',
                'verification': 'Backup and recovery test',
                'business_justification': 'Ensures ability to recover from data loss incidents and ransomware attacks.',
                'effort': 'High (1-2 days)',
                'priority_modifier': 1.2
            },
            'Secure Configuration': {
                'impact': 'System vulnerabilities and security weaknesses',
                'verification': 'Configuration audit',
                'business_justification': 'Reduces attack surface by eliminating security misconfigurations.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 1.2
            },
            'Network Ports and Protocols': {
                'impact': 'Unauthorized network access and service exploitation',
                'verification': 'Port scanning, service enumeration',
                'business_justification': 'Limits attack surface by controlling network services and communications.',
                'effort': 'Medium (2-4 hours)',
                'priority_modifier': 1.1
            },
            'Information Classification': {
                'impact': 'Improper handling of sensitive information',
                'verification': 'Information classification audit',
                'business_justification': 'Ensures appropriate protection of information based on its sensitivity.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 0.9
            },
            'Media Handling': {
                'impact': 'Data leakage through removable media',
                'verification': 'Media handling process review',
                'business_justification': 'Prevents data leakage through improper media handling.',
                'effort': 'Low (1-2 hours)',
                'priority_modifier': 0.8
            },
            'User Access Management': {
                'impact': 'Unauthorized access to systems and applications',
                'verification': 'User access review',
                'business_justification': 'Ensures only authorized users have appropriate access to systems.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 1.2
            },
            'System and Application Access Control': {
                'impact': 'Unauthorized access to system functions',
                'verification': 'Application access control review',
                'business_justification': 'Restricts access to system and application functions based on least privilege.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 1.1
            },
            'Equipment Security': {
                'impact': 'Physical damage or theft of equipment',
                'verification': 'Equipment security assessment',
                'business_justification': 'Protects physical assets from damage, theft, or unauthorized access.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 0.9
            },
            'Mobile Devices and Teleworking': {
                'impact': 'Data leakage through mobile devices',
                'verification': 'Mobile device security assessment',
                'business_justification': 'Secures information accessed through mobile devices and remote work.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 1.0
            },
            'Third Party Risk': {
                'impact': 'Security breaches through third-party connections',
                'verification': 'Vendor security assessment',
                'business_justification': 'Manages security risks from third-party relationships and supply chain.',
                'effort': 'High (1-2 days)',
                'priority_modifier': 1.1
            },
            'Training and Awareness': {
                'impact': 'Human errors leading to security incidents',
                'verification': 'Security awareness assessment',
                'business_justification': 'Reduces human error and builds security-conscious culture.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 0.9
            },
            'Endpoint Security': {
                'impact': 'Endpoint compromise and data breaches',
                'verification': 'Endpoint security assessment',
                'business_justification': 'Protects endpoints from compromise and prevents data breaches.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 1.2
            },
            'Security Monitoring': {
                'impact': 'Undetected security incidents',
                'verification': 'Security monitoring review',
                'business_justification': 'Enables detection and response to security incidents.',
                'effort': 'High (1-2 days)',
                'priority_modifier': 1.3
            },
            'Application Security': {
                'impact': 'Application vulnerabilities and data breaches',
                'verification': 'Application security assessment',
                'business_justification': 'Prevents exploitation of application vulnerabilities.',
                'effort': 'High (1-2 days)',
                'priority_modifier': 1.3
            },
            'Information Security Governance': {
                'impact': 'Ineffective security management and oversight',
                'verification': 'Governance structure review',
                'business_justification': 'Ensures effective management and oversight of information security.',
                'effort': 'High (1-2 days)',
                'priority_modifier': 1.0
            },
            'User Responsibilities': {
                'impact': 'Security incidents due to user negligence',
                'verification': 'User awareness assessment',
                'business_justification': 'Ensures users understand and fulfill their security responsibilities.',
                'effort': 'Low (1-2 hours)',
                'priority_modifier': 0.9
            },
            'Organization of Information Security': {
                'impact': 'Unclear security roles and responsibilities',
                'verification': 'Security organization review',
                'business_justification': 'Establishes clear security roles and responsibilities.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 0.9
            },
            'General': {
                'impact': 'Various security weaknesses',
                'verification': 'General security assessment',
                'business_justification': 'Improves overall security posture and compliance standing.',
                'effort': 'Medium (4-8 hours)',
                'priority_modifier': 1.0
            }
        }
        
        # Framework-specific guidance
        self.framework_guidance = {
            'CIS': {
                'reference_url': 'https://www.cisecurity.org/controls/',
                'priority_modifier': 1.1,
                'regulatory_impact': 'Medium'
            },
            'ISO27001': {
                'reference_url': 'https://www.iso.org/isoiec-27001-information-security.html',
                'priority_modifier': 1.0,
                'regulatory_impact': 'High'
            },
            'RBI': {
                'reference_url': 'https://www.rbi.org.in/Scripts/NotificationUser.aspx?Id=11494',
                'priority_modifier': 1.3,
                'regulatory_impact': 'Critical'
            }
        }
    
    def _load_remediation_templates(self) -> Dict[str, Dict[str, Dict[str, str]]]:
        """
        Load remediation script templates from files or define inline
        
        Returns:
            Dictionary of remediation templates by platform and category
        """
        # Default templates defined inline
        templates = {
            'linux': {
                'firewall': {
                    'name': 'enable_configure_firewall.sh',
                    'description': 'Enable and configure UFW firewall with secure defaults',
                    'content': '''#!/bin/bash
# Enable and configure UFW firewall
# This script configures the Uncomplicated Firewall (UFW) with secure defaults
# It will reset any existing configuration, so review before running

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

echo "[+] Configuring UFW firewall with secure defaults..."

# Reset UFW to default state
echo "[+] Resetting UFW to default state..."
ufw --force reset

# Set default policies
echo "[+] Setting default deny policies..."
ufw default deny incoming
ufw default allow outgoing

# Allow SSH (modify port if your SSH runs on non-standard port)
echo "[+] Allowing SSH connections..."
ufw allow ssh

# Optional: Allow other necessary services
# Uncomment as needed:
# ufw allow 80/tcp    # HTTP
# ufw allow 443/tcp   # HTTPS
# ufw allow 53/udp    # DNS

# Enable the firewall
echo "[+] Enabling UFW firewall..."
ufw --force enable

# Show status
echo "[+] Firewall configuration complete. Current status:"
ufw status verbose

echo "[+] Firewall configuration complete."
echo "[!] IMPORTANT: Ensure you have not locked yourself out of remote access."
echo "    If connecting remotely, verify SSH access still works before closing this session."
'''
                },
                'patch_management': {
                    'name': 'setup_automatic_updates.sh',
                    'description': 'Configure automatic security updates',
                    'content': '''#!/bin/bash
# Automated patch management setup
# This script configures automatic security updates on Debian/Ubuntu systems

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

echo "[+] Setting up automatic security updates..."

# Detect distribution
if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    echo "[+] Detected Debian/Ubuntu system"
    
    # Install unattended-upgrades package
    echo "[+] Installing unattended-upgrades package..."
    apt update
    apt install -y unattended-upgrades apt-listchanges
    
    # Configure unattended-upgrades
    echo "[+] Configuring unattended-upgrades..."
    cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

    cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}";
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Mail "root";
Unattended-Upgrade::MailReport "on-change";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOF

    # Enable and start service
    echo "[+] Enabling and starting unattended-upgrades service..."
    systemctl enable unattended-upgrades
    systemctl restart unattended-upgrades
    
    # Test configuration
    echo "[+] Testing unattended-upgrades configuration..."
    unattended-upgrade --dry-run --debug
    
elif [ -f /etc/redhat-release ]; then
    # RHEL/CentOS/Fedora
    echo "[+] Detected RHEL/CentOS/Fedora system"
    
    # Install dnf-automatic
    echo "[+] Installing dnf-automatic package..."
    dnf install -y dnf-automatic
    
    # Configure automatic updates
    echo "[+] Configuring automatic updates..."
    sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
    
    # Enable and start service
    echo "[+] Enabling and starting dnf-automatic service..."
    systemctl enable --now dnf-automatic.timer
    
    # Show status
    echo "[+] Automatic updates configuration complete. Current status:"
    systemctl status dnf-automatic.timer
else
    echo "[!] Unsupported distribution. This script supports Debian/Ubuntu and RHEL/CentOS/Fedora."
    exit 1
fi

echo "[+] Automatic security updates have been configured successfully."
echo "[+] The system will now automatically install security updates."
'''
                },
                'secure_ssh': {
                    'name': 'secure_ssh_configuration.sh',
                    'description': 'Secure SSH server configuration',
                    'content': '''#!/bin/bash
# Secure SSH configuration
# This script hardens the SSH server configuration

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

echo "[+] Securing SSH server configuration..."

# Backup original configuration
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_FILE="${SSHD_CONFIG}.backup-$(date +%Y%m%d-%H%M%S)"

echo "[+] Creating backup of SSH configuration at ${BACKUP_FILE}"
cp $SSHD_CONFIG $BACKUP_FILE

# Function to set or update SSH configuration parameters
update_ssh_config() {
    local param="$1"
    local value="$2"
    
    # Check if parameter exists
    if grep -q "^#*\\s*${param}" $SSHD_CONFIG; then
        # Parameter exists, update it
        sed -i "s/^#*\\s*${param}.*/${param} ${value}/" $SSHD_CONFIG
    else
        # Parameter doesn't exist, add it
        echo "${param} ${value}" >> $SSHD_CONFIG
    fi
}

echo "[+] Updating SSH configuration parameters..."

# Disable root login
update_ssh_config "PermitRootLogin" "no"

# Use SSH protocol 2
update_ssh_config "Protocol" "2"

# Disable password authentication (use key-based auth)
# Uncomment this line if you have set up key-based authentication
# update_ssh_config "PasswordAuthentication" "no"

# Disable empty passwords
update_ssh_config "PermitEmptyPasswords" "no"

# Disable X11 forwarding
update_ssh_config "X11Forwarding" "no"

# Set maximum authentication attempts
update_ssh_config "MaxAuthTries" "4"

# Enable strict mode checking
update_ssh_config "StrictModes" "yes"

# Set idle timeout (5 minutes)
update_ssh_config "ClientAliveInterval" "300"
update_ssh_config "ClientAliveCountMax" "0"

# Disable host-based authentication
update_ssh_config "HostbasedAuthentication" "no"

# Disable agent forwarding
update_ssh_config "AllowAgentForwarding" "no"

# Disable TCP forwarding
update_ssh_config "AllowTcpForwarding" "no"

# Disable gateway ports
update_ssh_config "GatewayPorts" "no"

# Restrict to specific ciphers
update_ssh_config "Ciphers" "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"

# Restrict to specific MACs
update_ssh_config "MACs" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"

# Restrict to specific key exchange algorithms
update_ssh_config "KexAlgorithms" "curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"

# Check configuration
echo "[+] Checking SSH configuration for errors..."
sshd -t
if [ $? -ne 0 ]; then
    echo "[!] Error in SSH configuration. Reverting to backup."
    cp $BACKUP_FILE $SSHD_CONFIG
    exit 1
fi

# Restart SSH service
echo "[+] Restarting SSH service..."
systemctl restart sshd

echo "[+] SSH hardening complete."
echo "[!] IMPORTANT: If you're connecting remotely, verify you can still access the system."
echo "    Keep this session open until you confirm you can log in with the new settings."
'''
                },
                'log_management': {
                    'name': 'setup_centralized_logging.sh',
                    'description': 'Configure centralized logging with rsyslog',
                    'content': '''#!/bin/bash
# Setup centralized logging
# This script configures rsyslog for centralized logging

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Default log server - CHANGE THIS to your actual log server
LOG_SERVER="logserver.example.com"
LOG_PORT="514"

# Ask for log server if running interactively
if [ -t 0 ]; then
    read -p "Enter log server hostname or IP [${LOG_SERVER}]: " input
    LOG_SERVER=${input:-$LOG_SERVER}
    
    read -p "Enter log server port [${LOG_PORT}]: " input
    LOG_PORT=${input:-$LOG_PORT}
fi

echo "[+] Setting up centralized logging to ${LOG_SERVER}:${LOG_PORT}..."

# Install rsyslog if not already installed
echo "[+] Ensuring rsyslog is installed..."
if command -v apt-get >/dev/null; then
    apt-get update
    apt-get install -y rsyslog
elif command -v dnf >/dev/null; then
    dnf install -y rsyslog
elif command -v yum >/dev/null; then
    yum install -y rsyslog
else
    echo "[!] Package manager not found. Please install rsyslog manually."
    exit 1
fi

# Backup original configuration
RSYSLOG_CONF="/etc/rsyslog.conf"
BACKUP_FILE="${RSYSLOG_CONF}.backup-$(date +%Y%m%d-%H%M%S)"

echo "[+] Creating backup of rsyslog configuration at ${BACKUP_FILE}"
cp $RSYSLOG_CONF $BACKUP_FILE

# Create centralized logging configuration
echo "[+] Creating centralized logging configuration..."
cat > /etc/rsyslog.d/10-remote-logging.conf <<EOF
# Forward all logs to remote syslog server
*.* @${LOG_SERVER}:${LOG_PORT}

# Optionally use TCP with encryption (uncomment to enable)
#\$DefaultNetstreamDriverCAFile /etc/ssl/certs/ca.pem
#\$ActionSendStreamDriver gtls
#\$ActionSendStreamDriverMode 1
#\$ActionSendStreamDriverAuthMode anon
#*.* @@${LOG_SERVER}:${LOG_PORT}
EOF

# Configure local logging retention
echo "[+] Configuring local logging retention..."
cat > /etc/rsyslog.d/20-local-logging.conf <<EOF
# Local logging configuration
# Set file permissions
\$FileOwner root
\$FileGroup adm
\$FileCreateMode 0640
\$DirCreateMode 0755
\$Umask 0022

# Log authentication messages
auth,authpriv.*                 /var/log/auth.log

# Log all kernel messages
kern.*                          /var/log/kern.log

# Log system messages
syslog.*                        /var/log/syslog

# Log daemon messages
daemon.*                        /var/log/daemon.log

# Log mail messages
mail.*                          /var/log/mail.log

# Log cron messages
cron.*                          /var/log/cron.log

# Everybody gets emergency messages
*.emerg                         :omusrmsg:*

# Log all messages to a single file for convenience
*.* /var/log/all.log
EOF

# Configure log rotation
echo "[+] Configuring log rotation..."
cat > /etc/logrotate.d/rsyslog <<EOF
/var/log/syslog
/var/log/auth.log
/var/log/kern.log
/var/log/mail.log
/var/log/daemon.log
/var/log/cron.log
/var/log/all.log
{
    rotate 14
    daily
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF

# Restart rsyslog service
echo "[+] Restarting rsyslog service..."
systemctl restart rsyslog

# Verify configuration
echo "[+] Verifying rsyslog configuration..."
systemctl status rsyslog

echo "[+] Centralized logging setup complete."
echo "[+] Logs are now being forwarded to ${LOG_SERVER}:${LOG_PORT}"
echo "[+] Local logs are also being retained in /var/log/"
'''
                },
                'vulnerability_scan': {
                    'name': 'run_vulnerability_scan.sh',
                    'description': 'Install and run vulnerability scanner',
                    'content': '''#!/bin/bash
# Install and run vulnerability scanner
# This script installs and runs Lynis for system security auditing

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

echo "[+] Setting up vulnerability scanning tools..."

# Output directory for reports
REPORT_DIR="/var/log/security-scans"
mkdir -p $REPORT_DIR
chmod 750 $REPORT_DIR

# Install Lynis
install_lynis

# Run Lynis audit
echo "[+] Running Lynis security audit..."
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="${REPORT_DIR}/lynis-report-${TIMESTAMP}.txt"

# Run comprehensive audit
lynis audit system --quiet --no-colors > "${REPORT_FILE}" 2>&1

# Generate summary report
echo "[+] Generating vulnerability summary..."
SUMMARY_FILE="${REPORT_DIR}/lynis-summary-${TIMESTAMP}.txt"

cat > "${SUMMARY_FILE}" <<EOF
=============================================================
Vulnerability Scan Summary - $(date)
=============================================================

Report File: ${REPORT_FILE}
Scan Type: Lynis Security Audit
System: $(hostname)
Timestamp: ${TIMESTAMP}

=============================================================
EOF

# Extract key findings from Lynis report
if [ -f "${REPORT_FILE}" ]; then
    echo "" >> "${SUMMARY_FILE}"
    echo "HIGH PRIORITY FINDINGS:" >> "${SUMMARY_FILE}"
    echo "======================" >> "${SUMMARY_FILE}"
    
    # Extract warnings and suggestions
    grep -E "^\[WARNING\]|^\[SUGGESTION\]" "${REPORT_FILE}" | head -20 >> "${SUMMARY_FILE}"
    
    echo "" >> "${SUMMARY_FILE}"
    echo "SYSTEM INFORMATION:" >> "${SUMMARY_FILE}"
    echo "==================" >> "${SUMMARY_FILE}"
    
    # Extract system info
    grep -E "OS|Kernel|Version" "${REPORT_FILE}" | head -10 >> "${SUMMARY_FILE}"
    
    echo "" >> "${SUMMARY_FILE}"
    echo "SECURITY SCORE:" >> "${SUMMARY_FILE}"
    echo "==============" >> "${SUMMARY_FILE}"
    
    # Extract hardening index
    grep -E "Hardening index|Score" "${REPORT_FILE}" >> "${SUMMARY_FILE}"
fi

# Set appropriate permissions
chmod 640 "${REPORT_FILE}"
chmod 640 "${SUMMARY_FILE}"

echo "[+] Vulnerability scan complete."
echo "[+] Full report: ${REPORT_FILE}"
echo "[+] Summary report: ${SUMMARY_FILE}"

# Display summary
if [ -f "${SUMMARY_FILE}" ]; then
    echo ""
    echo "SCAN SUMMARY:"
    echo "============="
    cat "${SUMMARY_FILE}"
fi

# Install additional scanning tools
echo "[+] Installing additional security tools..."

# Install ClamAV for malware scanning
if command -v apt-get >/dev/null; then
    apt-get install -y clamav clamav-daemon
    freshclam
elif command -v dnf >/dev/null; then
    dnf install -y clamav clamav-update
    freshclam
elif command -v yum >/dev/null; then
    yum install -y epel-release
    yum install -y clamav clamav-update
    freshclam
fi

# Install rkhunter for rootkit detection
if command -v apt-get >/dev/null; then
    apt-get install -y rkhunter
elif command -v dnf >/dev/null; then
    dnf install -y rkhunter
elif command -v yum >/dev/null; then
    yum install -y rkhunter
fi

# Update rkhunter database if installed
if command -v rkhunter >/dev/null; then
    echo "[+] Updating rkhunter database..."
    rkhunter --update --quiet
    
    echo "[+] Running rootkit scan..."
    RKHUNTER_REPORT="${REPORT_DIR}/rkhunter-${TIMESTAMP}.log"
    rkhunter --check --quiet --skip-keypress --report-warnings-only > "${RKHUNTER_REPORT}" 2>&1
    chmod 640 "${RKHUNTER_REPORT}"
    echo "[+] Rootkit scan complete: ${RKHUNTER_REPORT}"
fi

echo "[+] All vulnerability scans completed successfully."
echo "[+] Reports saved in: ${REPORT_DIR}"
'''
                },
                'backup_setup': {
                    'name': 'setup_backup_system.sh',
                    'description': 'Configure automated backup system',
                    'content': '''#!/bin/bash
# Setup automated backup system
# This script configures rsync-based backups with encryption

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

echo "[+] Setting up automated backup system..."

# Configuration variables
BACKUP_USER="backupuser"
BACKUP_DIR="/backup"
LOG_DIR="/var/log/backups"
SSH_KEY_DIR="/home/${BACKUP_USER}/.ssh"

# Directories to backup (modify as needed)
BACKUP_SOURCES=(
    "/etc"
    "/home"
    "/var/log"
    "/root"
    "/opt"
)

# Remote backup server (change this)
BACKUP_SERVER="backup.example.com"
BACKUP_REMOTE_DIR="/backups/$(hostname)"

# Create backup user
echo "[+] Creating backup user..."
if ! id "$BACKUP_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$BACKUP_USER"
    echo "[+] Backup user created: $BACKUP_USER"
else
    echo "[+] Backup user already exists: $BACKUP_USER"
fi

# Create directories
mkdir -p "$BACKUP_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "$SSH_KEY_DIR"

# Set permissions
chown "$BACKUP_USER:$BACKUP_USER" "$BACKUP_DIR"
chown "$BACKUP_USER:$BACKUP_USER" "$SSH_KEY_DIR"
chmod 700 "$SSH_KEY_DIR"

# Generate SSH key for backup user if not exists
if [ ! -f "$SSH_KEY_DIR/id_rsa" ]; then
    echo "[+] Generating SSH key for backup user..."
    sudo -u "$BACKUP_USER" ssh-keygen -t rsa -b 4096 -f "$SSH_KEY_DIR/id_rsa" -N ""
    echo "[+] SSH key generated. Public key:"
    cat "$SSH_KEY_DIR/id_rsa.pub"
    echo ""
    echo "[!] Add this public key to $BACKUP_SERVER authorized_keys"
fi

# Create backup script
BACKUP_SCRIPT="/usr/local/bin/system_backup.sh"
cat > "$BACKUP_SCRIPT" <<'EOF'
#!/bin/bash
# Automated system backup script

# Configuration
BACKUP_USER="backupuser"
BACKUP_DIR="/backup"
LOG_DIR="/var/log/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="${LOG_DIR}/backup_${TIMESTAMP}.log"

# Remote backup configuration
BACKUP_SERVER="backup.example.com"
BACKUP_REMOTE_DIR="/backups/$(hostname)"
SSH_KEY="/home/${BACKUP_USER}/.ssh/id_rsa"

# Backup sources
BACKUP_SOURCES=(
    "/etc"
    "/home" 
    "/var/log"
    "/root"
    "/opt"
)

# Exclusions
EXCLUDES=(
    "*.tmp"
    "*.cache"
    "*.log"
    "lost+found"
    "/proc"
    "/sys"
    "/dev"
    "/tmp"
    "/var/tmp"
)

# Create exclude file
EXCLUDE_FILE="/tmp/backup_excludes_$"
printf "%s\n" "${EXCLUDES[@]}" > "$EXCLUDE_FILE"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "Starting backup process"

# Create local backup
LOCAL_BACKUP="${BACKUP_DIR}/backup_${TIMESTAMP}"
mkdir -p "$LOCAL_BACKUP"

log "Creating local backup in $LOCAL_BACKUP"

for source in "${BACKUP_SOURCES[@]}"; do
    if [ -d "$source" ]; then
        log "Backing up $source"
        rsync -av --exclude-from="$EXCLUDE_FILE" "$source" "$LOCAL_BACKUP/" 2>&1 | tee -a "$LOG_FILE"
    else
        log "Warning: $source not found, skipping"
    fi
done

# Create compressed archive
ARCHIVE_FILE="${BACKUP_DIR}/backup_${TIMESTAMP}.tar.gz"
log "Creating compressed archive: $ARCHIVE_FILE"

tar -czf "$ARCHIVE_FILE" -C "$LOCAL_BACKUP" . 2>&1 | tee -a "$LOG_FILE"

if [ $? -eq 0 ]; then
    log "Archive created successfully"
    # Remove uncompressed backup
    rm -rf "$LOCAL_BACKUP"
else
    log "Error creating archive"
    exit 1
fi

# Upload to remote server (if configured)
if [ -n "$BACKUP_SERVER" ] && [ -f "$SSH_KEY" ]; then
    log "Uploading to remote server: $BACKUP_SERVER"
    
    # Create remote directory
    sudo -u "$BACKUP_USER" ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no "$BACKUP_SERVER" \
        "mkdir -p $BACKUP_REMOTE_DIR" 2>&1 | tee -a "$LOG_FILE"
    
    # Upload archive
    sudo -u "$BACKUP_USER" scp -i "$SSH_KEY" -o StrictHostKeyChecking=no \
        "$ARCHIVE_FILE" "${BACKUP_SERVER}:${BACKUP_REMOTE_DIR}/" 2>&1 | tee -a "$LOG_FILE"
    
    if [ $? -eq 0 ]; then
        log "Remote upload successful"
    else
        log "Remote upload failed"
    fi
else
    log "Remote backup not configured or SSH key not found"
fi

# Cleanup old local backups (keep last 7 days)
log "Cleaning up old backups"
find "$BACKUP_DIR" -name "backup_*.tar.gz" -mtime +7 -delete 2>&1 | tee -a "$LOG_FILE"

# Cleanup old logs (keep last 30 days)
find "$LOG_DIR" -name "backup_*.log" -mtime +30 -delete 2>&1 | tee -a "$LOG_FILE"

# Remove temporary exclude file
rm -f "$EXCLUDE_FILE"

log "Backup process completed"

# Send notification (if mail is configured)
if command -v mail >/dev/null; then
    echo "Backup completed on $(hostname) at $(date)" | \
        mail -s "Backup Completed - $(hostname)" root
fi
EOF

# Make backup script executable
chmod +x "$BACKUP_SCRIPT"

# Create cron job for automated backups
echo "[+] Setting up automated backup schedule..."
CRON_FILE="/etc/cron.d/system-backup"

cat > "$CRON_FILE" <<EOF
# Automated system backup
# Runs daily at 2:00 AM
0 2 * * * root $BACKUP_SCRIPT >/dev/null 2>&1

# Weekly backup verification
0 3 * * 0 root $BACKUP_SCRIPT --verify >/dev/null 2>&1
EOF

# Set proper permissions for cron file
chmod 644 "$CRON_FILE"

# Create backup verification script
VERIFY_SCRIPT="/usr/local/bin/verify_backup.sh"
cat > "$VERIFY_SCRIPT" <<'EOF'
#!/bin/bash
# Backup verification script

BACKUP_DIR="/backup"
LOG_DIR="/var/log/backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
VERIFY_LOG="${LOG_DIR}/backup_verify_${TIMESTAMP}.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$VERIFY_LOG"
}

log "Starting backup verification"

# Find latest backup
LATEST_BACKUP=$(ls -t ${BACKUP_DIR}/backup_*.tar.gz 2>/dev/null | head -n1)

if [ -z "$LATEST_BACKUP" ]; then
    log "Error: No backup files found in $BACKUP_DIR"
    exit 1
fi

log "Verifying backup: $LATEST_BACKUP"

# Test archive integrity
if tar -tzf "$LATEST_BACKUP" >/dev/null 2>&1; then
    log "Backup archive integrity verified"
else
    log "Error: Backup archive is corrupted"
    exit 1
fi

# Check backup age
BACKUP_AGE=$(find "$LATEST_BACKUP" -mtime +2 | wc -l)
if [ "$BACKUP_AGE" -gt 0 ]; then
    log "Warning: Latest backup is more than 2 days old"
else
    log "Backup age is acceptable"
fi

# Check backup size
BACKUP_SIZE=$(du -h "$LATEST_BACKUP" | cut -f1)
log "Backup size: $BACKUP_SIZE"

log "Backup verification completed"

# Send notification
if command -v mail >/dev/null; then
    echo "Backup verification completed on $(hostname)" | \
        mail -s "Backup Verification - $(hostname)" root
fi
EOF

chmod +x "$VERIFY_SCRIPT"

# Test backup system
echo "[+] Testing backup system..."
sudo -u "$BACKUP_USER" "$BACKUP_SCRIPT"

echo "[+] Backup system setup complete."
echo "[+] Backup script: $BACKUP_SCRIPT"
echo "[+] Verification script: $VERIFY_SCRIPT"
echo "[+] Backups will run daily at 2:00 AM"
echo "[+] Logs are stored in: $LOG_DIR"
echo ""
echo "[!] IMPORTANT: Configure remote backup server details in:"
echo "    $BACKUP_SCRIPT"
echo "    Add the backup user's public key to the remote server"
'''
                }
            },
            'windows': {
                'firewall': {
                    'name': 'configure_windows_firewall.ps1',
                    'description': 'Configure Windows Defender Firewall with secure settings',
                    'content': '''# Configure Windows Defender Firewall
# This script configures Windows Firewall with secure defaults

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "[+] Configuring Windows Defender Firewall..." -ForegroundColor Green

# Enable Windows Firewall for all profiles
Write-Host "[+] Enabling Windows Firewall for all profiles..." -ForegroundColor Yellow
netsh advfirewall set allprofiles state on

# Set default actions
Write-Host "[+] Setting default firewall actions..." -ForegroundColor Yellow
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

# Configure Domain profile
Write-Host "[+] Configuring Domain profile..." -ForegroundColor Yellow
netsh advfirewall set domainprofile logging filename "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall-domain.log"
netsh advfirewall set domainprofile logging maxfilesize 4096
netsh advfirewall set domainprofile logging droppedconnections enable
netsh advfirewall set domainprofile logging allowedconnections enable

# Configure Private profile
Write-Host "[+] Configuring Private profile..." -ForegroundColor Yellow
netsh advfirewall set privateprofile logging filename "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall-private.log"
netsh advfirewall set privateprofile logging maxfilesize 4096
netsh advfirewall set privateprofile logging droppedconnections enable
netsh advfirewall set privateprofile logging allowedconnections enable

# Configure Public profile
Write-Host "[+] Configuring Public profile..." -ForegroundColor Yellow
netsh advfirewall set publicprofile logging filename "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall-public.log"
netsh advfirewall set publicprofile logging maxfilesize 4096
netsh advfirewall set publicprofile logging droppedconnections enable
netsh advfirewall set publicprofile logging allowedconnections enable

# Block common attack vectors
Write-Host "[+] Blocking common attack vectors..." -ForegroundColor Yellow

# Block NetBIOS
netsh advfirewall firewall add rule name="Block NetBIOS Inbound" dir=in action=block protocol=UDP localport=137
netsh advfirewall firewall add rule name="Block NetBIOS Outbound" dir=out action=block protocol=UDP localport=137

# Block SMB if not needed (uncomment if SMB is not required)
# netsh advfirewall firewall add rule name="Block SMB Inbound" dir=in action=block protocol=TCP localport=445
# netsh advfirewall firewall add rule name="Block SMB Outbound" dir=out action=block protocol=TCP localport=445

# Allow essential services
Write-Host "[+] Configuring essential service rules..." -ForegroundColor Yellow

# Allow ping (ICMP)
netsh advfirewall firewall add rule name="Allow ICMP Echo Request" dir=in action=allow protocol=icmpv4:8,any

# Allow Remote Desktop (uncomment if needed)
# netsh advfirewall firewall add rule name="Allow RDP" dir=in action=allow protocol=TCP localport=3389

Write-Host "[+] Windows Firewall configuration complete." -ForegroundColor Green
Write-Host "[+] Current firewall status:" -ForegroundColor Yellow
netsh advfirewall show allprofiles

Write-Host "[!] IMPORTANT: Verify that necessary applications can still connect." -ForegroundColor Red
'''
                },
                'patch_management': {
                    'name': 'configure_windows_updates.ps1',
                    'description': 'Configure Windows Update settings',
                    'content': '''# Configure Windows Update settings
# This script configures automatic Windows Updates

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

Write-Host "[+] Configuring Windows Update settings..." -ForegroundColor Green

# Import Windows Update module if available
try {
    Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
} catch {
    Write-Host "[+] Installing PSWindowsUpdate module..." -ForegroundColor Yellow
    Install-Module PSWindowsUpdate -Force -AllowClobber
    Import-Module PSWindowsUpdate
}

# Configure Windows Update via Registry
Write-Host "[+] Configuring Windows Update registry settings..." -ForegroundColor Yellow

$UpdatePath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate"
$AUPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"

# Create registry keys if they don't exist
if (!(Test-Path $UpdatePath)) {
    New-Item -Path $UpdatePath -Force
}
if (!(Test-Path $AUPath)) {
    New-Item -Path $AUPath -Force
}

# Configure automatic updates
Set-ItemProperty -Path $AUPath -Name "NoAutoUpdate" -Value 0 -Type DWord
Set-ItemProperty -Path $AUPath -Name "AUOptions" -Value 4 -Type DWord  # Auto download and install
Set-ItemProperty -Path $AUPath -Name "ScheduledInstallDay" -Value 0 -Type DWord  # Every day
Set-ItemProperty -Path $AUPath -Name "ScheduledInstallTime" -Value 3 -Type DWord  # 3 AM

# Enable automatic restart
Set-ItemProperty -Path $AUPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 0 -Type DWord

# Configure update notifications
Set-ItemProperty -Path $AUPath -Name "DetectionFrequencyEnabled" -Value 1 -Type DWord
Set-ItemProperty -Path $AUPath -Name "DetectionFrequency" -Value 22 -Type DWord  # Check every 22 hours

# Install Windows Updates via PowerShell
Write-Host "[+] Checking for available updates..." -ForegroundColor Yellow

try {
    # Get available updates
    $Updates = Get-WUList
    
    if ($Updates) {
        Write-Host "[+] Found $($Updates.Count) available updates" -ForegroundColor Yellow
        
        # Install critical and security updates
        Write-Host "[+] Installing critical and security updates..." -ForegroundColor Yellow
        Get-WUInstall -MicrosoftUpdate -AcceptAll -AutoReboot | Out-Host
    } else {
        Write-Host "[+] No updates available" -ForegroundColor Green
    }
} catch {
    Write-Host "[!] Error checking for updates: $($_.Exception.Message)" -ForegroundColor Red
    
    # Fallback to built-in Windows Update
    Write-Host "[+] Using Windows Update service..." -ForegroundColor Yellow
    Start-Service -Name wuauserv
    UsoClient StartScan
    UsoClient StartDownload
    UsoClient StartInstall
}

# Configure Windows Update service
Write-Host "[+] Configuring Windows Update service..." -ForegroundColor Yellow
Set-Service -Name wuauserv -StartupType Automatic
Start-Service -Name wuauserv

# Create scheduled task for update checks
Write-Host "[+] Creating scheduled task for regular update checks..." -ForegroundColor Yellow

$TaskName = "Security Update Check"
$TaskDescription = "Regular security update check and installation"

# Remove existing task if it exists
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

# Create new task
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -Command `"Get-WUInstall -MicrosoftUpdate -AcceptAll -AutoReboot`""
$Trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName $TaskName -Description $TaskDescription -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal

Write-Host "[+] Windows Update configuration complete." -ForegroundColor Green
Write-Host "[+] Updates will be checked and installed daily at 2:00 AM" -ForegroundColor Yellow

# Show current update status
Write-Host "[+] Current Windows Update status:" -ForegroundColor Yellow
Get-Service wuauserv | Select-Object Name, Status, StartType
'''
                }
            }
        }
        
        return templates

    def calculate_priority_score(self, finding: Dict[str, Any]) -> float:
        """
        Calculate priority score for a finding
        
        Args:
            finding: Dictionary containing finding details
            
        Returns:
            Float priority score (0-100, higher is more urgent)
        """
        # Base score from risk level
        risk_level = finding.get('risk_level', 'MEDIUM').upper()
        base_score = self.risk_levels.get(risk_level, {'weight': 50})['weight']
        
        # Category modifier
        category = finding.get('category', 'General')
        category_info = self.category_guidance.get(category, {'priority_modifier': 1.0})
        category_modifier = category_info['priority_modifier']
        
        # Framework modifier
        framework = finding.get('framework', '')
        framework_info = self.framework_guidance.get(framework, {'priority_modifier': 1.0})
        framework_modifier = framework_info['priority_modifier']
        
        # Calculate final score
        priority_score = base_score * category_modifier * framework_modifier
        
        # Ensure score is within bounds
        return min(100, max(0, priority_score))

    def generate_remediation_guidance(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive remediation guidance for a finding
        
        Args:
            finding: Dictionary containing finding details
            
        Returns:
            Dictionary containing remediation guidance
        """
        category = finding.get('category', 'General')
        risk_level = finding.get('risk_level', 'MEDIUM').upper()
        framework = finding.get('framework', '')
        
        # Get category-specific guidance
        category_info = self.category_guidance.get(category, self.category_guidance['General'])
        
        # Get framework-specific guidance
        framework_info = self.framework_guidance.get(framework, {})
        
        # Calculate priority score
        priority_score = self.calculate_priority_score(finding)
        
        # Get risk level info
        risk_info = self.risk_levels.get(risk_level, self.risk_levels['MEDIUM'])
        
        # Generate remediation steps based on category and finding details
        remediation_steps = self._generate_remediation_steps(finding)
        
        # Generate testing procedures
        testing_procedures = self._generate_testing_procedures(finding)
        
        # Create comprehensive guidance
        guidance = {
            'finding_id': finding.get('id', 'unknown'),
            'title': finding.get('title', 'Security Finding'),
            'description': finding.get('description', ''),
            'category': category,
            'risk_level': risk_level,
            'framework': framework,
            'priority_score': priority_score,
            'urgency': risk_info['timeframe'],
            'business_impact': category_info['impact'],
            'business_justification': category_info['business_justification'],
            'estimated_effort': category_info['effort'],
            'remediation_steps': remediation_steps,
            'testing_procedures': testing_procedures,
            'verification_method': category_info['verification'],
            'reference_links': [],
            'automated_scripts': [],
            'rollback_plan': self._generate_rollback_plan(finding),
            'compliance_notes': self._generate_compliance_notes(finding),
            'timeline': self._generate_timeline(finding, risk_level),
            'success_criteria': self._generate_success_criteria(finding),
            'dependencies': self._identify_dependencies(finding),
            'cost_estimate': self._estimate_cost(category_info['effort']),
            'stakeholders': self._identify_stakeholders(category)
        }
        
        # Add framework-specific reference
        if framework_info.get('reference_url'):
            guidance['reference_links'].append({
                'title': f'{framework} Framework Reference',
                'url': framework_info['reference_url'],
                'type': 'compliance_framework'
            })
        
        # Add automated scripts if available
        guidance['automated_scripts'] = self._get_applicable_scripts(finding)
        
        return guidance

    def _generate_remediation_steps(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate detailed remediation steps for a finding"""
        
        category = finding.get('category', 'General')
        title = finding.get('title', '').lower()
        description = finding.get('description', '').lower()
        
        steps = []
        
        # Category-specific step generation
        if 'firewall' in title or 'firewall' in description:
            steps.extend([
                {
                    'step': 1,
                    'action': 'Review current firewall configuration',
                    'details': 'Document existing firewall rules and policies to understand current state',
                    'responsibility': 'Network Administrator',
                    'estimated_time': '30 minutes'
                },
                {
                    'step': 2,
                    'action': 'Enable firewall if disabled',
                    'details': 'Activate firewall service on the system with default deny policies',
                    'responsibility': 'System Administrator',
                    'estimated_time': '15 minutes'
                },
                {
                    'step': 3,
                    'action': 'Configure essential service rules',
                    'details': 'Allow necessary services while maintaining security (SSH, HTTP/HTTPS as needed)',
                    'responsibility': 'Network Administrator',
                    'estimated_time': '45 minutes'
                },
                {
                    'step': 4,
                    'action': 'Test connectivity',
                    'details': 'Verify that legitimate traffic flows correctly while unauthorized access is blocked',
                    'responsibility': 'System Administrator',
                    'estimated_time': '30 minutes'
                }
            ])
            
        elif 'patch' in title or 'update' in title or 'patch' in description:
            steps.extend([
                {
                    'step': 1,
                    'action': 'Inventory current patch level',
                    'details': 'Document currently installed patches and identify missing security updates',
                    'responsibility': 'System Administrator',
                    'estimated_time': '45 minutes'
                },
                {
                    'step': 2,
                    'action': 'Test patches in staging environment',
                    'details': 'Deploy patches to test environment and verify compatibility with applications',
                    'responsibility': 'System Administrator',
                    'estimated_time': '2 hours'
                },
                {
                    'step': 3,
                    'action': 'Schedule maintenance window',
                    'details': 'Coordinate with stakeholders for production system downtime if required',
                    'responsibility': 'IT Manager',
                    'estimated_time': '30 minutes'
                },
                {
                    'step': 4,
                    'action': 'Deploy patches to production',
                    'details': 'Apply security patches to production systems during scheduled maintenance',
                    'responsibility': 'System Administrator',
                    'estimated_time': '1-3 hours'
                },
                {
                    'step': 5,
                    'action': 'Verify system functionality',
                    'details': 'Confirm all services are operational and applications function correctly',
                    'responsibility': 'System Administrator',
                    'estimated_time': '1 hour'
                }
            ])
            
        elif 'password' in title or 'password' in description:
            steps.extend([
                {
                    'step': 1,
                    'action': 'Review current password policy',
                    'details': 'Document existing password requirements and identify policy gaps',
                    'responsibility': 'Security Administrator',
                    'estimated_time': '30 minutes'
                },
                {
                    'step': 2,
                    'action': 'Update password policy settings',
                    'details': 'Configure minimum length, complexity, and expiration requirements',
                    'responsibility': 'System Administrator',
                    'estimated_time': '45 minutes'
                },
                {
                    'step': 3,
                    'action': 'Force password change for non-compliant accounts',
                    'details': 'Identify and require password updates for accounts not meeting new policy',
                    'responsibility': 'Security Administrator',
                    'estimated_time': '1 hour'
                },
                {
                    'step': 4,
                    'action': 'Communicate policy changes to users',
                    'details': 'Notify users of new password requirements and provide guidance',
                    'responsibility': 'IT Support',
                    'estimated_time': '30 minutes'
                }
            ])
            
        elif 'ssh' in title or 'ssh' in description:
            steps.extend([
                {
                    'step': 1,
                    'action': 'Backup current SSH configuration',
                    'details': 'Create backup of /etc/ssh/sshd_config before making changes',
                    'responsibility': 'System Administrator',
                    'estimated_time': '5 minutes'
                },
                {
                    'step': 2,
                    'action': 'Implement SSH hardening settings',
                    'details': 'Configure secure ciphers, disable root login, set max auth tries',
                    'responsibility': 'System Administrator',
                    'estimated_time': '30 minutes'
                },
                {
                    'step': 3,
                    'action': 'Test SSH configuration',
                    'details': 'Verify configuration syntax and test connectivity before restarting service',
                    'responsibility': 'System Administrator',
                    'estimated_time': '15 minutes'
                },
                {
                    'step': 4,
                    'action': 'Restart SSH service',
                    'details': 'Apply new configuration by restarting SSH daemon',
                    'responsibility': 'System Administrator',
                    'estimated_time': '5 minutes'
                }
            ])
            
        elif 'log' in title or 'audit' in title or 'monitor' in description:
            steps.extend([
                {
                    'step': 1,
                    'action': 'Review current logging configuration',
                    'details': 'Assess what events are currently being logged and retention policies',
                    'responsibility': 'System Administrator',
                    'estimated_time': '45 minutes'
                },
                {
                    'step': 2,
                    'action': 'Configure comprehensive logging',
                    'details': 'Enable logging for authentication, system changes, and security events',
                    'responsibility': 'System Administrator',
                    'estimated_time': '1 hour'
                },
                {
                    'step': 3,
                    'action': 'Set up log rotation',
                    'details': 'Configure log rotation to prevent disk space issues while retaining required data',
                    'responsibility': 'System Administrator',
                    'estimated_time': '30 minutes'
                },
                {
                    'step': 4,
                    'action': 'Test log forwarding',
                    'details': 'Verify logs are being generated and forwarded to central log server if configured',
                    'responsibility': 'System Administrator',
                    'estimated_time': '30 minutes'
                }
            ])
            
        else:
            # Generic steps based on category
            if category == 'Access Control':
                steps.extend([
                    {
                        'step': 1,
                        'action': 'Review user access permissions',
                        'details': 'Audit current user accounts and their assigned permissions',
                        'responsibility': 'Security Administrator',
                        'estimated_time': '1 hour'
                    },
                    {
                        'step': 2,
                        'action': 'Apply principle of least privilege',
                        'details': 'Remove unnecessary permissions and ensure users have minimum required access',
                        'responsibility': 'Security Administrator',
                        'estimated_time': '2 hours'
                    },
                    {
                        'step': 3,
                        'action': 'Implement role-based access control',
                        'details': 'Group users by role and assign permissions based on job functions',
                        'responsibility': 'Security Administrator',
                        'estimated_time': '3 hours'
                    }
                ])
            elif category == 'Vulnerability Management':
                steps.extend([
                    {
                        'step': 1,
                        'action': 'Perform vulnerability assessment',
                        'details': 'Run comprehensive vulnerability scan to identify security weaknesses',
                        'responsibility': 'Security Analyst',
                        'estimated_time': '2 hours'
                    },
                    {
                        'step': 2,
                        'action': 'Prioritize vulnerabilities by risk',
                        'details': 'Rank vulnerabilities based on exploitability and business impact',
                        'responsibility': 'Security Analyst',
                        'estimated_time': '1 hour'
                    },
                    {
                        'step': 3,
                        'action': 'Remediate high-risk vulnerabilities',
                        'details': 'Apply patches or implement compensating controls for critical issues',
                        'responsibility': 'System Administrator',
                        'estimated_time': '4 hours'
                    }
                ])
            else:
                # Default generic steps
                steps.extend([
                    {
                        'step': 1,
                        'action': 'Assess current state',
                        'details': 'Document the current configuration and identify specific issues',
                        'responsibility': 'System Administrator',
                        'estimated_time': '30 minutes'
                    },
                    {
                        'step': 2,
                        'action': 'Implement security controls',
                        'details': 'Apply necessary security configurations or controls to address the finding',
                        'responsibility': 'System Administrator',
                        'estimated_time': '1-2 hours'
                    },
                    {
                        'step': 3,
                        'action': 'Verify implementation',
                        'details': 'Test and confirm that the security controls are working as expected',
                        'responsibility': 'System Administrator',
                        'estimated_time': '30 minutes'
                    }
                ])
        
        return steps

    def _generate_testing_procedures(self, finding: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate testing procedures for remediation"""
        
        category = finding.get('category', 'General')
        title = finding.get('title', '').lower()
        
        procedures = []
        
        if 'firewall' in title:
            procedures.extend([
                {
                    'test': 'Port scanning test',
                    'procedure': 'Run nmap scan from external network to verify unauthorized ports are blocked',
                    'expected_result': 'Only authorized services should be accessible'
                },
                {
                    'test': 'Service connectivity test',
                    'procedure': 'Verify legitimate applications can connect through firewall',
                    'expected_result': 'All required services function normally'
                }
            ])
        elif 'patch' in title or 'update' in title:
            procedures.extend([
                {
                    'test': 'System functionality test',
                    'procedure': 'Verify all critical applications and services start and function correctly',
                    'expected_result': 'All services operational with no degraded performance'
                },
                {
                    'test': 'Patch level verification',
                    'procedure': 'Run system commands to verify patches were installed successfully',
                    'expected_result': 'All critical security patches show as installed'
                }
            ])
        elif 'password' in title:
            procedures.extend([
                {
                    'test': 'Password policy enforcement test',
                    'procedure': 'Attempt to set weak passwords that violate policy',
                    'expected_result': 'System should reject passwords that do not meet policy requirements'
                },
                {
                    'test': 'Account lockout test',
                    'procedure': 'Test account lockout functionality with multiple failed login attempts',
                    'expected_result': 'Accounts should lock after configured number of failed attempts'
                }
            ])
        else:
            # Generic testing procedures
            procedures.extend([
                {
                    'test': 'Configuration verification',
                    'procedure': 'Review system configuration to confirm changes were applied',
                    'expected_result': 'Configuration matches security requirements'
                },
                {
                    'test': 'Functional testing',
                    'procedure': 'Test system functionality to ensure no negative impact from changes',
                    'expected_result': 'System operates normally with improved security posture'
                }
            ])
        
        return procedures

    def _generate_rollback_plan(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Generate rollback plan for remediation"""
        
        category = finding.get('category', 'General')
        
        return {
            'backup_requirements': [
                'Configuration files before changes',
                'System state documentation',
                'User account status before modifications'
            ],
            'rollback_steps': [
                'Stop affected services',
                'Restore original configuration files',
                'Restart services',
                'Verify system functionality'
            ],
            'rollback_time_estimate': '30-60 minutes',
            'rollback_triggers': [
                'Service outages',
                'Application failures',
                'User connectivity issues',
                'Performance degradation'
            ],
            'emergency_contacts': [
                'System Administrator',
                'Network Administrator', 
                'IT Manager'
            ]
        }

    def _generate_compliance_notes(self, finding: Dict[str, Any]) -> Dict[str, str]:
        """Generate compliance-specific notes"""
        
        framework = finding.get('framework', '')
        category = finding.get('category', 'General')
        
        notes = {
            'regulatory_requirement': f'This remediation addresses {framework} compliance requirements',
            'documentation_needs': 'Document all changes and maintain evidence of implementation',
            'audit_evidence': 'Retain configuration files, logs, and test results for audit purposes',
            'reporting_requirements': 'Report completion to compliance team with evidence package'
        }
        
        # Framework-specific notes
        if framework == 'RBI':
            notes['regulatory_impact'] = 'Critical for RBI compliance - failure to address may result in regulatory penalties'
            notes['timeline_requirement'] = 'Must be addressed within regulatory timeline requirements'
        elif framework == 'ISO27001':
            notes['certification_impact'] = 'Required for ISO 27001 certification maintenance'
            notes['continual_improvement'] = 'Consider as input for continual improvement process'
        elif framework == 'CIS':
            notes['benchmark_alignment'] = 'Aligns with CIS Critical Security Controls best practices'
            notes['industry_standard'] = 'Follows widely accepted industry security standards'
        
        return notes

    def _generate_timeline(self, finding: Dict[str, Any], risk_level: str) -> Dict[str, str]:
        """Generate implementation timeline based on risk level"""
        
        risk_info = self.risk_levels.get(risk_level, self.risk_levels['MEDIUM'])
        
        if risk_level == 'CRITICAL':
            return {
                'immediate_action': 'Within 4 hours',
                'full_remediation': 'Within 24 hours',
                'verification': 'Within 48 hours',
                'documentation': 'Within 72 hours'
            }
        elif risk_level == 'HIGH':
            return {
                'immediate_action': 'Within 24 hours',
                'full_remediation': 'Within 1 week',
                'verification': 'Within 10 days',
                'documentation': 'Within 2 weeks'
            }
        elif risk_level == 'MEDIUM':
            return {
                'immediate_action': 'Within 1 week',
                'full_remediation': 'Within 1 month',
                'verification': 'Within 6 weeks',
                'documentation': 'Within 2 months'
            }
        else:  # LOW
            return {
                'immediate_action': 'Within 2 weeks',
                'full_remediation': 'Within 3 months',
                'verification': 'Within 4 months',
                'documentation': 'Within 5 months'
            }

    def _generate_success_criteria(self, finding: Dict[str, Any]) -> List[str]:
        """Generate success criteria for remediation"""
        
        category = finding.get('category', 'General')
        title = finding.get('title', '').lower()
        
        criteria = []
        
        # Common success criteria
        criteria.append('Finding no longer appears in subsequent security scans')
        criteria.append('System functionality remains intact after remediation')
        criteria.append('Security control is properly configured and operational')
        
        # Category-specific criteria
        if 'firewall' in title:
            criteria.extend([
                'Unauthorized network traffic is blocked',
                'Legitimate services remain accessible',
                'Firewall logs show proper rule enforcement'
            ])
        elif 'patch' in title:
            criteria.extend([
                'All critical security patches are installed',
                'System vulnerability scan shows reduced risk score',
                'Applications function normally after patching'
            ])
        elif 'password' in title:
            criteria.extend([
                'Password policy settings are enforced',
                'Weak passwords are rejected by the system',
                'User accounts comply with policy requirements'
            ])
        elif category == 'Access Control':
            criteria.extend([
                'Users have minimum necessary permissions',
                'Unauthorized access attempts are blocked',
                'Access controls are consistently enforced'
            ])
        
        return criteria

    def _identify_dependencies(self, finding: Dict[str, Any]) -> List[Dict[str, str]]:
        """Identify dependencies for remediation"""
        
        category = finding.get('category', 'General')
        title = finding.get('title', '').lower()
        
        dependencies = []
        
        # Common dependencies
        dependencies.append({
            'type': 'approval',
            'description': 'Management approval for system changes',
            'criticality': 'high'
        })
        
        dependencies.append({
            'type': 'maintenance_window',
            'description': 'Scheduled maintenance window for system changes',
            'criticality': 'medium'
        })
        
        # Specific dependencies based on finding type
        if 'firewall' in title:
            dependencies.extend([
                {
                    'type': 'network_documentation',
                    'description': 'Current network topology and service requirements',
                    'criticality': 'high'
                },
                {
                    'type': 'stakeholder_approval',
                    'description': 'Network team approval for firewall rule changes',
                    'criticality': 'high'
                }
            ])
        elif 'patch' in title:
            dependencies.extend([
                {
                    'type': 'testing_environment',
                    'description': 'Test environment that mirrors production',
                    'criticality': 'high'
                },
                {
                    'type': 'rollback_plan',
                    'description': 'Verified rollback procedures in case of issues',
                    'criticality': 'high'
                }
            ])
        elif category == 'Access Control':
            dependencies.extend([
                {
                    'type': 'user_inventory',
                    'description': 'Complete inventory of user accounts and roles',
                    'criticality': 'medium'
                },
                {
                    'type': 'business_process_review',
                    'description': 'Understanding of business processes requiring access',
                    'criticality': 'medium'
                }
            ])
        
        return dependencies

    def _estimate_cost(self, effort_description: str) -> Dict[str, str]:
        """Estimate cost based on effort description"""
        
        # Extract effort level from description
        if 'Low' in effort_description:
            return {
                'labor_hours': '1-2 hours',
                'estimated_cost': '$100-200',
                'cost_category': 'Low'
            }
        elif 'Medium' in effort_description:
            return {
                'labor_hours': '4-8 hours', 
                'estimated_cost': '$400-800',
                'cost_category': 'Medium'
            }
        elif 'High' in effort_description:
            if 'days' in effort_description:
                return {
                    'labor_hours': '16-32 hours',
                    'estimated_cost': '$1,600-3,200',
                    'cost_category': 'High'
                }
            else:
                return {
                    'labor_hours': '8-16 hours',
                    'estimated_cost': '$800-1,600', 
                    'cost_category': 'High'
                }
        elif 'Very High' in effort_description:
            return {
                'labor_hours': '80-160 hours',
                'estimated_cost': '$8,000-16,000',
                'cost_category': 'Very High'
            }
        else:
            return {
                'labor_hours': '4-8 hours',
                'estimated_cost': '$400-800',
                'cost_category': 'Medium'
            }

    def _identify_stakeholders(self, category: str) -> List[Dict[str, str]]:
        """Identify key stakeholders for remediation"""
        
        stakeholders = [
            {
                'role': 'IT Manager',
                'responsibility': 'Overall project oversight and approval',
                'involvement': 'high'
            },
            {
                'role': 'System Administrator',
                'responsibility': 'Technical implementation of remediation',
                'involvement': 'high'
            }
        ]
        
        # Category-specific stakeholders
        if category in ['Access Control', 'User Access Management']:
            stakeholders.extend([
                {
                    'role': 'Security Administrator',
                    'responsibility': 'Access control policy implementation',
                    'involvement': 'high'
                },
                {
                    'role': 'HR Manager',
                    'responsibility': 'User role definitions and approvals',
                    'involvement': 'medium'
                }
            ])
        elif category == 'Network Security':
            stakeholders.append({
                'role': 'Network Administrator',
                'responsibility': 'Network security configuration',
                'involvement': 'high'
            })
        elif category in ['Data Protection', 'Cryptography']:
            stakeholders.append({
                'role': 'Data Protection Officer',
                'responsibility': 'Data protection compliance oversight',
                'involvement': 'high'
            })
        elif category == 'Physical Security':
            stakeholders.append({
                'role': 'Facilities Manager',
                'responsibility': 'Physical security implementation',
                'involvement': 'high'
            })
        
        return stakeholders

    def _get_applicable_scripts(self, finding: Dict[str, Any]) -> List[Dict[str, str]]:
        """Get applicable automated scripts for the finding"""
        
        title = finding.get('title', '').lower()
        description = finding.get('description', '').lower()
        category = finding.get('category', '')
        
        applicable_scripts = []
        
        # Check for script applicability based on keywords
        for platform, categories in self.remediation_templates.items():
            for script_category, script_info in categories.items():
                script_applicable = False
                
                # Check if script is applicable based on finding content
                if script_category == 'firewall' and ('firewall' in title or 'firewall' in description):
                    script_applicable = True
                elif script_category == 'patch_management' and ('patch' in title or 'update' in title):
                    script_applicable = True
                elif script_category == 'secure_ssh' and ('ssh' in title or 'ssh' in description):
                    script_applicable = True
                elif script_category == 'log_management' and ('log' in title or 'audit' in title or 'monitor' in description):
                    script_applicable = True
                elif script_category == 'vulnerability_scan' and ('vulnerabilit' in title or 'scan' in description):
                    script_applicable = True
                elif script_category == 'backup_setup' and ('backup' in title or 'recovery' in description):
                    script_applicable = True
                
                if script_applicable:
                    applicable_scripts.append({
                        'name': script_info['name'],
                        'description': script_info['description'],
                        'platform': platform,
                        'category': script_category,
                        'path': f"remediation_scripts/{platform}_{script_info['name']}"
                    })
        
        return applicable_scripts

    def generate_remediation_scripts(self, findings: List[Dict[str, Any]], target_platform: str = 'linux') -> Dict[str, str]:
        """
        Generate automated remediation scripts for findings
        
        Args:
            findings: List of findings to generate scripts for
            target_platform: Target platform (linux, windows)
            
        Returns:
            Dictionary mapping script names to file paths
        """
        generated_scripts = {}
        
        # Create platform-specific scripts directory
        platform_scripts_dir = self.scripts_dir / target_platform
        platform_scripts_dir.mkdir(exist_ok=True)
        
        for finding in findings:
            applicable_scripts = self._get_applicable_scripts(finding)
            
            for script_info in applicable_scripts:
                if script_info['platform'] == target_platform:
                    script_name = script_info['name']
                    script_path = platform_scripts_dir / script_name
                    
                    # Get script content from templates
                    script_content = self.remediation_templates[target_platform][script_info['category']]['content']
                    
                    # Write script to file
                    try:
                        with open(script_path, 'w', encoding='utf-8') as f:
                            f.write(script_content)
                        
                        # Make script executable on Unix-like systems
                        if target_platform == 'linux':
                            os.chmod(script_path, 0o755)
                        
                        generated_scripts[script_name] = str(script_path)
                        logger.info(f"Generated remediation script: {script_path}")
                        
                    except Exception as e:
                        logger.error(f"Failed to generate script {script_name}: {str(e)}")
        
        return generated_scripts

    def create_remediation_report(self, findings: List[Dict[str, Any]], output_format: str = 'json') -> str:
        """
        Create comprehensive remediation report
        
        Args:
            findings: List of findings to create report for
            output_format: Output format (json, html, markdown)
            
        Returns:
            Path to generated report file
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate remediation guidance for all findings
        remediation_data = []
        for finding in findings:
            guidance = self.generate_remediation_guidance(finding)
            remediation_data.append(guidance)
        
        # Sort by priority score (highest first)
        remediation_data.sort(key=lambda x: x['priority_score'], reverse=True)
        
        # Create report based on format
        if output_format == 'json':
            report_file = self.output_dir / f"remediation_report_{timestamp}.json"
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'report_metadata': {
                        'generated_at': datetime.now().isoformat(),
                        'total_findings': len(findings),
                        'critical_findings': len([f for f in remediation_data if f['risk_level'] == 'CRITICAL']),
                        'high_findings': len([f for f in remediation_data if f['risk_level'] == 'HIGH']),
                        'medium_findings': len([f for f in remediation_data if f['risk_level'] == 'MEDIUM']),
                        'low_findings': len([f for f in remediation_data if f['risk_level'] == 'LOW'])
                    },
                    'remediation_guidance': remediation_data
                }, f, indent=2, ensure_ascii=False)
                
        elif output_format == 'html':
            report_file = self.output_dir / f"remediation_report_{timestamp}.html"
            html_content = self._generate_html_report(remediation_data)
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
        elif output_format == 'markdown':
            report_file = self.output_dir / f"remediation_report_{timestamp}.md"
            markdown_content = self._generate_markdown_report(remediation_data)
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        logger.info(f"Remediation report generated: {report_file}")
        return str(report_file)

    def _generate_html_report(self, remediation_data: List[Dict[str, Any]]) -> str:
        """Generate HTML remediation report"""
        
        # Count findings by risk level
        risk_counts = {}
        for item in remediation_data:
            risk_level = item['risk_level']
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        html_content = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Remediation Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; }}
        .summary {{ background-color: #ecf0f1; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
        .finding {{ border: 1px solid #ddd; margin-bottom: 20px; padding: 15px; border-radius: 5px; }}
        .risk-critical {{ border-left: 5px solid #e74c3c; }}
        .risk-high {{ border-left: 5px solid #f39c12; }}
        .risk-medium {{ border-left: 5px solid #f1c40f; }}
        .risk-low {{ border-left: 5px solid #27ae60; }}
        .steps {{ margin: 10px 0; }}
        .step {{ background-color: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 3px; }}
        .timeline {{ display: flex; justify-content: space-between; background-color: #e8f4f8; padding: 10px; border-radius: 3px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Remediation Report</h1>
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>Total Findings: {len(remediation_data)}</p>
        <ul>
            <li>Critical: {risk_counts.get('CRITICAL', 0)}</li>
            <li>High: {risk_counts.get('HIGH', 0)}</li>
            <li>Medium: {risk_counts.get('MEDIUM', 0)}</li>
            <li>Low: {risk_counts.get('LOW', 0)}</li>
        </ul>
    </div>
'''
        
        for idx, item in enumerate(remediation_data, 1):
            risk_class = f"risk-{item['risk_level'].lower()}"
            
            html_content += f'''
    <div class="finding {risk_class}">
        <h3>#{idx}: {item['title']}</h3>
        <p><strong>Risk Level:</strong> {item['risk_level']} | <strong>Priority Score:</strong> {item['priority_score']:.1f}</p>
        <p><strong>Category:</strong> {item['category']} | <strong>Framework:</strong> {item['framework']}</p>
        <p><strong>Description:</strong> {item['description']}</p>
        
        <h4>Business Impact</h4>
        <p>{item['business_impact']}</p>
        
        <h4>Remediation Steps</h4>
        <div class="steps">
'''
            
            for step in item['remediation_steps']:
                html_content += f'''
            <div class="step">
                <strong>Step {step['step']}:</strong> {step['action']}<br>
                <em>Details:</em> {step['details']}<br>
                <em>Responsibility:</em> {step['responsibility']} | <em>Time:</em> {step['estimated_time']}
            </div>
'''
            
            html_content += f'''
        </div>
        
        <h4>Timeline</h4>
        <div class="timeline">
            <div><strong>Immediate:</strong> {item['timeline']['immediate_action']}</div>
            <div><strong>Full Remediation:</strong> {item['timeline']['full_remediation']}</div>
            <div><strong>Verification:</strong> {item['timeline']['verification']}</div>
        </div>
        
        <h4>Cost Estimate</h4>
        <p><strong>Effort:</strong> {item['estimated_effort']} | <strong>Cost:</strong> {item['cost_estimate']['estimated_cost']}</p>
        
        <h4>Success Criteria</h4>
        <ul>
'''
            
            for criterion in item['success_criteria']:
                html_content += f"<li>{criterion}</li>"
            
            html_content += '''
        </ul>
    </div>
'''
        
        html_content += '''
</body>
</html>
'''
        
        return html_content

    def _generate_markdown_report(self, remediation_data: List[Dict[str, Any]]) -> str:
        """Generate Markdown remediation report"""
        
        # Count findings by risk level
        risk_counts = {}
        for item in remediation_data:
            risk_level = item['risk_level']
            risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
        
        markdown_content = f'''# Security Remediation Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary

**Total Findings:** {len(remediation_data)}

- **Critical:** {risk_counts.get('CRITICAL', 0)}
- **High:** {risk_counts.get('HIGH', 0)}  
- **Medium:** {risk_counts.get('MEDIUM', 0)}
- **Low:** {risk_counts.get('LOW', 0)}

---

## Remediation Details

'''
        
        for idx, item in enumerate(remediation_data, 1):
            markdown_content += f'''### #{idx}: {item['title']}

**Risk Level:** {item['risk_level']} | **Priority Score:** {item['priority_score']:.1f}  
**Category:** {item['category']} | **Framework:** {item['framework']}  
**Urgency:** {item['urgency']} | **Effort:** {item['estimated_effort']}

#### Description
{item['description']}

#### Business Impact
{item['business_impact']}

#### Business Justification
{item['business_justification']}

#### Remediation Steps
'''
            
            for step in item['remediation_steps']:
                markdown_content += f'''
{step['step']}. **{step['action']}**
   - *Details:* {step['details']}
   - *Responsibility:* {step['responsibility']}
   - *Estimated Time:* {step['estimated_time']}
'''
            
            markdown_content += f'''
#### Testing Procedures
'''
            
            for test in item['testing_procedures']:
                markdown_content += f'''
- **{test['test']}**
  - *Procedure:* {test['procedure']}
  - *Expected Result:* {test['expected_result']}
'''
            
            markdown_content += f'''
#### Timeline
- **Immediate Action:** {item['timeline']['immediate_action']}
- **Full Remediation:** {item['timeline']['full_remediation']}
- **Verification:** {item['timeline']['verification']}
- **Documentation:** {item['timeline']['documentation']}

#### Cost Estimate
- **Labor Hours:** {item['cost_estimate']['labor_hours']}
- **Estimated Cost:** {item['cost_estimate']['estimated_cost']}
- **Cost Category:** {item['cost_estimate']['cost_category']}

#### Success Criteria
'''
            
            for criterion in item['success_criteria']:
                markdown_content += f"- {criterion}\n"
            
            markdown_content += f'''
#### Dependencies
'''
            
            for dep in item['dependencies']:
                markdown_content += f"- **{dep['type'].replace('_', ' ').title()}:** {dep['description']} (*{dep['criticality']} criticality*)\n"
            
            markdown_content += f'''
#### Stakeholders
'''
            
            for stakeholder in item['stakeholders']:
                markdown_content += f"- **{stakeholder['role']}:** {stakeholder['responsibility']} (*{stakeholder['involvement']} involvement*)\n"
            
            if item['automated_scripts']:
                markdown_content += f'''
#### Automated Scripts Available
'''
                for script in item['automated_scripts']:
                    markdown_content += f"- **{script['name']}:** {script['description']} (Platform: {script['platform']})\n"
            
            markdown_content += "\n---\n\n"
        
        return markdown_content

    def create_executive_summary(self, remediation_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Create executive summary of remediation requirements
        
        Args:
            remediation_data: List of remediation guidance data
            
        Returns:
            Dictionary containing executive summary
        """
        # Risk level counts
        risk_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for item in remediation_data:
            risk_counts[item['risk_level']] += 1
        
        # Category breakdown
        category_counts = {}
        for item in remediation_data:
            category = item['category']
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Framework breakdown
        framework_counts = {}
        for item in remediation_data:
            framework = item['framework']
            if framework:
                framework_counts[framework] = framework_counts.get(framework, 0) + 1
        
        # Cost estimation
        total_min_cost = 0
        total_max_cost = 0
        total_min_hours = 0
        total_max_hours = 0
        
        for item in remediation_data:
            cost_range = item['cost_estimate']['estimated_cost']
            hours_range = item['cost_estimate']['labor_hours']
            
            # Extract cost range
            if '-' in cost_range:
                min_cost, max_cost = cost_range.replace('() {
    echo "[+] Installing Lynis security scanner..."
    
    if command -v apt-get >/dev/null; then
        # Debian/Ubuntu
        apt-get update
        apt-get install -y lynis
    elif command -v dnf >/dev/null; then
        # Fedora/RHEL 8+
        dnf install -y lynis
    elif command -v yum >/dev/null; then
        # CentOS/RHEL 7
        yum install -y epel-release
        yum install -y lynis
    else
        # Manual installation
        echo "[+] Package manager not found, installing Lynis manually..."
        
        # Create temporary directory
        TEMP_DIR=$(mktemp -d)
        cd $TEMP_DIR
        
        # Download latest Lynis
        curl -s https://cisofy.com/files/lynis-latest.tar.gz -o lynis.tar.gz
        
        # Verify download
        if [ ! -f lynis.tar.gz ]; then
            echo "[!] Failed to download Lynis. Please install manually."
            rm -rf $TEMP_DIR
            exit 1
        fi
        
        # Extract and install
        tar xzf lynis.tar.gz
        cd lynis
        ./lynis update info
        
        # Create symbolic link
        mkdir -p /usr/local/lynis
        cp -a * /usr/local/lynis/
        ln -s /usr/local/lynis/lynis /usr/local/bin/lynis
        
        # Clean up
        cd /
        rm -rf $TEMP_DIR
    fi
    
    # Verify installation
    if ! command -v lynis >/dev/null; then
        echo "[!] Lynis installation failed. Please install manually."
        exit 1
    fi
}

# Install Lynis
install_lynis, '').replace(',', '').split('-')
                total_min_cost += int(min_cost)
                total_max_cost += int(max_cost)
            
            # Extract hours range
            if '-' in hours_range:
                min_hours, max_hours = hours_range.replace(' hours', '').split('-')
                total_min_hours += int(min_hours)
                total_max_hours += int(max_hours)
        
        # Timeline analysis
        critical_items = [item for item in remediation_data if item['risk_level'] == 'CRITICAL']
        high_items = [item for item in remediation_data if item['risk_level'] == 'HIGH']
        
        # Top priorities
        top_priorities = sorted(remediation_data, key=lambda x: x['priority_score'], reverse=True)[:5]
        
        summary = {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_findings': len(remediation_data),
                'assessment_scope': 'System-wide security assessment'
            },
            'risk_analysis': {
                'risk_distribution': risk_counts,
                'critical_findings_requiring_immediate_action': len(critical_items),
                'high_priority_findings': len(high_items),
                'overall_risk_score': sum(item['priority_score'] for item in remediation_data) / len(remediation_data) if remediation_data else 0
            },
            'category_breakdown': dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True)),
            'framework_compliance': framework_counts,
            'resource_requirements': {
                'estimated_labor_hours': f"{total_min_hours}-{total_max_hours}",
                'estimated_cost_range': f"${total_min_cost:,}-${total_max_cost:,}",
                'timeline_summary': {
                    'immediate_action_required': f"{len(critical_items)} findings",
                    'short_term_remediation': f"{len(high_items)} findings",
                    'long_term_improvements': f"{risk_counts['MEDIUM'] + risk_counts['LOW']} findings"
                }
            },
            'top_priorities': [
                {
                    'title': item['title'],
                    'risk_level': item['risk_level'],
                    'category': item['category'],
                    'priority_score': item['priority_score'],
                    'urgency': item['urgency'],
                    'business_impact': item['business_impact'][:200] + '...' if len(item['business_impact']) > 200 else item['business_impact']
                } for item in top_priorities
            ],
            'recommendations': {
                'immediate_actions': [
                    "Address all CRITICAL risk findings within 24 hours",
                    "Implement emergency response procedures for critical vulnerabilities",
                    "Ensure backup and recovery systems are operational"
                ],
                'short_term_actions': [
                    "Develop detailed remediation project plan",
                    "Assign dedicated resources for HIGH priority findings",
                    "Establish regular progress monitoring and reporting"
                ],
                'long_term_strategies': [
                    "Implement continuous security monitoring",
                    "Establish regular security assessment schedule",
                    "Develop security awareness training program",
                    "Create formal incident response procedures"
                ]
            },
            'success_metrics': [
                "Reduction in critical and high-risk findings by 90% within 30 days",
                "Implementation of automated security controls",
                "Establishment of continuous monitoring capabilities",
                "Achievement of target compliance framework requirements",
                "Improved security posture scoring in follow-up assessments"
            ]
        }
        
        return summary

    def generate_remediation_playbook(self, findings: List[Dict[str, Any]], output_dir: Optional[str] = None) -> str:
        """
        Generate comprehensive remediation playbook
        
        Args:
            findings: List of security findings
            output_dir: Output directory (optional)
            
        Returns:
            Path to generated playbook
        """
        if output_dir:
            playbook_dir = Path(output_dir)
        else:
            playbook_dir = self.output_dir / "remediation_playbook"
        
        playbook_dir.mkdir(exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate remediation guidance
        remediation_data = []
        for finding in findings:
            guidance = self.generate_remediation_guidance(finding)
            remediation_data.append(guidance)
        
        # Sort by priority
        remediation_data.sort(key=lambda x: x['priority_score'], reverse=True)
        
        # Generate executive summary
        executive_summary = self.create_executive_summary(remediation_data)
        
        # Create main playbook document
        playbook_content = self._generate_playbook_content(remediation_data, executive_summary)
        playbook_file = playbook_dir / f"security_remediation_playbook_{timestamp}.md"
        
        with open(playbook_file, 'w', encoding='utf-8') as f:
            f.write(playbook_content)
        
        # Generate supporting documents
        self._generate_supporting_documents(remediation_data, playbook_dir, timestamp)
        
        # Generate automated scripts
        for platform in ['linux', 'windows']:
            scripts = self.generate_remediation_scripts(findings, platform)
            if scripts:
                logger.info(f"Generated {len(scripts)} {platform} remediation scripts")
        
        logger.info(f"Remediation playbook generated: {playbook_file}")
        return str(playbook_file)

    def _generate_playbook_content(self, remediation_data: List[Dict[str, Any]], executive_summary: Dict[str, Any]) -> str:
        """Generate main playbook content"""
        
        content = f'''# Security Remediation Playbook

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Version:** 1.0  
**Classification:** Internal Use

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Risk Analysis](#risk-analysis)
3. [Resource Requirements](#resource-requirements)
4. [Remediation Timeline](#remediation-timeline)
5. [Detailed Remediation Plans](#detailed-remediation-plans)
6. [Implementation Checklist](#implementation-checklist)
7. [Quality Assurance](#quality-assurance)
8. [Appendices](#appendices)

---

## Executive Summary

### Overview
This playbook provides comprehensive guidance for remediating {executive_summary['report_metadata']['total_findings']} security findings identified during the security assessment. The findings span multiple categories and risk levels, requiring coordinated remediation efforts.

### Key Statistics
- **Total Findings:** {executive_summary['report_metadata']['total_findings']}
- **Critical Risk:** {executive_summary['risk_analysis']['risk_distribution']['CRITICAL']}
- **High Risk:** {executive_summary['risk_analysis']['risk_distribution']['HIGH']}
- **Medium Risk:** {executive_summary['risk_analysis']['risk_distribution']['MEDIUM']}
- **Low Risk:** {executive_summary['risk_analysis']['risk_distribution']['LOW']}

### Resource Requirements
- **Estimated Labor:** {executive_summary['resource_requirements']['estimated_labor_hours']} hours
- **Estimated Cost:** {executive_summary['resource_requirements']['estimated_cost_range']}
- **Timeline:** {executive_summary['resource_requirements']['timeline_summary']['immediate_action_required']} require immediate attention

---

## Risk Analysis

### Risk Distribution
'''
        
        for risk_level, count in executive_summary['risk_analysis']['risk_distribution'].items():
            if count > 0:
                percentage = (count / executive_summary['report_metadata']['total_findings']) * 100
                content += f"- **{risk_level}:** {count} findings ({percentage:.1f}%)\n"
        
        content += f'''

### Category Breakdown
'''
        
        for category, count in list(executive_summary['category_breakdown'].items())[:10]:
            content += f"- **{category}:** {count} findings\n"
        
        content += f'''

### Overall Risk Score
**{executive_summary['risk_analysis']['overall_risk_score']:.1f}/100** - Based on weighted priority scoring

---

## Resource Requirements

### Personnel
- **Security Administrator:** Primary remediation lead
- **System Administrators:** Technical implementation
- **Network Administrator:** Network security changes
- **IT Manager:** Project oversight and approvals
- **Compliance Officer:** Regulatory compliance verification

### Timeline Summary
- **Immediate Action Required:** {executive_summary['resource_requirements']['timeline_summary']['immediate_action_required']}
- **Short-term Remediation:** {executive_summary['resource_requirements']['timeline_summary']['short_term_remediation']}
- **Long-term Improvements:** {executive_summary['resource_requirements']['timeline_summary']['long_term_improvements']}

### Budget Requirements
- **Labor Costs:** {executive_summary['resource_requirements']['estimated_cost_range']}
- **Additional Tools/Software:** $2,000 - $5,000 (estimated)
- **Training and Certification:** $1,000 - $3,000 (estimated)

---

## Remediation Timeline

### Phase 1: Critical Issues (0-24 hours)
'''
        
        critical_items = [item for item in remediation_data if item['risk_level'] == 'CRITICAL']
        for idx, item in enumerate(critical_items, 1):
            content += f"{idx}. {item['title']} (Priority: {item['priority_score']:.1f})\n"
        
        content += f'''

### Phase 2: High Priority (1-7 days)
'''
        
        high_items = [item for item in remediation_data if item['risk_level'] == 'HIGH']
        for idx, item in enumerate(high_items[:10], 1):  # Show top 10
            content += f"{idx}. {item['title']} (Priority: {item['priority_score']:.1f})\n"
        
        content += f'''

### Phase 3: Medium Priority (1-4 weeks)
- {len([item for item in remediation_data if item['risk_level'] == 'MEDIUM'])} medium priority findings
- Focus on systematic implementation of security controls
- Establish ongoing monitoring and maintenance procedures

### Phase 4: Low Priority (1-3 months)
- {len([item for item in remediation_data if item['risk_level'] == 'LOW'])} low priority findings
- Continuous improvement and optimization
- Security awareness and training initiatives

---

## Detailed Remediation Plans

'''
        
        # Include detailed plans for top priority items
        top_items = sorted(remediation_data, key=lambda x: x['priority_score'], reverse=True)[:10]
        
        for idx, item in enumerate(top_items, 1):
            content += f'''### {idx}. {item['title']}

**Risk Level:** {item['risk_level']} | **Priority Score:** {item['priority_score']:.1f}  
**Category:** {item['category']} | **Estimated Effort:** {item['estimated_effort']}

#### Description
{item['description']}

#### Business Impact
{item['business_impact']}

#### Implementation Steps
'''
            
            for step in item['remediation_steps']:
                content += f'''
{step['step']}. **{step['action']}**
   - Details: {step['details']}
   - Responsibility: {step['responsibility']}
   - Time Estimate: {step['estimated_time']}
'''
            
            content += f'''
#### Success Criteria
'''
            for criterion in item['success_criteria']:
                content += f"- {criterion}\n"
            
            content += f'''
#### Verification
- Method: {item['verification_method']}
- Timeline: {item['timeline']['verification']}

---

'''
        
        content += f'''## Implementation Checklist

### Pre-Implementation
- [ ] Review and approve remediation plan
- [ ] Assign responsible personnel
- [ ] Schedule maintenance windows
- [ ] Prepare rollback procedures
- [ ] Backup critical configurations

### Critical Phase (24 hours)
'''
        
        for item in critical_items:
            content += f"- [ ] {item['title']}\n"
        
        content += f'''

### High Priority Phase (1 week)
'''
        
        for item in high_items[:5]:  # Top 5 high priority
            content += f"- [ ] {item['title']}\n"
        
        content += f'''

### Post-Implementation
- [ ] Verify all remediation steps completed
- [ ] Conduct security assessment validation
- [ ] Update documentation and procedures
- [ ] Report completion to stakeholders
- [ ] Schedule follow-up reviews

---

## Quality Assurance

### Testing Requirements
- All changes must be tested in non-production environment first
- Document test results before production implementation
- Verify functionality after each remediation step
- Conduct security validation scanning

### Documentation Standards
- Maintain detailed implementation logs
- Document all configuration changes
- Record test results and validation evidence
- Update system documentation and procedures

### Communication Plan
- Daily status updates during critical phase
- Weekly progress reports to management
- Immediate notification of any issues or delays
- Final completion report with evidence package

---

## Appendices

### Appendix A: Automated Scripts
Automated remediation scripts are available in the `remediation_scripts/` directory:
'''
        
        # List available automated scripts
        for platform in ['linux', 'windows']:
            platform_scripts = []
            for category, templates in self.remediation_templates.get(platform, {}).items():
                platform_scripts.append(f"- {templates['name']}: {templates['description']}")
            
            if platform_scripts:
                content += f'''
#### {platform.title()} Scripts
'''
                content += '\n'.join(platform_scripts) + '\n'
        
        content += f'''

### Appendix B: Reference Links
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Critical Security Controls](https://www.cisecurity.org/controls/)
- [ISO 27001 Information Security](https://www.iso.org/isoiec-27001-information-security.html)

### Appendix C: Contact Information
- **IT Manager:** [Contact Information]
- **Security Team:** [Contact Information]  
- **Network Team:** [Contact Information]
- **Emergency Contact:** [Contact Information]

---

*This playbook is a living document and should be updated as remediation progresses and new findings are identified.*
'''
        
        return content

    def _generate_supporting_documents(self, remediation_data: List[Dict[str, Any]], playbook_dir: Path, timestamp: str):
        """Generate supporting documents for the playbook"""
        
        # Create executive summary document
        exec_summary = self.create_executive_summary(remediation_data)
        exec_file = playbook_dir / f"executive_summary_{timestamp}.json"
        with open(exec_file, 'w', encoding='utf-8') as f:
            json.dump(exec_summary, f, indent=2, ensure_ascii=False)
        
        # Create detailed remediation data
        detailed_file = playbook_dir / f"detailed_remediation_{timestamp}.json"
        with open(detailed_file, 'w', encoding='utf-8') as f:
            json.dump(remediation_data, f, indent=2, ensure_ascii=False)
        
        # Create implementation tracking spreadsheet data
        tracking_data = []
        for item in remediation_data:
            tracking_data.append({
                'ID': item['finding_id'],
                'Title': item['title'],
                'Risk Level': item['risk_level'],
                'Category': item['category'],
                'Priority Score': item['priority_score'],
                'Status': 'Not Started',
                'Assigned To': '',
                'Due Date': '',
                'Completion Date': '',
                'Notes': ''
            })
        
        tracking_file = playbook_dir / f"implementation_tracking_{timestamp}.json"
        with open(tracking_file, 'w', encoding='utf-8') as f:
            json.dump(tracking_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Supporting documents generated in {playbook_dir}")

# Example usage and test functions
def main():
    """Example usage of the Enhanced Remediation module"""
    
    # Initialize remediation module
    remediation = EnhancedRemediation()
    
    # Example findings data
    example_findings = [
        {
            'id': 'SEC-001',
            'title': 'Firewall not configured properly',
            'description': 'System firewall is disabled or misconfigured, allowing unauthorized network access',
            'category': 'Network Security',
            'risk_level': 'HIGH',
            'framework': 'CIS'
        },
        {
            'id': 'SEC-002', 
            'title': 'Missing security patches',
            'description': 'Critical security patches are missing from the system',
            'category': 'Vulnerability Management',
            'risk_level': 'CRITICAL',
            'framework': 'ISO27001'
        },
        {
            'id': 'SEC-003',
            'title': 'Weak password policy',
            'description': 'Password policy does not meet security requirements',
            'category': 'Access Control',
            'risk_level': 'MEDIUM',
            'framework': 'RBI'
        },
        {
            'id': 'SEC-004',
            'title': 'SSH configuration insecure',
            'description': 'SSH server configuration allows insecure access methods',
            'category': 'Configuration Management', 
            'risk_level': 'HIGH',
            'framework': 'CIS'
        },
        {
            'id': 'SEC-005',
            'title': 'Insufficient logging enabled',
            'description': 'System logging is not comprehensive enough for security monitoring',
            'category': 'Logging and Monitoring',
            'risk_level': 'MEDIUM',
            'framework': 'ISO27001'
        }
    ]
    
    print("Enhanced Remediation Module - Example Usage")
    print("=" * 50)
    
    # Generate remediation guidance
    print("Generating remediation guidance...")
    remediation_guidance = []
    for finding in example_findings:
        guidance = remediation.generate_remediation_guidance(finding)
        remediation_guidance.append(guidance)
        print(f"- Generated guidance for: {finding['title']}")
    
    # Generate automated scripts
    print("\nGenerating automated remediation scripts...")
    linux_scripts = remediation.generate_remediation_scripts(example_findings, 'linux')
    windows_scripts = remediation.generate_remediation_scripts(example_findings, 'windows')
    
    print(f"- Generated {len(linux_scripts)} Linux scripts")
    print(f"- Generated {len(windows_scripts)} Windows scripts")
    
    # Create comprehensive reports
    print("\nCreating remediation reports...")
    
    # JSON report
    json_report = remediation.create_remediation_report(example_findings, 'json')
    print(f"- JSON report: {json_report}")
    
    # HTML report
    html_report = remediation.create_remediation_report(example_findings, 'html')
    print(f"- HTML report: {html_report}")
    
    # Markdown report
    md_report = remediation.create_remediation_report(example_findings, 'markdown')
    print(f"- Markdown report: {md_report}")
    
    # Generate complete remediation playbook
    print("\nGenerating comprehensive remediation playbook...")
    playbook_path = remediation.generate_remediation_playbook(example_findings)
    print(f"- Playbook generated: {playbook_path}")
    
    # Create executive summary
    print("\nGenerating executive summary...")
    exec_summary = remediation.create_executive_summary(remediation_guidance)
    print(f"- Total findings: {exec_summary['report_metadata']['total_findings']}")
    print(f"- Critical findings: {exec_summary['risk_analysis']['risk_distribution']['CRITICAL']}")
    print(f"- Overall risk score: {exec_summary['risk_analysis']['overall_risk_score']:.1f}")
    
    print("\n" + "=" * 50)
    print("Enhanced Remediation Module execution completed successfully!")
    print(f"All outputs saved to: {remediation.output_dir}")

if __name__ == "__main__":
    main()() {
    echo "[+] Installing Lynis security scanner..."
    
    if command -v apt-get >/dev/null; then
        # Debian/Ubuntu
        apt-get update
        apt-get install -y lynis
    elif command -v dnf >/dev/null; then
        # Fedora/RHEL 8+
        dnf install -y lynis
    elif command -v yum >/dev/null; then
        # CentOS/RHEL 7
        yum install -y epel-release
        yum install -y lynis
    else
        # Manual installation
        echo "[+] Package manager not found, installing Lynis manually..."
        
        # Create temporary directory
        TEMP_DIR=$(mktemp -d)
        cd $TEMP_DIR
        
        # Download latest Lynis
        curl -s https://cisofy.com/files/lynis-latest.tar.gz -o lynis.tar.gz
        
        # Verify download
        if [ ! -f lynis.tar.gz ]; then
            echo "[!] Failed to download Lynis. Please install manually."
            rm -rf $TEMP_DIR
            exit 1
        fi
        
        # Extract and install
        tar xzf lynis.tar.gz
        cd lynis
        ./lynis update info
        
        # Create symbolic link
        mkdir -p /usr/local/lynis
        cp -a * /usr/local/lynis/
        ln -s /usr/local/lynis/lynis /usr/local/bin/lynis
        
        # Clean up
        cd /
        rm -rf $TEMP_DIR
    fi
    
    # Verify installation
    if ! command -v lynis >/dev/null; then
        echo "[!] Lynis installation failed. Please install manually."
        exit 1
    fi
}

# Install Lynis
install_lynis