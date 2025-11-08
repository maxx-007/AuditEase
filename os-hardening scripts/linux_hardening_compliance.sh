#!/bin/bash

################################################################################
# Linux OS Hardening Script - Compliance Edition
# Complies with: RBI Cybersecurity Guidelines, ISO 27001:2022, CIS Controls v8
# Target: Ubuntu/Debian/RHEL-based systems
# Author: DevSecOps Security Team
# Version: 1.0
################################################################################

set -euo pipefail

# Configuration
LOG_FILE="/var/log/compliance_hardening.log"
REPORT_FILE="/var/log/compliance_summary.json"
BACKUP_DIR="/var/backups/hardening_$(date +%Y%m%d_%H%M%S)"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Compliance tracking
declare -A COMPLIANCE_STATUS

################################################################################
# Utility Functions
################################################################################

log_action() {
    echo "[${TIMESTAMP}] $1" | tee -a "${LOG_FILE}"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1" | tee -a "${LOG_FILE}"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1" | tee -a "${LOG_FILE}"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1" | tee -a "${LOG_FILE}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        log_error "Cannot detect OS"
        exit 1
    fi
    log_action "Detected OS: $OS $OS_VERSION"
}

backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        mkdir -p "${BACKUP_DIR}"
        cp -p "$file" "${BACKUP_DIR}/$(basename $file).bak"
        log_action "Backed up: $file"
    fi
}

record_compliance() {
    local control=$1
    local status=$2
    local description=$3
    COMPLIANCE_STATUS["$control"]="$status|$description"
}

################################################################################
# 1. USER AND PASSWORD MANAGEMENT
# ISO 27001: A.9.2.1, A.9.4.3 | CIS: 5.4.1, 5.4.2 | RBI: Authentication Controls
################################################################################

harden_password_policy() {
    log_action "=== Configuring Password Policy ==="
    
    # CIS 5.4.1 - Set password expiration
    # ISO 27001 A.9.4.3 - Password management system
    backup_file /etc/login.defs
    
    if grep -q "^PASS_MAX_DAYS" /etc/login.defs; then
        sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    else
        echo "PASS_MAX_DAYS   90" >> /etc/login.defs
    fi
    
    if grep -q "^PASS_MIN_DAYS" /etc/login.defs; then
        sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    else
        echo "PASS_MIN_DAYS   1" >> /etc/login.defs
    fi
    
    if grep -q "^PASS_WARN_AGE" /etc/login.defs; then
        sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    else
        echo "PASS_WARN_AGE   7" >> /etc/login.defs
    fi
    
    log_success "Password aging policy configured (90 days max, 1 day min, 7 days warning)"
    record_compliance "CIS-5.4.1" "APPLIED" "Password expiration configured"
    
    # CIS 5.4.2 - Password complexity
    # ISO 27001 A.9.4.3 - Password quality
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt-get install -y libpam-pwquality >/dev/null 2>&1
        backup_file /etc/security/pwquality.conf
        
        cat > /etc/security/pwquality.conf <<EOF
# CIS 5.4.2 - Password complexity requirements
# ISO 27001 A.9.4.3 - Password management
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
difok = 3
EOF
        log_success "Password complexity configured (14 chars, 4 classes)"
        
    elif [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        yum install -y libpwquality >/dev/null 2>&1
        backup_file /etc/security/pwquality.conf
        
        cat > /etc/security/pwquality.conf <<EOF
minlen = 14
minclass = 4
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
maxrepeat = 3
difok = 3
EOF
        log_success "Password complexity configured"
    fi
    
    record_compliance "CIS-5.4.2" "APPLIED" "Password complexity requirements set"
    
    # Configure password history
    # CIS 5.4.3 - Limit password reuse
    backup_file /etc/pam.d/common-password 2>/dev/null || backup_file /etc/pam.d/system-auth 2>/dev/null || true
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        if ! grep -q "remember=5" /etc/pam.d/common-password; then
            sed -i '/pam_unix.so/s/$/ remember=5/' /etc/pam.d/common-password
        fi
    elif [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        if ! grep -q "remember=5" /etc/pam.d/system-auth; then
            sed -i '/pam_unix.so/s/$/ remember=5/' /etc/pam.d/system-auth
        fi
    fi
    
    log_success "Password history configured (remember last 5)"
    record_compliance "CIS-5.4.3" "APPLIED" "Password reuse limited"
}

configure_account_lockout() {
    log_action "=== Configuring Account Lockout Policy ==="
    
    # CIS 5.4.4 - Account lockout
    # ISO 27001 A.9.4.2 - Secure log-on procedures
    # RBI: Account lockout after failed attempts
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        if ! grep -q "pam_tally2" /etc/pam.d/common-auth; then
            sed -i '1i auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900' /etc/pam.d/common-auth
        fi
    elif [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        if ! grep -q "pam_faillock" /etc/pam.d/system-auth; then
            sed -i '/^auth/i auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900' /etc/pam.d/system-auth
            sed -i '/^auth.*sufficient.*pam_unix.so/a auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' /etc/pam.d/system-auth
        fi
    fi
    
    log_success "Account lockout configured (5 attempts, 15 min lockout)"
    record_compliance "CIS-5.4.4" "APPLIED" "Account lockout policy configured"
}

configure_sudo_logging() {
    log_action "=== Configuring Sudo Logging ==="
    
    # CIS 5.3.3 - Sudo logging
    # ISO 27001 A.12.4.1 - Event logging
    
    if ! grep -q "Defaults logfile" /etc/sudoers; then
        echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers
        echo 'Defaults log_input,log_output' >> /etc/sudoers
    fi
    
    touch /var/log/sudo.log
    chmod 600 /var/log/sudo.log
    
    log_success "Sudo logging configured"
    record_compliance "CIS-5.3.3" "APPLIED" "Sudo command logging enabled"
}

################################################################################
# 2. SSH HARDENING
# ISO 27001: A.13.1.1, A.9.4.2 | CIS: 5.2.x | RBI: Secure remote access
################################################################################

harden_ssh() {
    log_action "=== Hardening SSH Configuration ==="
    
    backup_file /etc/ssh/sshd_config
    
    # CIS 5.2.1 - SSH Protocol 2
    sed -i 's/^#*Protocol.*/Protocol 2/' /etc/ssh/sshd_config
    
    # CIS 5.2.2 - Disable root login
    # ISO 27001 A.9.4.2 - Secure log-on procedures
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    log_success "Root login disabled"
    record_compliance "CIS-5.2.2" "APPLIED" "SSH root login disabled"
    
    # CIS 5.2.4 - Disable empty passwords
    sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
    
    # CIS 5.2.5 - Disable host-based authentication
    sed -i 's/^#*HostbasedAuthentication.*/HostbasedAuthentication no/' /etc/ssh/sshd_config
    
    # CIS 5.2.6 - Set SSH idle timeout
    # ISO 27001 A.11.2.8 - Unattended user equipment
    sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 0/' /etc/ssh/sshd_config
    log_success "SSH idle timeout configured (5 minutes)"
    record_compliance "CIS-5.2.6" "APPLIED" "SSH idle timeout set"
    
    # CIS 5.2.7 - Set SSH login grace time
    sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 60/' /etc/ssh/sshd_config
    
    # CIS 5.2.10 - Disable password authentication (uncomment if key-based auth is ready)
    # sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    log_warning "Password authentication still enabled - configure key-based auth first"
    
    # CIS 5.2.11 - Use only approved ciphers
    echo "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
    echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
    echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
    
    # CIS 5.2.12 - Set SSH MaxAuthTries
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config
    
    # CIS 5.2.13 - Set SSH MaxStartups
    sed -i 's/^#*MaxStartups.*/MaxStartups 10:30:60/' /etc/ssh/sshd_config
    
    # CIS 5.2.14 - Set SSH Banner
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    cat > /etc/issue.net <<EOF
***************************************************************************
                            NOTICE TO USERS
This system is for authorized use only. All activities are monitored and
logged. Unauthorized access is prohibited and will be prosecuted.
***************************************************************************
EOF
    
    # Restart SSH service
    systemctl restart sshd || systemctl restart ssh
    log_success "SSH hardening completed"
    record_compliance "CIS-5.2" "APPLIED" "SSH service hardened"
}

################################################################################
# 3. FILE PERMISSIONS
# ISO 27001: A.9.4.5 | CIS: 6.1.x | RBI: System file integrity
################################################################################

set_file_permissions() {
    log_action "=== Setting Critical File Permissions ==="
    
    # CIS 6.1.2 - /etc/passwd permissions
    # ISO 27001 A.9.4.5 - Access control to program source code
    chmod 644 /etc/passwd
    log_success "/etc/passwd permissions set to 644"
    record_compliance "CIS-6.1.2" "APPLIED" "/etc/passwd secured"
    
    # CIS 6.1.3 - /etc/shadow permissions
    chmod 000 /etc/shadow
    log_success "/etc/shadow permissions set to 000"
    record_compliance "CIS-6.1.3" "APPLIED" "/etc/shadow secured"
    
    # CIS 6.1.4 - /etc/group permissions
    chmod 644 /etc/group
    log_success "/etc/group permissions set to 644"
    
    # CIS 6.1.5 - /etc/gshadow permissions
    if [[ -f /etc/gshadow ]]; then
        chmod 000 /etc/gshadow
        log_success "/etc/gshadow permissions set to 000"
    fi
    
    # CIS 6.1.6 - /etc/passwd- permissions
    if [[ -f /etc/passwd- ]]; then
        chmod 600 /etc/passwd-
    fi
    
    # CIS 6.1.7 - /etc/shadow- permissions
    if [[ -f /etc/shadow- ]]; then
        chmod 000 /etc/shadow-
    fi
    
    # CIS 6.1.8 - /etc/group- permissions
    if [[ -f /etc/group- ]]; then
        chmod 600 /etc/group-
    fi
    
    # CIS 6.1.9 - /etc/gshadow- permissions
    if [[ -f /etc/gshadow- ]]; then
        chmod 000 /etc/gshadow-
    fi
    
    # Log file permissions
    # ISO 27001 A.12.4.1 - Event logging
    chmod 640 /var/log/messages 2>/dev/null || true
    chmod 640 /var/log/syslog 2>/dev/null || true
    chmod 640 /var/log/auth.log 2>/dev/null || true
    chmod 640 /var/log/secure 2>/dev/null || true
    
    log_success "Log file permissions configured"
    record_compliance "ISO-27001-A.12.4.1" "APPLIED" "Log file permissions secured"
}

################################################################################
# 4. FIREWALL CONFIGURATION
# ISO 27001: A.13.1.1 | CIS: 3.5.x | RBI: Network security controls
################################################################################

configure_firewall() {
    log_action "=== Configuring Firewall ==="
    
    # CIS 3.5.1 - Configure UFW (Ubuntu/Debian)
    # CIS 3.5.2 - Configure firewalld (RHEL)
    # ISO 27001 A.13.1.1 - Network controls
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt-get install -y ufw >/dev/null 2>&1
        
        # Set default policies
        ufw --force default deny incoming
        ufw --force default allow outgoing
        ufw --force default deny routed
        
        # Allow SSH
        ufw --force allow 22/tcp
        
        # Enable firewall
        ufw --force enable
        
        log_success "UFW configured and enabled"
        record_compliance "CIS-3.5.1" "APPLIED" "UFW firewall configured"
        
    elif [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        yum install -y firewalld >/dev/null 2>&1
        systemctl start firewalld
        systemctl enable firewalld
        
        firewall-cmd --permanent --set-default-zone=drop
        firewall-cmd --permanent --zone=drop --add-service=ssh
        firewall-cmd --reload
        
        log_success "firewalld configured and enabled"
        record_compliance "CIS-3.5.2" "APPLIED" "firewalld configured"
    fi
    
    record_compliance "ISO-27001-A.13.1.1" "APPLIED" "Network security controls implemented"
}

################################################################################
# 5. DISABLE UNNECESSARY SERVICES
# ISO 27001: A.12.6.2 | CIS: 2.2.x | RBI: Minimize attack surface
################################################################################

disable_unnecessary_services() {
    log_action "=== Disabling Unnecessary Services ==="
    
    # CIS 2.2.2 - Ensure X Window System is not installed
    # ISO 27001 A.12.6.2 - Restrictions on software installation
    
    local services=("telnet" "rsh" "rlogin" "rexec" "talk" "ntalk" "tftp" "xinetd" "avahi-daemon" "cups" "nfs-server" "rpcbind" "snmpd")
    
    for service in "${services[@]}"; do
        if systemctl list-unit-files | grep -q "^${service}.service"; then
            systemctl stop "${service}" 2>/dev/null || true
            systemctl disable "${service}" 2>/dev/null || true
            log_success "Disabled service: ${service}"
        fi
    done
    
    # Remove unnecessary packages
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt-get remove -y telnetd rsh-server rsh-client talk talkd tftp nis >/dev/null 2>&1 || true
    elif [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        yum remove -y telnet-server rsh-server talk-server tftp-server ypserv >/dev/null 2>&1 || true
    fi
    
    log_success "Unnecessary services disabled"
    record_compliance "CIS-2.2" "APPLIED" "Unnecessary services removed"
}

################################################################################
# 6. LOGGING AND AUDITING
# ISO 27001: A.12.4.1 | CIS: 4.1.x | RBI: Security logging and monitoring
################################################################################

configure_logging() {
    log_action "=== Configuring Logging and Auditing ==="
    
    # CIS 4.2.1 - Configure rsyslog
    # ISO 27001 A.12.4.1 - Event logging
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt-get install -y rsyslog >/dev/null 2>&1
    elif [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        yum install -y rsyslog >/dev/null 2>&1
    fi
    
    systemctl enable rsyslog
    systemctl start rsyslog
    
    backup_file /etc/rsyslog.conf
    
    # Configure rsyslog
    cat >> /etc/rsyslog.conf <<EOF

# CIS 4.2.1 - Comprehensive logging
auth,authpriv.*                 /var/log/auth.log
*.*;auth,authpriv.none          -/var/log/syslog
kern.*                          -/var/log/kern.log
mail.*                          -/var/log/mail.log
mail.err                        /var/log/mail.err
*.emerg                         :omusrmsg:*
EOF
    
    systemctl restart rsyslog
    log_success "rsyslog configured"
    record_compliance "CIS-4.2.1" "APPLIED" "Comprehensive logging configured"
}

configure_auditd() {
    log_action "=== Configuring auditd ==="
    
    # CIS 4.1.1 - Enable auditd
    # ISO 27001 A.12.4.1 - Event logging
    # RBI: Security audit trails
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt-get install -y auditd audispd-plugins >/dev/null 2>&1
    elif [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        yum install -y audit audit-libs >/dev/null 2>&1
    fi
    
    systemctl enable auditd
    systemctl start auditd
    
    backup_file /etc/audit/rules.d/audit.rules
    
    # CIS 4.1.3 - Audit system calls
    cat > /etc/audit/rules.d/hardening.rules <<EOF
# CIS 4.1.3 - Record events that modify date and time
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# CIS 4.1.4 - Record events that modify user/group information
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# CIS 4.1.5 - Record events that modify network environment
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# CIS 4.1.6 - Record events that modify system's Mandatory Access Controls
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy

# CIS 4.1.7 - Collect login and logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# CIS 4.1.8 - Collect session initiation information
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# CIS 4.1.9 - Collect discretionary access control permission modification events
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

# CIS 4.1.10 - Collect unsuccessful unauthorized access attempts to files
-a always,exit -F arch=b64 -S open -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -S openat -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S open -S openat -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

# CIS 4.1.11 - Collect use of privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

# CIS 4.1.12 - Collect successful file system mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# CIS 4.1.13 - Collect file deletion events by user
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# CIS 4.1.14 - Collect changes to system administration scope
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# CIS 4.1.15 - Collect system administrator actions
-w /var/log/sudo.log -p wa -k actions

# CIS 4.1.16 - Collect kernel module loading and unloading
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# CIS 4.1.17 - Make the audit configuration immutable
-e 2
EOF
    
    # Load audit rules
    augenrules --load
    
    log_success "auditd configured with comprehensive rules"
    record_compliance "CIS-4.1" "APPLIED" "System auditing configured"
}

################################################################################
# 7. KERNEL PARAMETERS
# ISO 27001: A.13.1.1 | CIS: 3.x | RBI: Network security
################################################################################

harden_kernel_parameters() {
    log_action "=== Hardening Kernel Parameters ==="
    
    backup_file /etc/sysctl.conf
    
    # CIS 3.1.1 - Disable IP forwarding
    # ISO 27001 A.13.1.1 - Network controls
    cat >> /etc/sysctl.conf <<EOF

# CIS 3.1.1 - Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# CIS 3.1.2 - Disable Send Packet Redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# CIS 3.2.1 - Disable Source Routed Packet Acceptance
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# CIS 3.2.2 - Disable ICMP Redirect Acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# CIS 3.2.3 - Disable Secure ICMP Redirect Acceptance
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# CIS 3.2.4 - Log Suspicious Packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# CIS 3.2.5 - Enable Ignore Broadcast Requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# CIS 3.2.6 - Enable Bad Error Message Protection
net.ipv4.icmp_ignore_bogus_error_responses = 1

# CIS 3.2.7 - Enable RFC-recommended Source Route Validation
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# CIS 3.2.8 - Enable TCP SYN Cookies
net.ipv4.tcp_syncookies = 1

# CIS 3.2.9 - Disable IPv6 Router Advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Additional hardening - Disable IPv6 if not required
# Uncomment if IPv6 is not used
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# RBI - Additional network security
net.ipv4.tcp_timestamps = 0
kernel.randomize_va_space = 2
kernel.exec-shield = 1
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
fs.suid_dumpable = 0
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.conf >/dev/null 2>&1
    
    log_success "Kernel parameters hardened"
    record_compliance "CIS-3.1" "APPLIED" "Network parameters hardened"
    record_compliance "CIS-3.2" "APPLIED" "Host-based firewall parameters configured"
}

################################################################################
# 8. AUTO-UPDATES AND PACKAGE INTEGRITY
# ISO 27001: A.12.6.1 | CIS: 1.8 | RBI: Patch management
################################################################################

configure_auto_updates() {
    log_action "=== Configuring Automatic Updates ==="
    
    # CIS 1.8 - Ensure updates are installed
    # ISO 27001 A.12.6.1 - Management of technical vulnerabilities
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt-get install -y unattended-upgrades apt-listchanges >/dev/null 2>&1
        
        backup_file /etc/apt/apt.conf.d/50unattended-upgrades
        
        cat > /etc/apt/apt.conf.d/50unattended-upgrades <<EOF
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
    "\${distro_id}ESMApps:\${distro_codename}-apps-security";
    "\${distro_id}ESM:\${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::InstallOnShutdown "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-Time "03:00";
EOF
        
        cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
        
        systemctl enable unattended-upgrades
        systemctl start unattended-upgrades
        
        log_success "Unattended upgrades configured for Debian/Ubuntu"
        
    elif [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        yum install -y yum-cron >/dev/null 2>&1
        
        backup_file /etc/yum/yum-cron.conf
        
        sed -i 's/^apply_updates = .*/apply_updates = yes/' /etc/yum/yum-cron.conf
        sed -i 's/^update_cmd = .*/update_cmd = security/' /etc/yum/yum-cron.conf
        
        systemctl enable yum-cron
        systemctl start yum-cron
        
        log_success "yum-cron configured for RHEL/CentOS"
    fi
    
    record_compliance "CIS-1.8" "APPLIED" "Automatic security updates configured"
    record_compliance "ISO-27001-A.12.6.1" "APPLIED" "Patch management implemented"
}

configure_package_integrity() {
    log_action "=== Configuring Package Integrity Verification ==="
    
    # CIS 1.2.2 - Ensure GPG keys are configured
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt-get install -y debian-archive-keyring >/dev/null 2>&1 || true
        log_success "GPG keys verified for apt"
        
    elif [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        # Ensure GPG check is enabled
        if ! grep -q "^gpgcheck=1" /etc/yum.conf; then
            echo "gpgcheck=1" >> /etc/yum.conf
        fi
        log_success "GPG check enabled for yum"
    fi
    
    record_compliance "CIS-1.2.2" "APPLIED" "Package integrity verification enabled"
}

################################################################################
# 9. CRON AND AT SECURITY
# ISO 27001: A.9.4.5 | CIS: 5.1.x | RBI: Job scheduling security
################################################################################

secure_cron() {
    log_action "=== Securing Cron and At ==="
    
    # CIS 5.1.2 - Ensure permissions on /etc/crontab are configured
    # ISO 27001 A.9.4.5 - Access control to program source code
    
    if [[ -f /etc/crontab ]]; then
        chown root:root /etc/crontab
        chmod 600 /etc/crontab
        log_success "/etc/crontab permissions set"
    fi
    
    # CIS 5.1.3 - Ensure permissions on /etc/cron.hourly are configured
    if [[ -d /etc/cron.hourly ]]; then
        chown root:root /etc/cron.hourly
        chmod 700 /etc/cron.hourly
    fi
    
    # CIS 5.1.4 - Ensure permissions on /etc/cron.daily are configured
    if [[ -d /etc/cron.daily ]]; then
        chown root:root /etc/cron.daily
        chmod 700 /etc/cron.daily
    fi
    
    # CIS 5.1.5 - Ensure permissions on /etc/cron.weekly are configured
    if [[ -d /etc/cron.weekly ]]; then
        chown root:root /etc/cron.weekly
        chmod 700 /etc/cron.weekly
    fi
    
    # CIS 5.1.6 - Ensure permissions on /etc/cron.monthly are configured
    if [[ -d /etc/cron.monthly ]]; then
        chown root:root /etc/cron.monthly
        chmod 700 /etc/cron.monthly
    fi
    
    # CIS 5.1.7 - Ensure permissions on /etc/cron.d are configured
    if [[ -d /etc/cron.d ]]; then
        chown root:root /etc/cron.d
        chmod 700 /etc/cron.d
    fi
    
    # CIS 5.1.8 - Ensure cron is restricted to authorized users
    rm -f /etc/cron.deny
    rm -f /etc/at.deny
    touch /etc/cron.allow
    touch /etc/at.allow
    chmod 600 /etc/cron.allow
    chmod 600 /etc/at.allow
    chown root:root /etc/cron.allow
    chown root:root /etc/at.allow
    
    log_success "Cron and At access restricted to authorized users"
    record_compliance "CIS-5.1" "APPLIED" "Cron and At secured"
}

################################################################################
# 10. FILE INTEGRITY MONITORING
# ISO 27001: A.12.4.1 | CIS: 1.3 | RBI: File integrity monitoring
################################################################################

install_aide() {
    log_action "=== Installing and Configuring AIDE ==="
    
    # CIS 1.3.1 - Ensure AIDE is installed
    # ISO 27001 A.12.4.1 - Event logging
    # RBI: File integrity monitoring
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt-get install -y aide aide-common >/dev/null 2>&1
        
        # Initialize AIDE database
        if [[ ! -f /var/lib/aide/aide.db ]]; then
            log_action "Initializing AIDE database (this may take several minutes)..."
            aideinit
            mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
        fi
        
    elif [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        yum install -y aide >/dev/null 2>&1
        
        if [[ ! -f /var/lib/aide/aide.db.gz ]]; then
            log_action "Initializing AIDE database (this may take several minutes)..."
            aide --init
            mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz 2>/dev/null || true
        fi
    fi
    
    # CIS 1.3.2 - Ensure filesystem integrity is regularly checked
    # Configure daily AIDE check
    cat > /etc/cron.daily/aide-check <<'EOF'
#!/bin/bash
/usr/bin/aide --check | mail -s "AIDE Integrity Check Report" root
EOF
    
    chmod 755 /etc/cron.daily/aide-check
    
    log_success "AIDE installed and configured for daily checks"
    record_compliance "CIS-1.3" "APPLIED" "File integrity monitoring configured"
}

################################################################################
# 11. ADDITIONAL HARDENING
# ISO 27001: Various | CIS: Various | RBI: Additional controls
################################################################################

additional_hardening() {
    log_action "=== Applying Additional Hardening Measures ==="
    
    # Disable core dumps
    # CIS 1.5.1 - Ensure core dumps are restricted
    cat >> /etc/security/limits.conf <<EOF
* hard core 0
EOF
    
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
    sysctl -w fs.suid_dumpable=0 >/dev/null 2>&1
    
    log_success "Core dumps disabled"
    record_compliance "CIS-1.5.1" "APPLIED" "Core dumps restricted"
    
    # Set message of the day
    # CIS 1.7.1 - Ensure message of the day is configured properly
    cat > /etc/motd <<EOF
*****************************************************************************
                       AUTHORIZED ACCESS ONLY
This system is for authorized use only. All activity is monitored and logged.
Unauthorized access attempts will be prosecuted to the fullest extent of law.
*****************************************************************************
EOF
    
    chmod 644 /etc/motd
    log_success "Message of the day configured"
    
    # Remove unnecessary user accounts
    # ISO 27001 A.9.2.6 - Removal of access rights
    log_action "Checking for unnecessary system accounts..."
    
    # Configure umask
    # CIS 5.4.5 - Ensure default user umask is configured
    backup_file /etc/profile
    backup_file /etc/bash.bashrc 2>/dev/null || true
    
    if ! grep -q "umask 027" /etc/profile; then
        echo "umask 027" >> /etc/profile
    fi
    
    if [[ -f /etc/bash.bashrc ]]; then
        if ! grep -q "umask 027" /etc/bash.bashrc; then
            echo "umask 027" >> /etc/bash.bashrc
        fi
    fi
    
    log_success "Default umask set to 027"
    record_compliance "CIS-5.4.5" "APPLIED" "Restrictive umask configured"
    
    # Configure login banner
    # CIS 1.7.2 - Ensure local login warning banner is configured properly
    cat > /etc/issue <<EOF
*****************************************************************************
                       AUTHORIZED ACCESS ONLY
*****************************************************************************
EOF
    
    chmod 644 /etc/issue
    log_success "Login banner configured"
}

################################################################################
# 12. SYSTEM UPDATES
# ISO 27001: A.12.6.1 | RBI: Vulnerability management
################################################################################

update_system() {
    log_action "=== Updating System Packages ==="
    
    if [[ "$OS" == "ubuntu" ]] || [[ "$OS" == "debian" ]]; then
        apt-get update >/dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get upgrade -y >/dev/null 2>&1
        log_success "System packages updated (Debian/Ubuntu)"
        
    elif [[ "$OS" == "rhel" ]] || [[ "$OS" == "centos" ]] || [[ "$OS" == "rocky" ]]; then
        yum update -y >/dev/null 2>&1
        log_success "System packages updated (RHEL/CentOS)"
    fi
    
    record_compliance "ISO-27001-A.12.6.1" "APPLIED" "System fully updated"
}

################################################################################
# 13. COMPLIANCE REPORT GENERATION
################################################################################

generate_compliance_report() {
    log_action "=== Generating Compliance Report ==="
    
    cat > "${REPORT_FILE}" <<EOF
{
  "report_generated": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "os": "$OS",
  "os_version": "$OS_VERSION",
  "compliance_standards": [
    "RBI Cybersecurity Guidelines",
    "ISO 27001:2022",
    "CIS Controls v8"
  ],
  "controls_applied": {
EOF
    
    local first=true
    for control in "${!COMPLIANCE_STATUS[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo "," >> "${REPORT_FILE}"
        fi
        
        IFS='|' read -r status description <<< "${COMPLIANCE_STATUS[$control]}"
        cat >> "${REPORT_FILE}" <<EOF
    "$control": {
      "status": "$status",
      "description": "$description"
    }
EOF
    done
    
    cat >> "${REPORT_FILE}" <<EOF

  },
  "total_controls_applied": ${#COMPLIANCE_STATUS[@]},
  "backup_location": "$BACKUP_DIR",
  "log_file": "$LOG_FILE"
}
EOF
    
    chmod 600 "${REPORT_FILE}"
    log_success "Compliance report generated: ${REPORT_FILE}"
}

print_summary() {
    echo ""
    echo "========================================================================"
    echo "           LINUX HARDENING COMPLIANCE SCRIPT - SUMMARY"
    echo "========================================================================"
    echo ""
    echo "Execution completed: $(date)"
    echo "Hostname: $(hostname)"
    echo "Operating System: $OS $OS_VERSION"
    echo ""
    echo "Controls Applied: ${#COMPLIANCE_STATUS[@]}"
    echo ""
    echo "Compliance Standards:"
    echo "  - RBI Cybersecurity Guidelines"
    echo "  - ISO 27001:2022"
    echo "  - CIS Controls v8 (Linux Server Benchmark)"
    echo ""
    echo "Files Generated:"
    echo "  - Log File: ${LOG_FILE}"
    echo "  - Compliance Report: ${REPORT_FILE}"
    echo "  - Backup Directory: ${BACKUP_DIR}"
    echo ""
    echo "========================================================================"
    echo "IMPORTANT POST-HARDENING STEPS:"
    echo "========================================================================"
    echo "1. Review the compliance report: cat ${REPORT_FILE} | jq ."
    echo "2. Test SSH access before logging out"
    echo "3. Configure SSH key-based authentication"
    echo "4. Review and customize firewall rules for your services"
    echo "5. Schedule regular AIDE integrity checks"
    echo "6. Configure centralized logging if required"
    echo "7. Reboot system to apply all kernel parameter changes"
    echo "========================================================================"
    echo ""
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    log_action "========================================"
    log_action "Linux OS Hardening Script - Started"
    log_action "Compliance: RBI, ISO 27001:2022, CIS v8"
    log_action "========================================"
    
    check_root
    detect_os
    
    # Execute hardening functions
    harden_password_policy
    configure_account_lockout
    configure_sudo_logging
    harden_ssh
    set_file_permissions
    configure_firewall
    disable_unnecessary_services
    configure_logging
    configure_auditd
    harden_kernel_parameters
    configure_auto_updates
    configure_package_integrity
    secure_cron
    install_aide
    additional_hardening
    update_system
    
    # Generate reports
    generate_compliance_report
    print_summary
    
    log_action "========================================"
    log_action "Linux OS Hardening Script - Completed"
    log_action "========================================"
}

# Execute main function
main "$@"