#!/bin/bash

################################################################################
# macOS Security Hardening Script - Compliance Edition
# Complies with: RBI Cybersecurity Guidelines, ISO 27001:2022, CIS Apple macOS
# Target: macOS 11.x (Big Sur) and above
# Author: Apple Platform Security Team
# Version: 1.0
################################################################################

set -euo pipefail

# Configuration
LOG_FILE="/Library/Logs/macos_hardening.log"
REPORT_FILE="/Library/Logs/compliance_summary.json"
BACKUP_FILE="/Library/Logs/hardening_backup_$(date +%Y%m%d_%H%M%S).json"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Get current user
CURRENT_USER=$(stat -f "%Su" /dev/console)
USER_HOME=$(dscl . -read /Users/"$CURRENT_USER" NFSHomeDirectory | awk '{print $2}')

# Compliance tracking
declare -A COMPLIANCE_STATUS
declare -A BACKUP_SETTINGS

################################################################################
# Utility Functions
################################################################################

log_action() {
    echo "[${TIMESTAMP}] $1" | tee -a "${LOG_FILE}"
}

log_success() {
    echo "[✓] $1" | tee -a "${LOG_FILE}"
}

log_warning() {
    echo "[!] $1" | tee -a "${LOG_FILE}"
}

log_error() {
    echo "[✗] $1" | tee -a "${LOG_FILE}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi
}

detect_macos_version() {
    MACOS_VERSION=$(sw_vers -productVersion)
    MACOS_MAJOR=$(echo "$MACOS_VERSION" | cut -d. -f1)
    MACOS_MINOR=$(echo "$MACOS_VERSION" | cut -d. -f2)
    MACOS_BUILD=$(sw_vers -buildVersion)
    
    log_action "Detected macOS Version: $MACOS_VERSION (Build: $MACOS_BUILD)"
    
    if [[ $MACOS_MAJOR -lt 11 ]]; then
        log_warning "This script is optimized for macOS 11+ (Big Sur and above)"
    fi
}

record_compliance() {
    local control=$1
    local status=$2
    local description=$3
    COMPLIANCE_STATUS["$control"]="$status|$description"
}

backup_setting() {
    local setting_name=$1
    local current_value=$2
    BACKUP_SETTINGS["$setting_name"]="$current_value"
}

execute_as_user() {
    sudo -u "$CURRENT_USER" "$@"
}

################################################################################
# 1. PASSWORD POLICY CONFIGURATION
# ISO 27001: A.9.4.3 | CIS: 5.2.x | RBI: Authentication Controls
################################################################################

configure_password_policy() {
    log_action "=== Configuring Password Policy ==="
    
    # CIS 5.2.1 - Configure account lockout threshold
    # ISO 27001 A.9.4.2 - Secure log-on procedures
    # RBI: Account lockout policy
    
    local current_lockout=$(pwpolicy -getaccountpolicies 2>/dev/null | grep -c "policyAttributeMaximumFailedAuthentications" || echo "0")
    backup_setting "account_lockout" "$current_lockout"
    
    pwpolicy -setaccountpolicies <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>policyCategoryAuthentication</key>
    <array>
        <dict>
            <key>policyContent</key>
            <string>(policyAttributeFailedAuthentications &lt; policyAttributeMaximumFailedAuthentications) OR (policyAttributeCurrentTime &gt; policyAttributeLastFailedAuthenticationTime + autoEnableInSeconds)</string>
            <key>policyIdentifier</key>
            <string>com.apple.policy.lockout</string>
            <key>policyParameters</key>
            <dict>
                <key>policyAttributeMaximumFailedAuthentications</key>
                <integer>5</integer>
                <key>autoEnableInSeconds</key>
                <integer>900</integer>
            </dict>
        </dict>
    </array>
    <key>policyCategoryPasswordContent</key>
    <array>
        <dict>
            <key>policyContent</key>
            <string>policyAttributePassword matches '.{14,}+'</string>
            <key>policyIdentifier</key>
            <string>com.apple.policy.minimum.length</string>
            <key>policyParameters</key>
            <dict>
                <key>minimumLength</key>
                <integer>14</integer>
            </dict>
        </dict>
        <dict>
            <key>policyContent</key>
            <string>policyAttributePassword matches '(.*[A-Z].*){1,}+'</string>
            <key>policyIdentifier</key>
            <string>com.apple.policy.uppercase</string>
        </dict>
        <dict>
            <key>policyContent</key>
            <string>policyAttributePassword matches '(.*[a-z].*){1,}+'</string>
            <key>policyIdentifier</key>
            <string>com.apple.policy.lowercase</string>
        </dict>
        <dict>
            <key>policyContent</key>
            <string>policyAttributePassword matches '(.*[0-9].*){1,}+'</string>
            <key>policyIdentifier</key>
            <string>com.apple.policy.numeric</string>
        </dict>
        <dict>
            <key>policyContent</key>
            <string>policyAttributePassword matches '(.*[^a-zA-Z0-9].*){1,}+'</string>
            <key>policyIdentifier</key>
            <string>com.apple.policy.special</string>
        </dict>
    </array>
    <key>policyCategoryPasswordChange</key>
    <array>
        <dict>
            <key>policyContent</key>
            <string>policyAttributeCurrentTime &gt; policyAttributeLastPasswordChangeTime + (policyAttributeExpiresEveryNDays * 24 * 60 * 60)</string>
            <key>policyIdentifier</key>
            <string>com.apple.policy.expiration</string>
            <key>policyParameters</key>
            <dict>
                <key>policyAttributeExpiresEveryNDays</key>
                <integer>90</integer>
            </dict>
        </dict>
    </array>
</dict>
</plist>
EOF
    
    log_success "Password policy configured (14 chars min, complexity, 90-day expiry, 5 attempts lockout)"
    record_compliance "CIS-5.2.1" "APPLIED" "Account lockout and password complexity configured"
    record_compliance "ISO-27001-A.9.4.3" "APPLIED" "Password management system implemented"
}

configure_screensaver_lock() {
    log_action "=== Configuring Screen Lock Policy ==="
    
    # CIS 2.3.1 - Set an inactivity interval of 20 minutes or less
    # ISO 27001 A.11.2.8 - Unattended user equipment
    # RBI: Idle timeout requirements
    
    local current_idle=$(execute_as_user defaults read com.apple.screensaver idleTime 2>/dev/null || echo "0")
    backup_setting "screensaver_idle" "$current_idle"
    
    # Set screensaver to start after 10 minutes
    execute_as_user defaults write com.apple.screensaver idleTime -int 600
    
    # Require password immediately after sleep or screensaver
    execute_as_user defaults write com.apple.screensaver askForPassword -int 1
    execute_as_user defaults write com.apple.screensaver askForPasswordDelay -int 0
    
    # System-wide settings
    defaults write /Library/Preferences/com.apple.screensaver idleTime -int 600
    defaults write /Library/Preferences/com.apple.screensaver askForPassword -int 1
    defaults write /Library/Preferences/com.apple.screensaver askForPasswordDelay -int 0
    
    log_success "Screen lock configured (10 min idle, immediate password)"
    record_compliance "CIS-2.3.1" "APPLIED" "Inactivity interval configured"
    record_compliance "ISO-27001-A.11.2.8" "APPLIED" "Unattended equipment protection enabled"
}

################################################################################
# 2. FILEVAULT ENCRYPTION
# ISO 27001: A.10.1.1 | CIS: 2.6.1 | RBI: Data encryption at rest
################################################################################

enable_filevault() {
    log_action "=== Configuring FileVault Encryption ==="
    
    # CIS 2.6.1 - Enable FileVault
    # ISO 27001 A.10.1.1 - Policy on the use of cryptographic controls
    # RBI: Encryption of data at rest
    
    local fv_status=$(fdesetup status | grep -c "FileVault is On" || echo "0")
    backup_setting "filevault_status" "$fv_status"
    
    if [[ "$fv_status" == "0" ]]; then
        log_warning "FileVault is not enabled. Enabling requires user interaction."
        log_warning "Run: sudo fdesetup enable -user $CURRENT_USER"
        record_compliance "CIS-2.6.1" "MANUAL_ACTION_REQUIRED" "FileVault needs manual enablement"
    else
        log_success "FileVault is already enabled"
        record_compliance "CIS-2.6.1" "COMPLIANT" "FileVault encryption active"
    fi
    
    # CIS 2.6.2 - Ensure Fireware Password is set
    local firmware_pw=$(firmwarepasswd -check | grep -c "Password Enabled: Yes" || echo "0")
    backup_setting "firmware_password" "$firmware_pw"
    
    if [[ "$firmware_pw" == "0" ]]; then
        log_warning "Firmware password not set. Consider setting with: sudo firmwarepasswd -setpasswd"
        record_compliance "CIS-2.6.2" "MANUAL_ACTION_REQUIRED" "Firmware password should be set"
    else
        log_success "Firmware password is enabled"
        record_compliance "CIS-2.6.2" "COMPLIANT" "Firmware password configured"
    fi
    
    record_compliance "ISO-27001-A.10.1.1" "APPLIED" "Cryptographic controls implemented"
}

################################################################################
# 3. FIREWALL CONFIGURATION
# ISO 27001: A.13.1.1 | CIS: 2.1.x | RBI: Network security controls
################################################################################

configure_firewall() {
    log_action "=== Configuring Application Firewall ==="
    
    # CIS 2.1.1 - Enable application firewall
    # ISO 27001 A.13.1.1 - Network controls
    # RBI: Endpoint firewall requirements
    
    local current_fw=$(defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null || echo "0")
    backup_setting "firewall_state" "$current_fw"
    
    # Enable firewall
    defaults write /Library/Preferences/com.apple.alf globalstate -int 1
    
    # CIS 2.1.2 - Enable stealth mode
    local current_stealth=$(defaults read /Library/Preferences/com.apple.alf stealthenabled 2>/dev/null || echo "0")
    backup_setting "stealth_mode" "$current_stealth"
    
    defaults write /Library/Preferences/com.apple.alf stealthenabled -int 1
    
    # CIS 2.1.3 - Enable firewall logging
    local current_logging=$(defaults read /Library/Preferences/com.apple.alf loggingenabled 2>/dev/null || echo "0")
    backup_setting "firewall_logging" "$current_logging"
    
    defaults write /Library/Preferences/com.apple.alf loggingenabled -int 1
    
    # Enable detailed logging
    defaults write /Library/Preferences/com.apple.alf loggingoption -string detail
    
    # Restart firewall
    launchctl unload /System/Library/LaunchDaemons/com.apple.alf.agent.plist 2>/dev/null || true
    launchctl load /System/Library/LaunchDaemons/com.apple.alf.agent.plist 2>/dev/null || true
    
    log_success "Application firewall enabled with stealth mode and logging"
    record_compliance "CIS-2.1.1" "APPLIED" "Application firewall enabled"
    record_compliance "CIS-2.1.2" "APPLIED" "Stealth mode enabled"
    record_compliance "CIS-2.1.3" "APPLIED" "Firewall logging enabled"
    record_compliance "ISO-27001-A.13.1.1" "APPLIED" "Network security controls implemented"
}

################################################################################
# 4. REMOTE ACCESS CONTROLS
# ISO 27001: A.9.4.2 | CIS: 2.4.x | RBI: Remote access security
################################################################################

disable_remote_services() {
    log_action "=== Disabling Remote Services ==="
    
    # CIS 2.4.1 - Disable Remote Apple Events
    # ISO 27001 A.9.4.2 - Secure log-on procedures
    local current_rae=$(systemsetup -getremoteappleevents 2>/dev/null | grep -c "On" || echo "0")
    backup_setting "remote_apple_events" "$current_rae"
    
    systemsetup -setremoteappleevents off >/dev/null 2>&1
    log_success "Remote Apple Events disabled"
    record_compliance "CIS-2.4.1" "APPLIED" "Remote Apple Events disabled"
    
    # CIS 2.4.2 - Disable Internet Sharing
    local current_sharing=$(defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null | grep -c "Enabled = 1" || echo "0")
    backup_setting "internet_sharing" "$current_sharing"
    
    defaults write /Library/Preferences/SystemConfiguration/com.apple.nat NAT -dict Enabled -int 0
    log_success "Internet Sharing disabled"
    record_compliance "CIS-2.4.2" "APPLIED" "Internet Sharing disabled"
    
    # CIS 2.4.3 - Disable Screen Sharing
    local current_screen=$(launchctl print-disabled system | grep -c "com.apple.screensharing.*true" || echo "0")
    backup_setting "screen_sharing" "$current_screen"
    
    launchctl disable system/com.apple.screensharing 2>/dev/null || true
    log_success "Screen Sharing disabled"
    record_compliance "CIS-2.4.3" "APPLIED" "Screen Sharing disabled"
    
    # CIS 2.4.4 - Disable Printer Sharing
    cupsctl --no-share-printers 2>/dev/null || true
    log_success "Printer Sharing disabled"
    record_compliance "CIS-2.4.4" "APPLIED" "Printer Sharing disabled"
    
    # CIS 2.4.5 - Disable Remote Login (SSH)
    local current_ssh=$(systemsetup -getremotelogin 2>/dev/null | grep -c "On" || echo "0")
    backup_setting "remote_login" "$current_ssh"
    
    systemsetup -setremotelogin off >/dev/null 2>&1
    log_success "Remote Login (SSH) disabled"
    record_compliance "CIS-2.4.5" "APPLIED" "Remote Login disabled"
    
    # CIS 2.4.6 - Disable File Sharing
    launchctl disable system/com.apple.smbd 2>/dev/null || true
    log_success "File Sharing (SMB) disabled"
    record_compliance "CIS-2.4.6" "APPLIED" "File Sharing disabled"
    
    # CIS 2.4.7 - Disable Remote Management
    /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -deactivate -stop 2>/dev/null || true
    log_success "Remote Management (ARD) disabled"
    record_compliance "CIS-2.4.7" "APPLIED" "Remote Management disabled"
    
    # Disable Bluetooth Sharing
    local current_bt=$(defaults read /Library/Preferences/com.apple.Bluetooth.plist ControllerPowerState 2>/dev/null || echo "0")
    backup_setting "bluetooth_sharing" "$current_bt"
    
    defaults write /Library/Preferences/com.apple.Bluetooth.plist PrefKeyServicesEnabled -bool false
    log_success "Bluetooth Sharing disabled"
    
    record_compliance "ISO-27001-A.9.4.2" "APPLIED" "Remote access controls implemented"
    record_compliance "RBI-REMOTE-ACCESS" "APPLIED" "Remote services secured"
}

################################################################################
# 5. USB AND EXTERNAL MEDIA CONTROLS
# ISO 27001: A.8.3.1 | CIS: Custom | RBI: Removable media controls
################################################################################

restrict_external_media() {
    log_action "=== Configuring External Media Restrictions ==="
    
    # ISO 27001 A.8.3.1 - Management of removable media
    # RBI: Removable media policy
    
    # Disable auto-mounting of external drives
    local current_automount=$(defaults read /Library/Preferences/SystemConfiguration/autodiskmount.plist AutomountDisksWithoutUserLogin 2>/dev/null || echo "true")
    backup_setting "automount_external" "$current_automount"
    
    defaults write /Library/Preferences/SystemConfiguration/autodiskmount.plist AutomountDisksWithoutUserLogin -bool false
    log_success "Auto-mounting of external drives disabled at login"
    
    # Disable CD/DVD sharing
    launchctl disable system/com.apple.ODSAgent 2>/dev/null || true
    log_success "CD/DVD sharing disabled"
    
    record_compliance "ISO-27001-A.8.3.1" "APPLIED" "Removable media controls configured"
    record_compliance "RBI-MEDIA-CONTROL" "APPLIED" "External media restrictions applied"
}

################################################################################
# 6. GATEKEEPER AND XPROTECT
# ISO 27001: A.12.6.1 | CIS: 2.7.x | RBI: Malware protection
################################################################################

configure_gatekeeper() {
    log_action "=== Configuring Gatekeeper and XProtect ==="
    
    # CIS 2.7.1 - Enable Gatekeeper
    # ISO 27001 A.12.6.1 - Management of technical vulnerabilities
    # RBI: Endpoint protection requirements
    
    local current_gk=$(spctl --status 2>/dev/null | grep -c "assessments enabled" || echo "0")
    backup_setting "gatekeeper_status" "$current_gk"
    
    spctl --master-enable
    log_success "Gatekeeper enabled"
    record_compliance "CIS-2.7.1" "APPLIED" "Gatekeeper enabled"
    
    # CIS 2.7.2 - Enable XProtect automatic updates
    defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true
    defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
    log_success "XProtect automatic updates enabled"
    record_compliance "CIS-2.7.2" "APPLIED" "XProtect auto-updates enabled"
    
    # CIS 2.7.3 - Enable automatic system data files and security updates
    defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
    defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true
    log_success "Automatic security updates enabled"
    record_compliance "CIS-2.7.3" "APPLIED" "Automatic updates configured"
    
    # Enforce App Store-only software installation
    local current_gk_policy=$(spctl --status --verbose 2>/dev/null | grep -c "developer id" || echo "0")
    backup_setting "gatekeeper_policy" "$current_gk_policy"
    
    # Set to Mac App Store and identified developers
    spctl --enable --label "Mac App Store" 2>/dev/null || true
    spctl --enable --label "Developer ID" 2>/dev/null || true
    
    log_success "Gatekeeper configured for App Store and identified developers"
    record_compliance "RBI-ENDPOINT-PROTECTION" "APPLIED" "Software installation restrictions applied"
    record_compliance "ISO-27001-A.12.6.1" "APPLIED" "Technical vulnerability management configured"
}

################################################################################
# 7. AUDIT AND LOGGING
# ISO 27001: A.12.4.1 | CIS: 3.x | RBI: Security logging and monitoring
################################################################################

configure_audit_logging() {
    log_action "=== Configuring Audit and Logging ==="
    
    # CIS 3.1 - Enable security auditing
    # ISO 27001 A.12.4.1 - Event logging
    # RBI: Security audit trails
    
    local current_audit=$(launchctl list | grep -c "com.apple.auditd" || echo "0")
    backup_setting "audit_daemon" "$current_audit"
    
    # Enable auditd
    launchctl load -w /System/Library/LaunchDaemons/com.apple.auditd.plist 2>/dev/null || true
    
    # Configure audit flags
    local current_flags=$(grep "^flags:" /etc/security/audit_control 2>/dev/null | cut -d: -f2 || echo "")
    backup_setting "audit_flags" "$current_flags"
    
    # Update audit_control with comprehensive flags
    if [[ -f /etc/security/audit_control ]]; then
        cp /etc/security/audit_control /etc/security/audit_control.backup
        
        # CIS 3.2 - Configure security auditing flags
        sed -i '' 's/^flags:.*/flags:lo,aa,ad,fd,fm,-all/' /etc/security/audit_control
        
        # Set policy flags
        sed -i '' 's/^policy:.*/policy:cnt,argv/' /etc/security/audit_control
        
        # Restart auditd
        audit -s
        
        log_success "Audit daemon configured with comprehensive flags"
        record_compliance "CIS-3.1" "APPLIED" "Security auditing enabled"
        record_compliance "CIS-3.2" "APPLIED" "Audit flags configured"
    else
        log_warning "audit_control file not found"
        record_compliance "CIS-3.1" "FAILED" "Could not configure auditing"
    fi
    
    # CIS 3.3 - Ensure install.log is retained for 365 days
    if [[ -f /etc/asl.conf ]]; then
        cp /etc/asl.conf /etc/asl.conf.backup
        
        if ! grep -q "ttl=365" /etc/asl.conf; then
            echo "? [A=com.apple.install] file /var/log/install.log mode=0640 format=bsd rotate=seq compress ttl=365" >> /etc/asl.conf
        fi
        
        log_success "Install log retention set to 365 days"
        record_compliance "CIS-3.3" "APPLIED" "Log retention configured"
    fi
    
    # Enable unified logging for security events
    log config --mode "level:debug,persist:debug" --subsystem com.apple.securityd 2>/dev/null || true
    log_success "Unified logging enhanced for security events"
    
    record_compliance "ISO-27001-A.12.4.1" "APPLIED" "Event logging implemented"
    record_compliance "RBI-LOGGING" "APPLIED" "Security logging and monitoring configured"
}

################################################################################
# 8. SYSTEM INTEGRITY AND UPDATES
# ISO 27001: A.12.6.1 | CIS: 1.x | RBI: Patch management
################################################################################

configure_system_integrity() {
    log_action "=== Configuring System Integrity Protection ==="
    
    # CIS 1.1 - Verify System Integrity Protection (SIP) is enabled
    # ISO 27001 A.12.5.1 - Installation of software on operational systems
    
    local sip_status=$(csrutil status 2>/dev/null | grep -c "enabled" || echo "0")
    backup_setting "sip_status" "$sip_status"
    
    if [[ "$sip_status" -gt 0 ]]; then
        log_success "System Integrity Protection (SIP) is enabled"
        record_compliance "CIS-1.1" "COMPLIANT" "SIP is enabled"
    else
        log_warning "System Integrity Protection (SIP) is disabled - should be enabled"
        record_compliance "CIS-1.1" "NON_COMPLIANT" "SIP should be enabled via Recovery Mode"
    fi
    
    # CIS 1.2 - Enable Auto Update
    local current_auto=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "0")
    backup_setting "automatic_updates" "$current_auto"
    
    softwareupdate --schedule on 2>/dev/null || true
    log_success "Automatic software updates enabled"
    record_compliance "CIS-1.2" "APPLIED" "Auto-update enabled"
    
    # CIS 1.3 - Enable app update installs
    defaults write /Library/Preferences/com.apple.commerce AutoUpdate -bool true
    log_success "App Store auto-updates enabled"
    record_compliance "CIS-1.3" "APPLIED" "App auto-updates enabled"
    
    # CIS 1.4 - Enable system data files and security update installs
    defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true
    defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
    log_success "System data and security updates auto-install enabled"
    record_compliance "CIS-1.4" "APPLIED" "Security updates auto-install enabled"
    
    # CIS 1.5 - Enable macOS update installs
    defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true
    log_success "macOS updates auto-install enabled"
    record_compliance "CIS-1.5" "APPLIED" "macOS auto-updates enabled"
    
    record_compliance "ISO-27001-A.12.6.1" "APPLIED" "Patch management configured"
}

################################################################################
# 9. PRIVACY AND LOCATION SERVICES
# ISO 27001: A.18.1.4 | CIS: 2.5.x | RBI: Privacy controls
################################################################################

configure_privacy_settings() {
    log_action "=== Configuring Privacy Settings ==="
    
    # CIS 2.5.1 - Disable Siri
    # ISO 27001 A.18.1.4 - Privacy and protection of personally identifiable information
    
    local current_siri=$(defaults read com.apple.assistant.support "Assistant Enabled" 2>/dev/null || echo "1")
    backup_setting "siri_enabled" "$current_siri"
    
    defaults write com.apple.assistant.support "Assistant Enabled" -bool false
    defaults write com.apple.Siri StatusMenuVisible -bool false
    defaults write com.apple.Siri UserHasDeclinedEnable -bool true
    
    log_success "Siri disabled"
    record_compliance "CIS-2.5.1" "APPLIED" "Siri disabled"
    
    # CIS 2.5.2 - Disable sending diagnostic and usage data to Apple
    local current_diag=$(defaults read /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit 2>/dev/null || echo "1")
    backup_setting "diagnostics_submission" "$current_diag"
    
    defaults write /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist AutoSubmit -bool false
    log_success "Diagnostic data submission disabled"
    record_compliance "CIS-2.5.2" "APPLIED" "Diagnostic data submission disabled"
    
    # CIS 2.5.3 - Disable Location Services if not required
    local current_location=$(defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled 2>/dev/null || echo "1")
    backup_setting "location_services" "$current_location"
    
    defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false
    log_success "Location Services disabled"
    record_compliance "CIS-2.5.3" "APPLIED" "Location Services disabled"
    
    # Disable analytics and improvements
    defaults write /Library/Application\ Support/CrashReporter/DiagnosticMessagesHistory.plist ThirdPartyDataSubmit -bool false
    log_success "Third-party data submission disabled"
    
    record_compliance "ISO-27001-A.18.1.4" "APPLIED" "Privacy protection configured"
}

################################################################################
# 10. ADDITIONAL HARDENING
# ISO 27001: Various | CIS: Various | RBI: Additional controls
################################################################################

additional_hardening() {
    log_action "=== Applying Additional Hardening Measures ==="
    
    # CIS 2.8.1 - Time Machine Auto-Backup
    local current_tm=$(defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup 2>/dev/null || echo "0")
    backup_setting "time_machine_backup" "$current_tm"
    
    defaults write /Library/Preferences/com.apple.TimeMachine AutoBackup -bool true
    log_success "Time Machine auto-backup enabled"
    record_compliance "CIS-2.8.1" "APPLIED" "Backup automation configured"
    
    # CIS 2.9.1 - Disable Wake on Network Access
    local current_wake=$(systemsetup -getwakeonnetworkaccess 2>/dev/null | grep -c "On" || echo "0")
    backup_setting "wake_on_network" "$current_wake"
    
    systemsetup -setwakeonnetworkaccess off >/dev/null 2>&1
    log_success "Wake on Network Access disabled"
    record_compliance "CIS-2.9.1" "APPLIED" "Wake on network disabled"
    
    # CIS 2.10.1 - Disable guest account
    local current_guest=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo "1")
    backup_setting "guest_account" "$current_guest"
    
    defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false
    log_success "Guest account disabled"
    record_compliance "CIS-2.10.1" "APPLIED" "Guest account disabled"
    
    # CIS 2.11.1 - Disable automatic login
    local current_autologin=$(defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || echo "none")
    backup_setting "auto_login" "$current_autologin"
    
    defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser 2>/dev/null || true
    log_success "Automatic login disabled"
    record_compliance "CIS-2.11.1" "APPLIED" "Automatic login disabled"
    
    # CIS 2.12.1 - Disable DVD or CD Sharing
    launchctl unload -w /System/Library/LaunchDaemons/com.apple.ODSAgent.plist 2>/dev/null || true
    log_success "DVD/CD sharing disabled"
    record_compliance "CIS-2.12.1" "APPLIED" "Optical media sharing disabled"
    
    # CIS 2.13.1 - Enable Secure Keyboard Entry in Terminal
    defaults write com.apple.Terminal SecureKeyboardEntry -bool true
    execute_as_user defaults write com.apple.Terminal SecureKeyboardEntry -bool true
    log_success "Secure keyboard entry enabled in Terminal"
    record_compliance "CIS-2.13.1" "APPLIED" "Secure keyboard entry enabled"
    
    # Disable Handoff
    local current_handoff=$(defaults read ~/Library/Preferences/ByHost/com.apple.coreservices.useractivityd.plist ActivityAdvertisingAllowed 2>/dev/null || echo "1")
    backup_setting "handoff" "$current_handoff"
    
    execute_as_user defaults write ~/Library/Preferences/ByHost/com.apple.coreservices.useractivityd.plist ActivityAdvertisingAllowed -bool false
    log_success "Handoff disabled"
    
    # Disable AirDrop
    local current_airdrop=$(defaults read com.apple.NetworkBrowser DisableAirDrop 2>/dev/null || echo "0")
    backup_setting "airdrop" "$current_airdrop"
    
    defaults write com.apple.NetworkBrowser DisableAirDrop -bool true
    log_success "AirDrop disabled"
    
    # Set login window to name and password
    defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true
    log_success "Login window set to name and password"
    
    # Disable bonjour advertising service
    defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true
    log_success "Bonjour advertising disabled"
    
    # Show all filename extensions
    execute_as_user defaults write NSGlobalDomain AppleShowAllExtensions -bool true
    log_success "All filename extensions shown"
    
    # Disable Safari auto-open safe files
    execute_as_user defaults write com.apple.Safari AutoOpenSafeDownloads -bool false
    log_success "Safari auto-open safe files disabled"
    
    # Enable Safari fraud warning
    execute_as_user defaults write com.apple.Safari WarnAboutFraudulentWebsites -bool true
    log_success "Safari fraud warning enabled"
    
    record_compliance "RBI-ADDITIONAL-CONTROLS" "APPLIED" "Additional security controls implemented"
}

################################################################################
# 11. NETWORK TIME PROTOCOL
# ISO 27001: A.12.4.4 | CIS: 2.2.x | RBI: Time synchronization
################################################################################

configure_ntp() {
    log_action "=== Configuring Network Time Protocol ==="
    
    # CIS 2.2.1 - Enable NTP
    # ISO 27001 A.12.4.4 - Clock synchronization
    
    local current_ntp=$(systemsetup -getusingnetworktime 2>/dev/null | grep -c "On" || echo "0")
    backup_setting "network_time" "$current_ntp"
    
    systemsetup -setusingnetworktime on >/dev/null 2>&1
    
    # CIS 2.2.2 - Configure NTP server
    systemsetup -setnetworktimeserver time.apple.com >/dev/null 2>&1
    
    log_success "Network Time Protocol enabled with time.apple.com"
    record_compliance "CIS-2.2.1" "APPLIED" "NTP enabled"
    record_compliance "CIS-2.2.2" "APPLIED" "NTP server configured"
    record_compliance "ISO-27001-A.12.4.4" "APPLIED" "Clock synchronization configured"
}

################################################################################
# 12. USER AND GROUP MANAGEMENT
# ISO 27001: A.9.2.1 | CIS: 5.x | RBI: Access control
################################################################################

configure_user_security() {
    log_action "=== Configuring User Security Settings ==="
    
    # CIS 5.1.1 - Ensure login window shows name and password
    local current_fullname=$(defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME 2>/dev/null || echo "0")
    backup_setting "login_window_fullname" "$current_fullname"
    
    defaults write /Library/Preferences/com.apple.loginwindow SHOWFULLNAME -bool true
    log_success "Login window configured to show name and password fields"
    record_compliance "CIS-5.1.1" "APPLIED" "Login window secured"
    
    # CIS 5.1.2 - Disable Show password hints
    local current_hints=$(defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint 2>/dev/null || echo "3")
    backup_setting "password_hints" "$current_hints"
    
    defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0
    log_success "Password hints disabled"
    record_compliance "CIS-5.1.2" "APPLIED" "Password hints disabled"
    
    # CIS 5.1.3 - Disable guest account login
    defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false
    defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess -bool false
    log_success "Guest account access fully disabled"
    record_compliance "CIS-5.1.3" "APPLIED" "Guest account login disabled"
    
    # CIS 5.1.4 - Disable "Allow guests to connect to shared folders"
    defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false
    log_success "Guest folder access disabled"
    record_compliance "CIS-5.1.4" "APPLIED" "Guest folder sharing disabled"
    
    record_compliance "ISO-27001-A.9.2.1" "APPLIED" "User registration and de-registration configured"
}

################################################################################
# 13. BACKUP SETTINGS TO JSON
################################################################################

save_backup_settings() {
    log_action "=== Saving Backup Settings ==="
    
    cat > "${BACKUP_FILE}" <<EOF
{
  "backup_timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "macos_version": "$MACOS_VERSION",
  "settings": {
EOF
    
    local first=true
    for setting in "${!BACKUP_SETTINGS[@]}"; do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo "," >> "${BACKUP_FILE}"
        fi
        
        local value="${BACKUP_SETTINGS[$setting]}"
        cat >> "${BACKUP_FILE}" <<EOF
    "$setting": "$value"
EOF
    done
    
    cat >> "${BACKUP_FILE}" <<EOF

  }
}
EOF
    
    chmod 600 "${BACKUP_FILE}"
    log_success "Backup settings saved to: ${BACKUP_FILE}"
}

################################################################################
# 14. COMPLIANCE REPORT GENERATION
################################################################################

generate_compliance_report() {
    log_action "=== Generating Compliance Report ==="
    
    local total_controls=${#COMPLIANCE_STATUS[@]}
    local applied_count=0
    local compliant_count=0
    local manual_count=0
    local failed_count=0
    
    for control in "${!COMPLIANCE_STATUS[@]}"; do
        IFS='|' read -r status description <<< "${COMPLIANCE_STATUS[$control]}"
        case "$status" in
            "APPLIED") ((applied_count++)) ;;
            "COMPLIANT") ((compliant_count++)) ;;
            "MANUAL_ACTION_REQUIRED") ((manual_count++)) ;;
            "FAILED"|"NON_COMPLIANT") ((failed_count++)) ;;
        esac
    done
    
    cat > "${REPORT_FILE}" <<EOF
{
  "report_metadata": {
    "generated_timestamp": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "macos_version": "$MACOS_VERSION",
    "macos_build": "$MACOS_BUILD",
    "current_user": "$CURRENT_USER",
    "script_version": "1.0"
  },
  "compliance_frameworks": [
    "RBI Cybersecurity Guidelines",
    "ISO 27001:2022 Annex A",
    "CIS Apple macOS Benchmark"
  ],
  "compliance_summary": {
    "total_controls": $total_controls,
    "applied": $applied_count,
    "compliant": $compliant_count,
    "manual_action_required": $manual_count,
    "failed_or_non_compliant": $failed_count,
    "compliance_percentage": $(awk "BEGIN {printf \"%.2f\", (($applied_count + $compliant_count) / $total_controls) * 100}")
  },
  "controls": {
EOF
    
    local first=true
    for control in $(echo "${!COMPLIANCE_STATUS[@]}" | tr ' ' '\n' | sort); do
        if [[ "$first" == true ]]; then
            first=false
        else
            echo "," >> "${REPORT_FILE}"
        fi
        
        IFS='|' read -r status description <<< "${COMPLIANCE_STATUS[$control]}"
        cat >> "${REPORT_FILE}" <<EOF
    "$control": {
      "status": "$status",
      "description": "$description",
      "timestamp": "$(date -Iseconds)"
    }
EOF
    done
    
    cat >> "${REPORT_FILE}" <<EOF

  },
  "recommendations": [
EOF
    
    if [[ $manual_count -gt 0 ]]; then
        echo '    "Review controls marked as MANUAL_ACTION_REQUIRED and complete them manually",' >> "${REPORT_FILE}"
    fi
    
    if [[ $failed_count -gt 0 ]]; then
        echo '    "Investigate and remediate failed or non-compliant controls",' >> "${REPORT_FILE}"
    fi
    
    cat >> "${REPORT_FILE}" <<EOF
    "Restart the system to ensure all changes take effect",
    "Review and test system functionality after hardening",
    "Document any exceptions or deviations from baseline",
    "Schedule regular compliance audits",
    "Keep system updated with latest security patches"
  ],
  "files": {
    "log_file": "$LOG_FILE",
    "backup_file": "$BACKUP_FILE",
    "report_file": "$REPORT_FILE"
  }
}
EOF
    
    chmod 600 "${REPORT_FILE}"
    log_success "Compliance report generated: ${REPORT_FILE}"
}

print_summary() {
    echo ""
    echo "========================================================================"
    echo "           macOS SECURITY HARDENING - EXECUTION SUMMARY"
    echo "========================================================================"
    echo ""
    echo "Execution completed: $(date)"
    echo "Hostname: $(hostname)"
    echo "macOS Version: $MACOS_VERSION (Build: $MACOS_BUILD)"
    echo "Current User: $CURRENT_USER"
    echo ""
    echo "Controls Applied: ${#COMPLIANCE_STATUS[@]}"
    echo ""
    echo "Compliance Frameworks:"
    echo "  ✓ RBI Cybersecurity Guidelines"
    echo "  ✓ ISO 27001:2022 Annex A"
    echo "  ✓ CIS Apple macOS Benchmark"
    echo ""
    echo "========================================================================"
    echo "FILES GENERATED:"
    echo "========================================================================"
    echo "  Log File:        ${LOG_FILE}"
    echo "  Compliance JSON: ${REPORT_FILE}"
    echo "  Backup Settings: ${BACKUP_FILE}"
    echo ""
    echo "========================================================================"
    echo "IMPORTANT POST-HARDENING ACTIONS:"
    echo "========================================================================"
    echo ""
    echo "1. REVIEW COMPLIANCE REPORT:"
    echo "   cat ${REPORT_FILE} | python -m json.tool"
    echo ""
    echo "2. MANUAL ACTIONS REQUIRED:"
    echo "   - Enable FileVault if not already enabled:"
    echo "     sudo fdesetup enable -user $CURRENT_USER"
    echo "   - Set firmware password (if not set):"
    echo "     sudo firmwarepasswd -setpasswd"
    echo "   - Verify System Integrity Protection:"
    echo "     csrutil status"
    echo ""
    echo "3. RESTART SYSTEM:"
    echo "   sudo shutdown -r now"
    echo ""
    echo "4. VERIFY FUNCTIONALITY:"
    echo "   - Test application launches"
    echo "   - Verify network connectivity"
    echo "   - Check sharing preferences"
    echo "   - Test user authentication"
    echo ""
    echo "5. ROLLBACK (IF NEEDED):"
    echo "   - Backup settings stored in: ${BACKUP_FILE}"
    echo "   - Use for reference to restore previous configurations"
    echo ""
    echo "========================================================================"
    echo "SECURITY RECOMMENDATIONS:"
    echo "========================================================================"
    echo ""
    echo "✓ Schedule regular security updates"
    echo "✓ Implement Time Machine backups"
    echo "✓ Enable two-factor authentication for Apple ID"
    echo "✓ Use a password manager"
    echo "✓ Train users on security awareness"
    echo "✓ Conduct periodic compliance audits"
    echo "✓ Monitor system logs regularly"
    echo "✓ Review firewall logs weekly"
    echo ""
    echo "========================================================================"
    echo ""
}

################################################################################
# 15. ROLLBACK FUNCTION
################################################################################

show_rollback_instructions() {
    log_action "=== Rollback Instructions ==="
    
    cat <<EOF

======================================================================
ROLLBACK INSTRUCTIONS
======================================================================

To rollback changes, refer to the backup file:
  ${BACKUP_FILE}

Example rollback commands:

1. Re-enable Remote Login (SSH):
   sudo systemsetup -setremotelogin on

2. Re-enable Screen Sharing:
   sudo launchctl enable system/com.apple.screensharing

3. Disable Firewall:
   sudo defaults write /Library/Preferences/com.apple.alf globalstate -int 0

4. Re-enable Guest Account:
   sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool true

5. Re-enable Automatic Login:
   sudo defaults write /Library/Preferences/com.apple.loginwindow autoLoginUser -string "username"

Note: Each setting in the backup file can be restored using appropriate
defaults write or systemsetup commands with the original values.

======================================================================
EOF
}

################################################################################
# MAIN EXECUTION
################################################################################

main() {
    log_action "========================================================================"
    log_action "macOS Security Hardening Script - Started"
    log_action "Compliance: RBI, ISO 27001:2022, CIS Apple macOS Benchmark"
    log_action "========================================================================"
    
    # Initialize log file
    touch "${LOG_FILE}"
    chmod 600 "${LOG_FILE}"
    
    check_root
    detect_macos_version
    
    # Execute hardening functions in order
    configure_password_policy
    configure_screensaver_lock
    enable_filevault
    configure_firewall
    disable_remote_services
    restrict_external_media
    configure_gatekeeper
    configure_audit_logging
    configure_system_integrity
    configure_privacy_settings
    configure_ntp
    configure_user_security
    additional_hardening
    
    # Save backup and generate reports
    save_backup_settings
    generate_compliance_report
    show_rollback_instructions
    print_summary
    
    log_action "========================================================================"
    log_action "macOS Security Hardening Script - Completed Successfully"
    log_action "========================================================================"
}

# Trap errors
trap 'log_error "Script failed at line $LINENO"' ERR

# Execute main function
main "$@"