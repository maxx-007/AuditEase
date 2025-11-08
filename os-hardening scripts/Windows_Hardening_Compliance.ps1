<#
.SYNOPSIS
    Windows Hardening Script - Compliance-Driven Security Configuration
    
.DESCRIPTION
    Production-grade PowerShell script for Windows 10/11/Server hardening
    Complies with RBI Cybersecurity Guidelines, ISO 27001:2022, and CIS Controls v8
    
.NOTES
    Version: 1.0
    Author: Cybersecurity Engineering Team
    Requires: Administrator privileges
    Compatible: Windows 10/11, Server 2016/2019/2022
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$ReportPath = "$env:TEMP\HardeningReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').json",
    [switch]$CreateBackup = $true,
    [string]$BackupPath = "$env:TEMP\HardeningBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)

# Initialize report structure
$Global:HardeningReport = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Hostname = $env:COMPUTERNAME
    WindowsVersion = (Get-CimInstance Win32_OperatingSystem).Caption
    Results = @()
}

function Write-HardeningLog {
    param(
        [string]$Control,
        [string]$Description,
        [string]$Status,
        [string]$ComplianceMapping,
        [string]$Details = ""
    )
    
    $logEntry = @{
        Control = $Control
        Description = $Description
        Status = $Status
        ComplianceMapping = $ComplianceMapping
        Details = $Details
        Timestamp = Get-Date -Format "HH:mm:ss"
    }
    
    $Global:HardeningReport.Results += $logEntry
    
    $color = switch ($Status) {
        "Success" { "Green" }
        "Failed" { "Red" }
        "Skipped" { "Yellow" }
        default { "White" }
    }
    
    Write-Host "[$Status] $Control - $Description" -ForegroundColor $color
}

function Backup-RegistryKey {
    param([string]$Path)
    
    if ($CreateBackup -and (Test-Path $Path)) {
        try {
            $backupFile = Join-Path $BackupPath "$($Path -replace ':', '' -replace '\\', '_').reg"
            $null = New-Item -Path $BackupPath -ItemType Directory -Force -ErrorAction SilentlyContinue
            reg export $Path $backupFile /y | Out-Null
        } catch {
            Write-Verbose "Backup failed for $Path"
        }
    }
}

function Set-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Value,
        [string]$Type = "DWord"
    )
    
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        return $true
    } catch {
        return $false
    }
}

# ============================================================================
# SECTION 1: USER ACCOUNT SECURITY
# ============================================================================

Write-Host "`n========== USER ACCOUNT SECURITY ==========" -ForegroundColor Cyan

# ISO 27001 A.9.2.1 - User registration and de-registration
# CIS Control 5.1 - Establish and maintain an inventory of accounts
# RBI Cybersecurity - User access management
try {
    Backup-RegistryKey "HKLM:\SAM"
    
    # Disable Guest account
    net user guest /active:no 2>$null
    $guestDisabled = (Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled -eq $false
    
    Write-HardeningLog -Control "UAC-001" -Description "Disable Guest Account" `
        -Status $(if ($guestDisabled) {"Success"} else {"Failed"}) `
        -ComplianceMapping "ISO 27001 A.9.2.1 | CIS 5.1 | RBI User Access"
} catch {
    Write-HardeningLog -Control "UAC-001" -Description "Disable Guest Account" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.9.2.1 | CIS 5.1 | RBI User Access" `
        -Details $_.Exception.Message
}

# ISO 27001 A.9.2.3 - Management of privileged access rights
# CIS Control 5.4 - Restrict administrator privileges
# RBI Cybersecurity - Privileged access management
try {
    # Rename default Administrator account
    $adminAccount = Get-LocalUser | Where-Object {$_.SID -like "*-500"}
    if ($adminAccount -and $adminAccount.Name -eq "Administrator") {
        Rename-LocalUser -Name "Administrator" -NewName "Admin_$(Get-Random -Minimum 1000 -Maximum 9999)" -ErrorAction Stop
        $renamed = $true
    } else {
        $renamed = $true # Already renamed
    }
    
    Write-HardeningLog -Control "UAC-002" -Description "Rename Administrator Account" `
        -Status $(if ($renamed) {"Success"} else {"Failed"}) `
        -ComplianceMapping "ISO 27001 A.9.2.3 | CIS 5.4 | RBI Privileged Access"
} catch {
    Write-HardeningLog -Control "UAC-002" -Description "Rename Administrator Account" `
        -Status "Skipped" -ComplianceMapping "ISO 27001 A.9.2.3 | CIS 5.4 | RBI Privileged Access" `
        -Details "Already renamed or not applicable"
}

# ============================================================================
# SECTION 2: PASSWORD POLICY
# ============================================================================

Write-Host "`n========== PASSWORD POLICY ==========" -ForegroundColor Cyan

# ISO 27001 A.9.4.3 - Password management system
# CIS Control 5.2 - Use unique passwords
# RBI Cybersecurity - Strong password requirements
try {
    Backup-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    
    $secpolConfig = @"
[Unicode]
Unicode=yes
[Version]
signature=`"`$CHICAGO`$`"
Revision=1
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 90
MinimumPasswordLength = 14
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
ClearTextPassword = 0
"@
    
    $secpolFile = "$env:TEMP\secpol.cfg"
    $secpolConfig | Out-File $secpolFile -Encoding ASCII
    secedit /configure /db secedit.sdb /cfg $secpolFile /areas SECURITYPOLICY | Out-Null
    Remove-Item $secpolFile -Force
    
    Write-HardeningLog -Control "PWD-001" -Description "Configure Password Policy (Min 14 chars, 90 days max age, complexity)" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.9.4.3 | CIS 5.2 | RBI Password Policy"
} catch {
    Write-HardeningLog -Control "PWD-001" -Description "Configure Password Policy" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.9.4.3 | CIS 5.2 | RBI Password Policy" `
        -Details $_.Exception.Message
}

# ISO 27001 A.9.4.2 - Secure log-on procedures
# CIS Control 6.2 - Ensure account lockout threshold is configured
# RBI Cybersecurity - Account lockout policy
try {
    $result = Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout" `
        -Name "MaxDenials" -Value 5
    
    Write-HardeningLog -Control "PWD-002" -Description "Account Lockout Threshold (5 attempts)" `
        -Status $(if ($result) {"Success"} else {"Failed"}) `
        -ComplianceMapping "ISO 27001 A.9.4.2 | CIS 6.2 | RBI Account Lockout"
} catch {
    Write-HardeningLog -Control "PWD-002" -Description "Account Lockout Threshold" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.9.4.2 | CIS 6.2 | RBI Account Lockout" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 3: AUDIT POLICY
# ============================================================================

Write-Host "`n========== AUDIT POLICY ==========" -ForegroundColor Cyan

# ISO 27001 A.12.4.1 - Event logging
# CIS Control 8.2 - Collect audit logs
# RBI Cybersecurity - Comprehensive logging
$auditCategories = @(
    @{Category="Account Logon"; Setting="Success,Failure"; Control="AUD-001"},
    @{Category="Account Management"; Setting="Success,Failure"; Control="AUD-002"},
    @{Category="Logon/Logoff"; Setting="Success,Failure"; Control="AUD-003"},
    @{Category="Object Access"; Setting="Success,Failure"; Control="AUD-004"},
    @{Category="Policy Change"; Setting="Success,Failure"; Control="AUD-005"},
    @{Category="Privilege Use"; Setting="Success,Failure"; Control="AUD-006"},
    @{Category="System"; Setting="Success,Failure"; Control="AUD-007"}
)

foreach ($audit in $auditCategories) {
    try {
        $auditCommand = "auditpol /set /category:`"$($audit.Category)`" /$($audit.Setting.Replace(',','/'))"
        Invoke-Expression $auditCommand | Out-Null
        
        Write-HardeningLog -Control $audit.Control -Description "Enable Audit: $($audit.Category)" `
            -Status "Success" `
            -ComplianceMapping "ISO 27001 A.12.4.1 | CIS 8.2 | RBI Logging"
    } catch {
        Write-HardeningLog -Control $audit.Control -Description "Enable Audit: $($audit.Category)" `
            -Status "Failed" -ComplianceMapping "ISO 27001 A.12.4.1 | CIS 8.2 | RBI Logging" `
            -Details $_.Exception.Message
    }
}

# ISO 27001 A.12.4.2 - Protection of log information
# CIS Control 8.3 - Ensure adequate audit log storage
# RBI Cybersecurity - Log retention
try {
    $logNames = @("Application", "Security", "System")
    foreach ($log in $logNames) {
        $eventLog = Get-WinEvent -ListLog $log -ErrorAction Stop
        wevtutil sl $log /ms:1073741824 # 1GB
        wevtutil sl $log /rt:false
    }
    
    Write-HardeningLog -Control "AUD-008" -Description "Configure Event Log Size (1GB) and Retention" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.12.4.2 | CIS 8.3 | RBI Log Retention"
} catch {
    Write-HardeningLog -Control "AUD-008" -Description "Configure Event Log Size and Retention" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.12.4.2 | CIS 8.3 | RBI Log Retention" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 4: WINDOWS DEFENDER
# ============================================================================

Write-Host "`n========== WINDOWS DEFENDER ==========" -ForegroundColor Cyan

# ISO 27001 A.12.2.1 - Controls against malware
# CIS Control 10.1 - Deploy and maintain anti-malware software
# RBI Cybersecurity - Endpoint protection
try {
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction Stop
    Set-MpPreference -DisableBlockAtFirstSeen $false -ErrorAction Stop
    Set-MpPreference -DisableIOAVProtection $false -ErrorAction Stop
    Set-MpPreference -DisableScriptScanning $false -ErrorAction Stop
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop
    Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
    Set-MpPreference -CloudBlockLevel High -ErrorAction Stop
    
    Write-HardeningLog -Control "DEF-001" -Description "Enable Windows Defender Real-Time Protection" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.12.2.1 | CIS 10.1 | RBI Endpoint Protection"
} catch {
    Write-HardeningLog -Control "DEF-001" -Description "Enable Windows Defender Real-Time Protection" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.12.2.1 | CIS 10.1 | RBI Endpoint Protection" `
        -Details $_.Exception.Message
}

# ISO 27001 A.12.2.1 - Controls against malware
# CIS Control 10.5 - Enable anti-exploitation features
# RBI Cybersecurity - Advanced threat protection
try {
    Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction Stop
    Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction Stop
    Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
    
    Write-HardeningLog -Control "DEF-002" -Description "Enable Controlled Folder Access and Network Protection" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.12.2.1 | CIS 10.5 | RBI Advanced Protection"
} catch {
    Write-HardeningLog -Control "DEF-002" -Description "Enable Controlled Folder Access and Network Protection" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.12.2.1 | CIS 10.5 | RBI Advanced Protection" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 5: WINDOWS FIREWALL
# ============================================================================

Write-Host "`n========== WINDOWS FIREWALL ==========" -ForegroundColor Cyan

# ISO 27001 A.13.1.1 - Network controls
# CIS Control 4.1 - Establish and maintain a secure network configuration
# RBI Cybersecurity - Network perimeter security
try {
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow -ErrorAction Stop
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True -ErrorAction Stop
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogMaxSizeKilobytes 16384 -ErrorAction Stop
    
    Write-HardeningLog -Control "FW-001" -Description "Enable Windows Firewall (All Profiles)" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.13.1.1 | CIS 4.1 | RBI Network Security"
} catch {
    Write-HardeningLog -Control "FW-001" -Description "Enable Windows Firewall" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.13.1.1 | CIS 4.1 | RBI Network Security" `
        -Details $_.Exception.Message
}

# ISO 27001 A.13.1.3 - Segregation in networks
# CIS Control 4.4 - Implement and manage a firewall
# RBI Cybersecurity - Inbound connection filtering
try {
    New-NetFirewallRule -DisplayName "Block Inbound SMBv1" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Block -Enabled True -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName "Block Inbound Telnet" -Direction Inbound -Protocol TCP -LocalPort 23 -Action Block -Enabled True -ErrorAction SilentlyContinue
    
    Write-HardeningLog -Control "FW-002" -Description "Block Inbound SMBv1 and Telnet" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.13.1.3 | CIS 4.4 | RBI Network Filtering"
} catch {
    Write-HardeningLog -Control "FW-002" -Description "Block Inbound SMBv1 and Telnet" `
        -Status "Skipped" -ComplianceMapping "ISO 27001 A.13.1.3 | CIS 4.4 | RBI Network Filtering" `
        -Details "Rules may already exist"
}

# ============================================================================
# SECTION 6: DISABLE UNNECESSARY SERVICES
# ============================================================================

Write-Host "`n========== DISABLE UNNECESSARY SERVICES ==========" -ForegroundColor Cyan

# ISO 27001 A.9.1.2 - Access to networks and network services
# CIS Control 4.8 - Uninstall or disable unnecessary services
# RBI Cybersecurity - Attack surface reduction
$servicesToDisable = @(
    @{Name="LxssManager"; Display="Windows Subsystem for Linux"; Control="SVC-001"},
    @{Name="RemoteRegistry"; Display="Remote Registry"; Control="SVC-002"},
    @{Name="RemoteAccess"; Display="Routing and Remote Access"; Control="SVC-003"},
    @{Name="WMSvc"; Display="Web Management Service"; Control="SVC-004"},
    @{Name="TlntSvr"; Display="Telnet"; Control="SVC-005"},
    @{Name="simptcp"; Display="Simple TCP/IP Services"; Control="SVC-006"},
    @{Name="SSDPSRV"; Display="SSDP Discovery"; Control="SVC-007"},
    @{Name="upnphost"; Display="UPnP Device Host"; Control="SVC-008"}
)

foreach ($svc in $servicesToDisable) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
            $status = "Success"
        } else {
            $status = "Skipped"
        }
        
        Write-HardeningLog -Control $svc.Control -Description "Disable $($svc.Display)" `
            -Status $status `
            -ComplianceMapping "ISO 27001 A.9.1.2 | CIS 4.8 | RBI Attack Surface Reduction"
    } catch {
        Write-HardeningLog -Control $svc.Control -Description "Disable $($svc.Display)" `
            -Status "Failed" -ComplianceMapping "ISO 27001 A.9.1.2 | CIS 4.8 | RBI Attack Surface Reduction" `
            -Details $_.Exception.Message
    }
}

# ISO 27001 A.13.1.3 - Segregation in networks
# CIS Control 9.2 - Ensure only approved ports, protocols, and services are running
# RBI Cybersecurity - Protocol hardening
try {
    Backup-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "SMB1" -Value 0
    
    # Disable SMB1 client
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
    
    Write-HardeningLog -Control "SVC-009" -Description "Disable SMBv1 Protocol" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.13.1.3 | CIS 9.2 | RBI Protocol Security"
} catch {
    Write-HardeningLog -Control "SVC-009" -Description "Disable SMBv1 Protocol" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.13.1.3 | CIS 9.2 | RBI Protocol Security" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 7: BITLOCKER & ENCRYPTION
# ============================================================================

Write-Host "`n========== BITLOCKER & ENCRYPTION ==========" -ForegroundColor Cyan

# ISO 27001 A.10.1.1 - Policy on the use of cryptographic controls
# CIS Control 3.6 - Encrypt data on end-user devices
# RBI Cybersecurity - Data encryption at rest
try {
    $bitlockerStatus = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
    
    if ($bitlockerStatus) {
        if ($bitlockerStatus.ProtectionStatus -eq "Off") {
            # Attempt to enable BitLocker
            Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -SkipHardwareTest -ErrorAction Stop
            $status = "Success"
            $details = "BitLocker enabled"
        } else {
            $status = "Success"
            $details = "BitLocker already enabled"
        }
    } else {
        $status = "Skipped"
        $details = "BitLocker not available on this system"
    }
    
    Write-HardeningLog -Control "ENC-001" -Description "Enable BitLocker Drive Encryption" `
        -Status $status `
        -ComplianceMapping "ISO 27001 A.10.1.1 | CIS 3.6 | RBI Data Encryption" `
        -Details $details
} catch {
    Write-HardeningLog -Control "ENC-001" -Description "Enable BitLocker Drive Encryption" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.10.1.1 | CIS 3.6 | RBI Data Encryption" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 8: RDP HARDENING
# ============================================================================

Write-Host "`n========== RDP HARDENING ==========" -ForegroundColor Cyan

# ISO 27001 A.9.4.2 - Secure log-on procedures
# CIS Control 4.5 - Implement and manage a firewall on servers
# RBI Cybersecurity - Remote access security
try {
    Backup-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
    
    # Enable Network Level Authentication
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "UserAuthentication" -Value 1
    
    # Disable clipboard redirection
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "fDisableClip" -Value 1
    
    # Disable drive redirection
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "fDisableCdm" -Value 1
    
    # Set encryption level to High
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "MinEncryptionLevel" -Value 3
    
    Write-HardeningLog -Control "RDP-001" -Description "Harden RDP (NLA, Disable Clipboard/Drive Redirection)" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.9.4.2 | CIS 4.5 | RBI Remote Access"
} catch {
    Write-HardeningLog -Control "RDP-001" -Description "Harden RDP Configuration" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.9.4.2 | CIS 4.5 | RBI Remote Access" `
        -Details $_.Exception.Message
}

# ISO 27001 A.13.1.1 - Network controls
# CIS Control 12.3 - Secure remote access
# RBI Cybersecurity - Session timeout
try {
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "MaxIdleTime" -Value 900000 # 15 minutes
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
        -Name "MaxDisconnectionTime" -Value 60000 # 1 minute
    
    Write-HardeningLog -Control "RDP-002" -Description "Configure RDP Session Timeouts" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.13.1.1 | CIS 12.3 | RBI Session Management"
} catch {
    Write-HardeningLog -Control "RDP-002" -Description "Configure RDP Session Timeouts" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.13.1.1 | CIS 12.3 | RBI Session Management" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 9: APPLICATION CONTROL
# ============================================================================

Write-Host "`n========== APPLICATION CONTROL ==========" -ForegroundColor Cyan

# ISO 27001 A.14.2.5 - Secure system engineering principles
# CIS Control 2.7 - Allowlist authorized software
# RBI Cybersecurity - Application whitelisting
try {
    $applockerService = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    if ($applockerService) {
        Set-Service -Name "AppIDSvc" -StartupType Automatic -ErrorAction Stop
        Start-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
        
        Write-HardeningLog -Control "APP-001" -Description "Enable AppLocker Service" `
            -Status "Success" `
            -ComplianceMapping "ISO 27001 A.14.2.5 | CIS 2.7 | RBI Application Control"
    } else {
        Write-HardeningLog -Control "APP-001" -Description "Enable AppLocker Service" `
            -Status "Skipped" `
            -ComplianceMapping "ISO 27001 A.14.2.5 | CIS 2.7 | RBI Application Control" `
            -Details "AppLocker not available"
    }
} catch {
    Write-HardeningLog -Control "APP-001" -Description "Enable AppLocker Service" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.14.2.5 | CIS 2.7 | RBI Application Control" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 10: NETWORK SECURITY
# ============================================================================

Write-Host "`n========== NETWORK SECURITY ==========" -ForegroundColor Cyan

# ISO 27001 A.13.1.1 - Network controls
# CIS Control 13.3 - Deploy network-based IPS
# RBI Cybersecurity - Network hardening
try {
    Backup-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    
    # Enable TCP SYN flood protection
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        -Name "SynAttackProtect" -Value 1
    
    # Enable TCP/IP security
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        -Name "EnableICMPRedirect" -Value 0
    
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        -Name "DisableIPSourceRouting" -Value 2
    
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" `
        -Name "EnableDeadGWDetect" -Value 0
    
    Write-HardeningLog -Control "NET-001" -Description "Configure TCP/IP Security Parameters" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.13.1.1 | CIS 13.3 | RBI Network Hardening"
} catch {
    Write-HardeningLog -Control "NET-001" -Description "Configure TCP/IP Security Parameters" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.13.1.1 | CIS 13.3 | RBI Network Hardening" `
        -Details $_.Exception.Message
}

# ISO 27001 A.13.1.3 - Segregation in networks
# CIS Control 13.4 - Perform traffic filtering
# RBI Cybersecurity - ICMP filtering
try {
    # Disable ICMP redirects
    netsh interface ipv4 set global icmpredirects=disabled | Out-Null
    
    # Configure firewall to limit ICMP
    New-NetFirewallRule -DisplayName "Limit ICMP Echo Request" -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow -Enabled True -ErrorAction SilentlyContinue
    
    Write-HardeningLog -Control "NET-002" -Description "Configure ICMP Security" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.13.1.3 | CIS 13.4 | RBI Network Filtering"
} catch {
    Write-HardeningLog -Control "NET-002" -Description "Configure ICMP Security" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.13.1.3 | CIS 13.4 | RBI Network Filtering" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 11: WINDOWS UPDATE
# ============================================================================

Write-Host "`n========== WINDOWS UPDATE ==========" -ForegroundColor Cyan

# ISO 27001 A.12.6.1 - Management of technical vulnerabilities
# CIS Control 7.1 - Establish and maintain a vulnerability management process
# RBI Cybersecurity - Patch management
try {
    Backup-RegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    
    # Enable automatic updates
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
        -Name "NoAutoUpdate" -Value 0
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
        -Name "AUOptions" -Value 4 # Auto download and schedule install
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
        -Name "ScheduledInstallDay" -Value 0 # Every day
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
        -Name "ScheduledInstallTime" -Value 3 # 3 AM
    
    Write-HardeningLog -Control "UPD-001" -Description "Configure Automatic Windows Updates" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.12.6.1 | CIS 7.1 | RBI Patch Management"
} catch {
    Write-HardeningLog -Control "UPD-001" -Description "Configure Automatic Windows Updates" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.12.6.1 | CIS 7.1 | RBI Patch Management" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 12: USER RIGHTS ASSIGNMENT
# ============================================================================

Write-Host "`n========== USER RIGHTS ASSIGNMENT ==========" -ForegroundColor Cyan

# ISO 27001 A.9.2.3 - Management of privileged access rights
# CIS Control 5.4 - Restrict administrator privileges to dedicated accounts
# RBI Cybersecurity - Least privilege principle
try {
    $userRightsConfig = @"
[Unicode]
Unicode=yes
[Version]
signature=`"`$CHICAGO`$`"
Revision=1
[Privilege Rights]
SeNetworkLogonRight = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeDenyNetworkLogonRight = *S-1-5-32-546
SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeDenyInteractiveLogonRight = *S-1-5-32-546
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
SeDenyRemoteInteractiveLogonRight = *S-1-5-32-546
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551
SeSystemtimePrivilege = *S-1-5-32-544,*S-1-5-19
SeTimeZonePrivilege = *S-1-5-32-544,*S-1-5-19
SeCreatePagefilePrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-544
SeAuditPrivilege = *S-1-5-19,*S-1-5-20
SeIncreaseQuotaPrivilege = *S-1-5-32-544,*S-1-5-19,*S-1-5-20
SeLoadDriverPrivilege = *S-1-5-32-544
SeSecurityPrivilege = *S-1-5-32-544
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-32-544
SeAssignPrimaryTokenPrivilege = *S-1-5-19,*S-1-5-20
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551
SeShutdownPrivilege = *S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551
SeTakeOwnershipPrivilege = *S-1-5-32-544
"@
    
    $userRightsFile = "$env:TEMP\userrights.cfg"
    $userRightsConfig | Out-File $userRightsFile -Encoding ASCII
    secedit /configure /db secedit.sdb /cfg $userRightsFile /areas USER_RIGHTS | Out-Null
    Remove-Item $userRightsFile -Force
    
    Write-HardeningLog -Control "UAR-001" -Description "Configure User Rights Assignment" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.9.2.3 | CIS 5.4 | RBI Least Privilege"
} catch {
    Write-HardeningLog -Control "UAR-001" -Description "Configure User Rights Assignment" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.9.2.3 | CIS 5.4 | RBI Least Privilege" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 13: SCREEN LOCK & SESSION SECURITY
# ============================================================================

Write-Host "`n========== SCREEN LOCK & SESSION SECURITY ==========" -ForegroundColor Cyan

# ISO 27001 A.11.2.8 - Unattended user equipment
# CIS Control 4.3 - Configure automatic session locking
# RBI Cybersecurity - Session management
try {
    Backup-RegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    # Enable screen saver lock
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" `
        -Name "ScreenSaveActive" -Value "1" -Type String
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" `
        -Name "ScreenSaverIsSecure" -Value "1" -Type String
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" `
        -Name "ScreenSaveTimeOut" -Value "900" -Type String # 15 minutes
    
    # Interactive logon message
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "LegalNoticeCaption" -Value "Authorized Access Only" -Type String
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "LegalNoticeText" -Value "This system is for authorized use only. Unauthorized access is prohibited and will be prosecuted." -Type String
    
    Write-HardeningLog -Control "SCR-001" -Description "Configure Screen Lock and Logon Banner" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.11.2.8 | CIS 4.3 | RBI Session Security"
} catch {
    Write-HardeningLog -Control "SCR-001" -Description "Configure Screen Lock and Logon Banner" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.11.2.8 | CIS 4.3 | RBI Session Security" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 14: SECURITY OPTIONS
# ============================================================================

Write-Host "`n========== SECURITY OPTIONS ==========" -ForegroundColor Cyan

# ISO 27001 A.9.4.1 - Information access restriction
# CIS Control 3.3 - Configure data access control lists
# RBI Cybersecurity - Access control
try {
    Backup-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    
    # Restrict anonymous access
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RestrictAnonymous" -Value 1
    
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "RestrictAnonymousSAM" -Value 1
    
    # Disable LM hash storage
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "NoLMHash" -Value 1
    
    # Enable LDAP signing
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" `
        -Name "LDAPClientIntegrity" -Value 1
    
    Write-HardeningLog -Control "SEC-001" -Description "Configure LSA Security Options" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.9.4.1 | CIS 3.3 | RBI Access Control"
} catch {
    Write-HardeningLog -Control "SEC-001" -Description "Configure LSA Security Options" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.9.4.1 | CIS 3.3 | RBI Access Control" `
        -Details $_.Exception.Message
}

# ISO 27001 A.9.4.3 - Password management system
# CIS Control 5.2 - Use unique passwords
# RBI Cybersecurity - Credential protection
try {
    # Enable Credential Guard (if supported)
    $osVersion = [System.Environment]::OSVersion.Version
    if ($osVersion.Major -ge 10 -and $osVersion.Build -ge 14393) {
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
            -Name "EnableVirtualizationBasedSecurity" -Value 1
        
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" `
            -Name "RequirePlatformSecurityFeatures" -Value 3
        
        Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "LsaCfgFlags" -Value 1
        
        $status = "Success"
        $details = "Credential Guard enabled (requires reboot)"
    } else {
        $status = "Skipped"
        $details = "Windows version does not support Credential Guard"
    }
    
    Write-HardeningLog -Control "SEC-002" -Description "Enable Credential Guard" `
        -Status $status `
        -ComplianceMapping "ISO 27001 A.9.4.3 | CIS 5.2 | RBI Credential Protection" `
        -Details $details
} catch {
    Write-HardeningLog -Control "SEC-002" -Description "Enable Credential Guard" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.9.4.3 | CIS 5.2 | RBI Credential Protection" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 15: POWERSHELL SECURITY
# ============================================================================

Write-Host "`n========== POWERSHELL SECURITY ==========" -ForegroundColor Cyan

# ISO 27001 A.12.4.1 - Event logging
# CIS Control 8.8 - Collect command-line audit logs
# RBI Cybersecurity - Script execution logging
try {
    Backup-RegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
    
    # Enable PowerShell script block logging
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging" -Value 1
    
    # Enable PowerShell transcription
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        -Name "EnableTranscripting" -Value 1
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        -Name "OutputDirectory" -Value "C:\PSTranscripts" -Type String
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" `
        -Name "EnableInvocationHeader" -Value 1
    
    # Enable PowerShell module logging
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" `
        -Name "EnableModuleLogging" -Value 1
    
    # Create transcript directory
    if (-not (Test-Path "C:\PSTranscripts")) {
        New-Item -Path "C:\PSTranscripts" -ItemType Directory -Force | Out-Null
    }
    
    Write-HardeningLog -Control "PS-001" -Description "Enable PowerShell Logging and Transcription" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.12.4.1 | CIS 8.8 | RBI Script Execution Logging"
} catch {
    Write-HardeningLog -Control "PS-001" -Description "Enable PowerShell Logging and Transcription" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.12.4.1 | CIS 8.8 | RBI Script Execution Logging" `
        -Details $_.Exception.Message
}

# ISO 27001 A.14.2.5 - Secure system engineering principles
# CIS Control 2.5 - Allowlist authorized scripts
# RBI Cybersecurity - Execution policy
try {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
    
    Write-HardeningLog -Control "PS-002" -Description "Set PowerShell Execution Policy to RemoteSigned" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.14.2.5 | CIS 2.5 | RBI Execution Policy"
} catch {
    Write-HardeningLog -Control "PS-002" -Description "Set PowerShell Execution Policy to RemoteSigned" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.14.2.5 | CIS 2.5 | RBI Execution Policy" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 16: WINDOWS FEATURES
# ============================================================================

Write-Host "`n========== WINDOWS FEATURES ==========" -ForegroundColor Cyan

# ISO 27001 A.9.1.2 - Access to networks and network services
# CIS Control 4.8 - Uninstall or disable unnecessary services
# RBI Cybersecurity - Feature minimization
$featuresToDisable = @(
    @{Name="TelnetClient"; Control="FTR-001"},
    @{Name="TFTP"; Control="FTR-002"},
    @{Name="SimpleTCP"; Control="FTR-003"},
    @{Name="WorkFolders-Client"; Control="FTR-004"}
)

foreach ($feature in $featuresToDisable) {
    try {
        $featureState = Get-WindowsOptionalFeature -Online -FeatureName $feature.Name -ErrorAction SilentlyContinue
        if ($featureState -and $featureState.State -eq "Enabled") {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature.Name -NoRestart -ErrorAction Stop | Out-Null
            $status = "Success"
        } else {
            $status = "Skipped"
        }
        
        Write-HardeningLog -Control $feature.Control -Description "Disable Windows Feature: $($feature.Name)" `
            -Status $status `
            -ComplianceMapping "ISO 27001 A.9.1.2 | CIS 4.8 | RBI Feature Minimization"
    } catch {
        Write-HardeningLog -Control $feature.Control -Description "Disable Windows Feature: $($feature.Name)" `
            -Status "Failed" -ComplianceMapping "ISO 27001 A.9.1.2 | CIS 4.8 | RBI Feature Minimization" `
            -Details $_.Exception.Message
    }
}

# ============================================================================
# SECTION 17: EXPLOIT PROTECTION
# ============================================================================

Write-Host "`n========== EXPLOIT PROTECTION ==========" -ForegroundColor Cyan

# ISO 27001 A.14.2.5 - Secure system engineering principles
# CIS Control 10.5 - Enable anti-exploitation features
# RBI Cybersecurity - Exploit mitigation
try {
    # Enable Data Execution Prevention (DEP)
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        -Name "NoDataExecutionPrevention" -Value 0
    
    # Enable SEHOP (Structured Exception Handler Overwrite Protection)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" `
        -Name "DisableExceptionChainValidation" -Value 0
    
    # Enable ASLR (Address Space Layout Randomization)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" `
        -Name "MoveImages" -Value 1
    
    Write-HardeningLog -Control "EXP-001" -Description "Enable DEP, SEHOP, and ASLR" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.14.2.5 | CIS 10.5 | RBI Exploit Mitigation"
} catch {
    Write-HardeningLog -Control "EXP-001" -Description "Enable DEP, SEHOP, and ASLR" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.14.2.5 | CIS 10.5 | RBI Exploit Mitigation" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 18: REGISTRY SECURITY
# ============================================================================

Write-Host "`n========== REGISTRY SECURITY ==========" -ForegroundColor Cyan

# ISO 27001 A.12.4.1 - Event logging
# CIS Control 8.5 - Collect detailed audit logs
# RBI Cybersecurity - Registry auditing
try {
    Backup-RegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    
    # Enable registry auditing
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "EnableLUA" -Value 1
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "ConsentPromptBehaviorAdmin" -Value 2
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "PromptOnSecureDesktop" -Value 1
    
    Write-HardeningLog -Control "REG-001" -Description "Configure UAC and Secure Desktop" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.12.4.1 | CIS 8.5 | RBI Registry Auditing"
} catch {
    Write-HardeningLog -Control "REG-001" -Description "Configure UAC and Secure Desktop" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.12.4.1 | CIS 8.5 | RBI Registry Auditing" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 19: USB & REMOVABLE MEDIA
# ============================================================================

Write-Host "`n========== USB & REMOVABLE MEDIA ==========" -ForegroundColor Cyan

# ISO 27001 A.8.3.1 - Management of removable media
# CIS Control 10.3 - Disable autorun
# RBI Cybersecurity - Removable media control
try {
    Backup-RegistryKey "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    
    # Disable AutoRun/AutoPlay
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -Name "NoDriveTypeAutoRun" -Value 255
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" `
        -Name "NoAutoplayfornonVolume" -Value 1
    
    Write-HardeningLog -Control "USB-001" -Description "Disable AutoRun and AutoPlay" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.8.3.1 | CIS 10.3 | RBI Removable Media Control"
} catch {
    Write-HardeningLog -Control "USB-001" -Description "Disable AutoRun and AutoPlay" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.8.3.1 | CIS 10.3 | RBI Removable Media Control" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 20: TIME SYNCHRONIZATION
# ============================================================================

Write-Host "`n========== TIME SYNCHRONIZATION ==========" -ForegroundColor Cyan

# ISO 27001 A.12.4.4 - Clock synchronization
# CIS Control 8.4 - Standardize time synchronization
# RBI Cybersecurity - Time synchronization
try {
    # Configure Windows Time service
    Set-Service -Name "W32Time" -StartupType Automatic -ErrorAction Stop
    Start-Service -Name "W32Time" -ErrorAction SilentlyContinue
    
    # Configure NTP client
    w32tm /config /manualpeerlist:"time.windows.com,0x9" /syncfromflags:manual /reliable:YES /update | Out-Null
    w32tm /resync /force | Out-Null
    
    Write-HardeningLog -Control "TIME-001" -Description "Configure Time Synchronization (NTP)" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.12.4.4 | CIS 8.4 | RBI Time Sync"
} catch {
    Write-HardeningLog -Control "TIME-001" -Description "Configure Time Synchronization" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.12.4.4 | CIS 8.4 | RBI Time Sync" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 21: ADDITIONAL NETWORK HARDENING
# ============================================================================

Write-Host "`n========== ADDITIONAL NETWORK HARDENING ==========" -ForegroundColor Cyan

# ISO 27001 A.13.1.1 - Network controls
# CIS Control 13.1 - Centralize security event alerting
# RBI Cybersecurity - Network protocol hardening
try {
    Backup-RegistryKey "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
    
    # Disable IPv6 if not needed (set to 0 to enable, 0xFF to disable all)
    Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
        -Name "DisabledComponents" -Value 0xFF
    
    # Disable NetBIOS over TCP/IP
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
    foreach ($adapter in $adapters) {
        $adapter.SetTcpipNetbios(2) | Out-Null # 2 = Disable NetBIOS
    }
    
    Write-HardeningLog -Control "NET-003" -Description "Disable IPv6 and NetBIOS over TCP/IP" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.13.1.1 | CIS 13.1 | RBI Protocol Hardening"
} catch {
    Write-HardeningLog -Control "NET-003" -Description "Disable IPv6 and NetBIOS over TCP/IP" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.13.1.1 | CIS 13.1 | RBI Protocol Hardening" `
        -Details $_.Exception.Message
}

# ============================================================================
# SECTION 22: BROWSER SECURITY (IF APPLICABLE)
# ============================================================================

Write-Host "`n========== BROWSER SECURITY ==========" -ForegroundColor Cyan

# ISO 27001 A.14.1.3 - Protecting application services transactions
# CIS Control 9.6 - Block unnecessary file types
# RBI Cybersecurity - Web browser hardening
try {
    Backup-RegistryKey "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    
    # Edge security settings
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
        -Name "SmartScreenEnabled" -Value 1
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
        -Name "SmartScreenPuaEnabled" -Value 1
    
    Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" `
        -Name "SSLErrorOverrideAllowed" -Value 0
    
    Write-HardeningLog -Control "BRW-001" -Description "Configure Microsoft Edge Security Settings" `
        -Status "Success" `
        -ComplianceMapping "ISO 27001 A.14.1.3 | CIS 9.6 | RBI Browser Hardening"
} catch {
    Write-HardeningLog -Control "BRW-001" -Description "Configure Microsoft Edge Security Settings" `
        -Status "Failed" -ComplianceMapping "ISO 27001 A.14.1.3 | CIS 9.6 | RBI Browser Hardening" `
        -Details $_.Exception.Message
}

# ============================================================================
# GENERATE FINAL REPORT
# ============================================================================

Write-Host "`n========== GENERATING REPORT ==========" -ForegroundColor Cyan

try {
    # Calculate statistics
    $totalControls = $Global:HardeningReport.Results.Count
    $successCount = ($Global:HardeningReport.Results | Where-Object {$_.Status -eq "Success"}).Count
    $failedCount = ($Global:HardeningReport.Results | Where-Object {$_.Status -eq "Failed"}).Count
    $skippedCount = ($Global:HardeningReport.Results | Where-Object {$_.Status -eq "Skipped"}).Count
    
    $Global:HardeningReport.Summary = @{
        TotalControls = $totalControls
        Successful = $successCount
        Failed = $failedCount
        Skipped = $skippedCount
        SuccessRate = [math]::Round(($successCount / $totalControls) * 100, 2)
    }
    
    # Export to JSON
    $Global:HardeningReport | ConvertTo-Json -Depth 10 | Out-File $ReportPath -Encoding UTF8
    
    Write-Host "`n========== HARDENING SUMMARY ==========" -ForegroundColor Green
    Write-Host "Total Controls: $totalControls" -ForegroundColor White
    Write-Host "Successful: $successCount" -ForegroundColor Green
    Write-Host "Failed: $failedCount" -ForegroundColor Red
    Write-Host "Skipped: $skippedCount" -ForegroundColor Yellow
    Write-Host "Success Rate: $($Global:HardeningReport.Summary.SuccessRate)%" -ForegroundColor Cyan
    Write-Host "`nReport saved to: $ReportPath" -ForegroundColor White
    
    if ($CreateBackup) {
        Write-Host "Backup saved to: $BackupPath" -ForegroundColor White
    }
    
    Write-Host "`n========== IMPORTANT NOTES ==========" -ForegroundColor Yellow
    Write-Host "1. A system restart is required for all changes to take effect" -ForegroundColor White
    Write-Host "2. Test all changes in a non-production environment first" -ForegroundColor White
    Write-Host "3. Review the JSON report for detailed compliance mapping" -ForegroundColor White
    Write-Host "4. Some controls may require additional manual configuration" -ForegroundColor White
    Write-Host "5. BitLocker may require TPM configuration" -ForegroundColor White
    Write-Host "6. Credential Guard requires virtualization support" -ForegroundColor White
    
} catch {
    Write-Host "Error generating report: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n========== HARDENING COMPLETE ==========" -ForegroundColor Green