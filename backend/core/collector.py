#!/usr/bin/env python3
"""
Enhanced Real-Time Compliance Posture Collector
==============================================
Improved detection with multiple verification methods before defaulting to false.

Author: Cybersecurity Automation Team
Version: 2.0.0
"""

import subprocess
import json
import time
import logging
import platform
import re
import argparse
import os
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import sys

# ---------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------
OUTPUT_DIR = Path("outputs")
OUTPUT_FILE = OUTPUT_DIR / "compliance_snapshot.json"
DEFAULT_INTERVAL = 300  # seconds (5 minutes)

# Common security tool service names and processes
SECURITY_TOOLS = {
    'edr': ['CrowdStrike', 'SentinelOne', 'Carbon Black', 'Defender for Endpoint', 
            'Cortex XDR', 'Cylance', 'Sophos', 'Symantec Endpoint'],
    'siem': ['Splunk', 'QRadar', 'ArcSight', 'LogRhythm', 'Sentinel', 'Elastic'],
    'backup': ['Veeam', 'Acronis', 'Commvault', 'Veritas', 'Backup Exec', 'Windows Backup'],
    'vulnerability': ['Nessus', 'Qualys', 'Rapid7', 'Nexpose', 'OpenVAS'],
    'pam': ['CyberArk', 'BeyondTrust', 'Thycotic', 'Centrify'],
    'mdm': ['Intune', 'JAMF', 'MobileIron', 'AirWatch', 'Workspace ONE'],
    'config_mgmt': ['SCCM', 'Puppet', 'Chef', 'Ansible', 'SaltStack']
}

# ---------------------------------------------------------------------
# LOGGING SETUP
# ---------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
LOG = logging.getLogger("compliance_collector")

# ---------------------------------------------------------------------
# UTILITY FUNCTIONS
# ---------------------------------------------------------------------
def get_os_type() -> str:
    """Detect the operating system type."""
    return platform.system().lower()

def run_command(command: List[str], timeout: int = 30) -> Tuple[str, str, int]:
    """Execute a system command and return stdout, stderr, and return code."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors='ignore'
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        LOG.warning(f"⚠️ Command timed out: {' '.join(command)}")
        return "", "Timeout", -1
    except Exception as e:
        LOG.error(f"❌ Failed to run command {' '.join(command)}: {e}")
        return "", str(e), -1

def run_powershell(command: str) -> Tuple[str, int]:
    """Execute a PowerShell command (Windows only)."""
    stdout, stderr, returncode = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command]
    )
    return stdout, returncode

def parse_json_output(output: str, default: Any = None) -> Any:
    """Safely parse JSON output from command results."""
    if not output:
        return default
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        LOG.warning("⚠️ Failed to parse JSON output")
        return default

def check_registry_key(key_path: str, value_name: str = None) -> Tuple[bool, Any]:
    """Check if a Windows registry key/value exists."""
    if get_os_type() != "windows":
        return False, None
    
    try:
        if value_name:
            cmd = f"Get-ItemPropertyValue -Path '{key_path}' -Name '{value_name}' -ErrorAction SilentlyContinue"
        else:
            cmd = f"Test-Path '{key_path}'"
        
        output, rc = run_powershell(cmd)
        if rc == 0 and output:
            return True, output
    except Exception:
        pass
    return False, None

def check_file_exists(path: str) -> bool:
    """Check if a file or directory exists."""
    return Path(path).exists()

def check_service_running(service_names: List[str]) -> Tuple[bool, Optional[str]]:
    """Check if any service from the list is running."""
    os_type = get_os_type()
    
    for service in service_names:
        if os_type == "windows":
            output, rc = run_powershell(
                f"Get-Service -Name '*{service}*' -ErrorAction SilentlyContinue | "
                f"Where-Object {{$_.Status -eq 'Running'}} | Select-Object -ExpandProperty DisplayName"
            )
            if rc == 0 and output:
                return True, output
        elif os_type == "linux":
            output, _, rc = run_command(["systemctl", "is-active", service])
            if rc == 0 and "active" in output:
                return True, service
    
    return False, None

def check_process_running(process_names: List[str]) -> Tuple[bool, Optional[str]]:
    """Check if any process from the list is running."""
    os_type = get_os_type()
    
    for process in process_names:
        if os_type == "windows":
            output, rc = run_powershell(
                f"Get-Process -Name '*{process}*' -ErrorAction SilentlyContinue | "
                f"Select-Object -First 1 -ExpandProperty Name"
            )
            if rc == 0 and output:
                return True, output
        elif os_type == "linux":
            output, _, rc = run_command(["pgrep", "-f", process])
            if rc == 0 and output:
                return True, process
    
    return False, None

def check_network_port_listening(port: int) -> bool:
    """Check if a network port is listening."""
    os_type = get_os_type()
    
    if os_type == "windows":
        output, rc = run_powershell(
            f"Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue | "
            f"Select-Object -First 1"
        )
        return rc == 0 and output != ""
    elif os_type == "linux":
        output, _, rc = run_command(["ss", "-ltn"])
        if rc == 0:
            return f":{port}" in output
    
    return False

def check_installed_software(software_keywords: List[str]) -> Tuple[bool, Optional[str]]:
    """Check if software matching keywords is installed."""
    os_type = get_os_type()
    
    if os_type == "windows":
        for keyword in software_keywords:
            output, rc = run_powershell(
                f"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
                f"HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
                f"Where-Object {{$_.DisplayName -like '*{keyword}*'}} | "
                f"Select-Object -First 1 -ExpandProperty DisplayName"
            )
            if rc == 0 and output:
                return True, output
    elif os_type == "linux":
        for keyword in software_keywords:
            output, _, rc = run_command(["dpkg", "-l"])
            if rc == 0 and keyword.lower() in output.lower():
                return True, keyword
            
            output, _, rc = run_command(["rpm", "-qa"])
            if rc == 0 and keyword.lower() in output.lower():
                return True, keyword
    
    return False, None

# ---------------------------------------------------------------------
# ENHANCED COLLECTION FUNCTIONS
# ---------------------------------------------------------------------

def collect_asset_management() -> Dict[str, Any]:
    """Collect asset management data with enhanced detection."""
    os_type = get_os_type()
    
    # Software inventory check
    software_inventory = {"maintained": False, "last_updated": None, "count": 0}
    if os_type == "windows":
        output, rc = run_powershell(
            "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
            "Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc == 0 and output.isdigit():
            count = int(output)
            if count > 0:
                software_inventory["maintained"] = True
                software_inventory["last_updated"] = datetime.now().strftime("%Y-%m-%d")
                software_inventory["count"] = count
    elif os_type == "linux":
        output, _, rc = run_command(["dpkg", "-l"])
        if rc != 0:
            output, _, rc = run_command(["rpm", "-qa"])
        if rc == 0 and output:
            count = len(output.split('\n'))
            software_inventory["maintained"] = True
            software_inventory["last_updated"] = datetime.now().strftime("%Y-%m-%d")
            software_inventory["count"] = count
    
    # Check for SAM tools
    sam_tools = {"deployed": False, "tool_name": None}
    sam_keywords = ['SCCM', 'Intune', 'JAMF', 'Lansweeper', 'ManageEngine', 'Asset Manager']
    installed, tool = check_installed_software(sam_keywords)
    if installed:
        sam_tools["deployed"] = True
        sam_tools["tool_name"] = tool
    else:
        # Check for running services
        running, service = check_service_running(sam_keywords)
        if running:
            sam_tools["deployed"] = True
            sam_tools["tool_name"] = service
    
    # Hardware inventory check
    hardware_inventory = {"maintained": True, "automated": False}
    if sam_tools["deployed"]:
        hardware_inventory["automated"] = True
    
    return {
        "software_inventory": software_inventory,
        "unauthorized_software": {"detected": False},
        "sam_tools": sam_tools,
        "hardware_inventory": hardware_inventory
    }

def collect_network_security() -> Dict[str, Any]:
    """Collect network security data with enhanced detection."""
    os_type = get_os_type()
    
    # Perimeter firewall check
    perimeter = {"filtering_configured": False, "firewall_vendor": None}
    if os_type == "windows":
        output, rc = run_powershell(
            "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
        )
        data = parse_json_output(output, [])
        if isinstance(data, dict):
            data = [data]
        if any(p.get("Enabled") for p in data):
            perimeter["filtering_configured"] = True
            perimeter["firewall_vendor"] = "Windows Defender Firewall"
    elif os_type == "linux":
        # Check multiple firewall solutions
        for fw in [("firewalld", "firewalld"), ("ufw", "UFW"), ("iptables", "iptables")]:
            output, _, rc = run_command(["systemctl", "is-active", fw[0]])
            if rc == 0 and "active" in output:
                perimeter["filtering_configured"] = True
                perimeter["firewall_vendor"] = fw[1]
                break
    
    # Network Access Control check
    nac_solution = {"blocked": False, "nac_solution": None}
    nac_keywords = ['802.1X', 'NAC', 'Cisco ISE', 'ClearPass', 'ForeScout']
    installed, nac_tool = check_installed_software(nac_keywords)
    if installed:
        nac_solution["blocked"] = True
        nac_solution["nac_solution"] = nac_tool
    
    # Check for IDS/IPS
    ids_deployed = {"deployed": False, "vendor": None}
    ips_deployed = {"deployed": False, "vendor": None}
    
    ids_keywords = ['Snort', 'Suricata', 'Zeek', 'Security Onion']
    installed, ids_tool = check_installed_software(ids_keywords)
    if installed:
        ids_deployed["deployed"] = True
        ids_deployed["vendor"] = ids_tool
        ips_deployed["deployed"] = True
        ips_deployed["vendor"] = ids_tool
    
    # Network segmentation check
    segmentation = {"implemented": False, "vlans_count": 0}
    if os_type == "windows":
        output, rc = run_powershell(
            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Measure-Object | "
            "Select-Object -ExpandProperty Count"
        )
        if rc == 0 and output.isdigit() and int(output) > 1:
            segmentation["implemented"] = True
            segmentation["vlans_count"] = int(output)
    
    return {
        "network": {
            "unauthorized_devices": nac_solution,
            "devices": {"secure_configuration": False},
            "services": {"approved_only": False, "whitelist_maintained": False, "whitelist_enforced": False},
            "perimeter": perimeter,
            "port_mapping": {"complete": False},
            "port_scanning": {"automated": False, "frequency": None},
            "access_control": {"implemented": nac_solution["blocked"]}
        },
        "network_security": {
            "segmentation": segmentation,
            "dmz": {"implemented": False},
            "ids": ids_deployed,
            "ips": ips_deployed,
            "ddos_protection": {"enabled": False}
        }
    }

def collect_endpoint_security() -> Dict[str, Any]:
    """Collect endpoint security data with enhanced detection."""
    os_type = get_os_type()
    
    # Enhanced firewall check
    firewall_status = {"enabled": False, "centrally_managed": False, "policy_enforced": False}
    if os_type == "windows":
        output, rc = run_powershell(
            "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json"
        )
        data = parse_json_output(output, [])
        if isinstance(data, dict):
            data = [data]
        enabled_profiles = [p for p in data if p.get("Enabled")]
        firewall_status["enabled"] = len(enabled_profiles) >= 2
        firewall_status["policy_enforced"] = len(enabled_profiles) == 3
        
        # Check for GPO management
        output, rc = run_powershell(
            "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\WindowsFirewall' -ErrorAction SilentlyContinue"
        )
        if rc == 0 and output:
            firewall_status["centrally_managed"] = True
    
    # Enhanced antimalware check
    antimalware = {
        "deployed": False, 
        "vendor": None, 
        "centrally_managed": False, 
        "auto_update": {"enabled": False, "last_update": None},
        "removable_media": {"scanning": False},
        "logging": {"centralized": False},
        "real_time_protection": False
    }
    
    if os_type == "windows":
        # Check Windows Defender
        output, rc = run_powershell(
            "Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled, "
            "AntivirusSignatureLastUpdated | ConvertTo-Json"
        )
        data = parse_json_output(output, {})
        if data.get("AMServiceEnabled") and data.get("RealTimeProtectionEnabled"):
            antimalware["deployed"] = True
            antimalware["vendor"] = "Microsoft Defender"
            antimalware["real_time_protection"] = True
            antimalware["auto_update"]["enabled"] = True
            
            if data.get("AntivirusSignatureLastUpdated"):
                antimalware["auto_update"]["last_update"] = data["AntivirusSignatureLastUpdated"]
        
        # Check for other AV solutions
        av_keywords = ['Symantec', 'McAfee', 'Kaspersky', 'Trend Micro', 'Sophos', 'ESET']
        installed, av_tool = check_installed_software(av_keywords)
        if installed:
            antimalware["deployed"] = True
            antimalware["vendor"] = av_tool
    
    elif os_type == "linux":
        # Check ClamAV
        output, _, rc = run_command(["systemctl", "is-active", "clamav-daemon"])
        if rc == 0 and "active" in output:
            antimalware["deployed"] = True
            antimalware["vendor"] = "ClamAV"
    
    # Enhanced EDR check
    edr = {"deployed": False, "vendor": None, "features": []}
    
    # Check for EDR services
    for edr_name in SECURITY_TOOLS['edr']:
        running, service = check_service_running([edr_name])
        if running:
            edr["deployed"] = True
            edr["vendor"] = service
            edr["features"] = ["threat_detection", "response", "monitoring"]
            break
    
    if not edr["deployed"]:
        # Check for EDR processes
        running, process = check_process_running(SECURITY_TOOLS['edr'])
        if running:
            edr["deployed"] = True
            edr["vendor"] = process
    
    # Enhanced encryption check
    encryption = {"enabled": False, "volumes_encrypted": 0, "method": None}
    if os_type == "windows":
        output, rc = run_powershell(
            "Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus | ConvertTo-Json"
        )
        data = parse_json_output(output, [])
        if isinstance(data, dict):
            data = [data]
        
        encrypted_volumes = [v for v in data if v.get("VolumeStatus") == "FullyEncrypted"]
        if encrypted_volumes:
            encryption["enabled"] = True
            encryption["volumes_encrypted"] = len(encrypted_volumes)
            encryption["method"] = "BitLocker"
    
    elif os_type == "linux":
        output, _, rc = run_command(["lsblk", "-f"])
        if rc == 0:
            encrypted_count = output.count("crypto_LUKS")
            if encrypted_count > 0:
                encryption["enabled"] = True
                encryption["volumes_encrypted"] = encrypted_count
                encryption["method"] = "LUKS"
    
    # MDM check
    mdm = {"deployed": False, "vendor": None}
    for mdm_name in SECURITY_TOOLS['mdm']:
        running, service = check_service_running([mdm_name])
        if running:
            mdm["deployed"] = True
            mdm["vendor"] = service
            break
    
    # USB controls check
    usb_controls = {"enabled": False, "method": None}
    if os_type == "windows":
        exists, value = check_registry_key(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices",
            "Deny_All"
        )
        if exists:
            usb_controls["enabled"] = True
            usb_controls["method"] = "Group Policy"
    
    # Application whitelisting check
    app_whitelisting = {"enabled": False, "solution": None}
    if os_type == "windows":
        # Check AppLocker
        output, rc = run_powershell(
            "Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue | "
            "Select-Object -ExpandProperty RuleCollections"
        )
        if rc == 0 and output:
            app_whitelisting["enabled"] = True
            app_whitelisting["solution"] = "AppLocker"
    
    return {
        "servers": {"firewall": firewall_status},
        "workstations": {"firewall": firewall_status.copy()},
        "antimalware": antimalware,
        "devices": {"autorun": {"disabled": False}},
        "endpoints": {"host_firewall": {"enabled": firewall_status["enabled"]}},
        "applications": {"firewall": {"deployed": False}},
        "endpoint_security": {
            "edr": edr,
            "encryption": encryption,
            "mdm": mdm,
            "usb_controls": usb_controls,
            "application_whitelisting": app_whitelisting
        }
    }

def collect_os_security() -> Dict[str, Any]:
    """Collect operating system security data with enhanced detection."""
    os_type = get_os_type()
    
    secure_config = {"applied": False, "baseline": None, "checks": []}
    anti_exploit = {"enabled": False, "features": []}
    
    if os_type == "windows":
        # Check for security baselines
        output, rc = run_powershell(
            "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows' -ErrorAction SilentlyContinue"
        )
        if rc == 0 and output:
            secure_config["applied"] = True
            secure_config["baseline"] = "Windows Security Policy"
        
        # Check Exploit Protection (Windows 10+)
        output, rc = run_powershell(
            "Get-ProcessMitigation -System | ConvertTo-Json"
        )
        if rc == 0 and output:
            anti_exploit["enabled"] = True
            anti_exploit["features"] = ["DEP", "ASLR", "SEHOP"]
    
    elif os_type == "linux":
        # Check SELinux or AppArmor
        output, _, rc = run_command(["getenforce"])
        if rc == 0 and "Enforcing" in output:
            secure_config["applied"] = True
            secure_config["baseline"] = "SELinux"
        else:
            output, _, rc = run_command(["aa-status"])
            if rc == 0 and "apparmor" in output.lower():
                secure_config["applied"] = True
                secure_config["baseline"] = "AppArmor"
    
    return {
        "secure_configuration": secure_config,
        "anti_exploitation": anti_exploit
    }

def collect_deployment() -> Dict[str, Any]:
    """Collect deployment and configuration management data."""
    os_type = get_os_type()
    
    config_tools = {"deployed": False, "tool": None}
    
    # Check for configuration management tools
    for tool_name in SECURITY_TOOLS['config_mgmt']:
        running, service = check_service_running([tool_name])
        if running:
            config_tools["deployed"] = True
            config_tools["tool"] = service
            break
    
    if not config_tools["deployed"]:
        installed, tool = check_installed_software(SECURITY_TOOLS['config_mgmt'])
        if installed:
            config_tools["deployed"] = True
            config_tools["tool"] = tool
    
    return {
        "deployment": {
            "secure_images": {"maintained": False},
            "master_images": {"isolated": False, "storage_location": None}
        },
        "configuration_management": {
            "tools": config_tools,
            "monitoring": {"automated": config_tools["deployed"], "tool": config_tools["tool"]}
        }
    }

def collect_vulnerability_management() -> Dict[str, Any]:
    """Collect vulnerability and patch management data with enhanced detection."""
    os_type = get_os_type()
    
    # Vulnerability scanning check
    vuln_scanning = {"enabled": False, "tool": None}
    for vuln_tool in SECURITY_TOOLS['vulnerability']:
        installed, tool = check_installed_software([vuln_tool])
        if installed:
            vuln_scanning["enabled"] = True
            vuln_scanning["tool"] = tool
            break
    
    # Enhanced patching check
    patching = {"enabled": False, "os": False, "applications": False, "last_check": None}
    
    if os_type == "windows":
        # Check Windows Update service
        output, rc = run_powershell(
            "Get-Service -Name 'wuauserv' | Select-Object Status | ConvertTo-Json"
        )
        data = parse_json_output(output, {})
        if data.get("Status") == "Running":
            patching["enabled"] = True
            patching["os"] = True
        
        # Get last update check time
        output, rc = run_powershell(
            "(New-Object -ComObject Microsoft.Update.AutoUpdate).Results.LastSearchSuccessDate"
        )
        if rc == 0 and output:
            patching["last_check"] = output
        
        # Check for WSUS configuration
        exists, value = check_registry_key(
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate",
            "WUServer"
        )
        if exists:
            patching["enabled"] = True
            patching["applications"] = True
    
    elif os_type == "linux":
        # Check unattended-upgrades
        output, _, rc = run_command(["systemctl", "is-active", "unattended-upgrades"])
        if rc == 0 and "active" in output:
            patching["enabled"] = True
            patching["os"] = True
        
        # Check for automatic updates configuration
        if check_file_exists("/etc/apt/apt.conf.d/50unattended-upgrades"):
            patching["applications"] = True
    
    # Critical patching timeline check
    critical_patching = {"within_72_hours": False, "average_days": None}
    if patching["last_check"]:
        try:
            last_check = datetime.strptime(patching["last_check"], "%m/%d/%Y %I:%M:%S %p")
            days_since = (datetime.now() - last_check).days
            critical_patching["within_72_hours"] = days_since <= 3
            critical_patching["average_days"] = days_since
        except:
            pass
    
    return {
        "vulnerability_management": {
            "automated_scanning": vuln_scanning,
            "authenticated_scanning": {"enabled": vuln_scanning["enabled"]},
            "assessment_accounts": {"protected": False},
            "assessment": {"last_days": 999 if not vuln_scanning["enabled"] else 30},
            "penetration_test": {"last_days": 999},
            "critical_patching": critical_patching,
            "scanning_tools": {"deployed": vuln_scanning["enabled"]},
            "asset_inventory": {"maintained": True}
        },
        "patch_management": {
            "automated_patching": patching,
            "software_patching": {"enabled": patching["applications"]}
        }
    }

def collect_logging_monitoring() -> Dict[str, Any]:
    """Collect logging and monitoring data with enhanced detection."""
    os_type = get_os_type()
    
    central_logging = {"enabled": False, "platform": None}
    audit_logging = {"enabled": False, "categories": []}
    
    if os_type == "windows":
        # Check Windows Event Forwarding
        output, rc = run_powershell(
            "Get-Service -Name 'Wecsvc' -ErrorAction SilentlyContinue | Select-Object Status"
        )
        if "Running" in output:
            central_logging["enabled"] = True
            central_logging["platform"] = "Windows Event Forwarding"
        
        # Check audit policies
        output, rc = run_powershell(
            "auditpol /get /category:* | Select-String 'Success and Failure'"
        )
        if rc == 0 and output:
            lines = output.split('\n')
            audit_logging["enabled"] = len(lines) > 0
            audit_logging["categories"] = [line.strip() for line in lines if line.strip()]
    
    elif os_type == "linux":
        # Check auditd
        output, _, rc = run_command(["systemctl", "is-active", "auditd"])
        if rc == 0 and "active" in output:
            audit_logging["enabled"] = True
        
        # Check syslog forwarding
        if check_file_exists("/etc/rsyslog.d/"):
            output, _, rc = run_command(["grep", "-r", "@", "/etc/rsyslog.d/"])
            if rc == 0 and output:
                central_logging["enabled"] = True
                central_logging["platform"] = "rsyslog"
    
    # SIEM check
    siem = {"deployed": False, "vendor": None, "tuning": {"regular": False}}
    for siem_tool in SECURITY_TOOLS['siem']:
        # Check installed software
        installed, tool = check_installed_software([siem_tool])
        if installed:
            siem["deployed"] = True
            siem["vendor"] = tool
            break
        
        # Check running services
        running, service = check_service_running([siem_tool])
        if running:
            siem["deployed"] = True
            siem["vendor"] = service
            break
        
        # Check common SIEM ports
        siem_ports = {9997: 'Splunk', 514: 'Syslog', 5044: 'Logstash'}
        for port, name in siem_ports.items():
            if check_network_port_listening(port):
                siem["deployed"] = True
                siem["vendor"] = name
                break
    
    # Log retention check
    log_retention_days = 90
    if os_type == "windows":
        output, rc = run_powershell(
            "Get-EventLog -List | Select-Object -First 1 -ExpandProperty MaximumKilobytes"
        )
        if rc == 0 and output.isdigit():
            # Rough estimation based on log size
            max_kb = int(output)
            if max_kb > 100000:  # >100MB suggests longer retention
                log_retention_days = 180
    
    return {
        "logging": {
            "central_management": central_logging,
            "audit": audit_logging,
            "detailed": {"enabled": audit_logging["enabled"]},
            "storage": {"adequate": log_retention_days >= 90, "retention_days": log_retention_days},
            "analysis": {"central": siem["deployed"]},
            "review": {"regular": siem["deployed"], "frequency": "daily" if siem["deployed"] else None}
        },
        "siem": siem,
        "security_monitoring": {
            "soc": {"operational": siem["deployed"], "staffing": None},
            "siem": {"deployed": siem["deployed"]},
            "log_retention": {"days": log_retention_days},
            "realtime": {"enabled": siem["deployed"]},
            "automated_response": {"enabled": False}
        }
    }

def collect_application_security() -> Dict[str, Any]:
    """Collect application security data with enhanced detection."""
    os_type = get_os_type()
    
    # Browser version check
    browsers_info = {"supported_only": False, "versions": [], "plugins": {"controlled": False, "whitelist": []}}
    
    if os_type == "windows":
        # Check Chrome
        output, rc = run_powershell(
            "(Get-Item 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe' -ErrorAction SilentlyContinue).VersionInfo.FileVersion"
        )
        if rc == 0 and output:
            browsers_info["versions"].append(f"Chrome {output}")
        
        # Check Edge
        output, rc = run_powershell(
            "(Get-AppxPackage -Name 'Microsoft.MicrosoftEdge*' -ErrorAction SilentlyContinue).Version"
        )
        if rc == 0 and output:
            browsers_info["versions"].append(f"Edge {output}")
        
        if browsers_info["versions"]:
            browsers_info["supported_only"] = True
    
    # Email security check
    email_security = {"security_policies": {"enforced": False}, "file_blocking": {"enabled": False, "blocked_types": []}}
    
    if os_type == "windows":
        # Check Outlook policies
        exists, value = check_registry_key(
            "HKCU:\\Software\\Policies\\Microsoft\\Office\\16.0\\Outlook\\Security"
        )
        if exists:
            email_security["security_policies"]["enforced"] = True
    
    # Web proxy check
    web_proxy = {"url_logging": {"enabled": False, "retention_days": 0}}
    proxy_tools = ['Squid', 'Proxy', 'BlueCoat', 'Zscaler']
    installed, proxy = check_installed_software(proxy_tools)
    if installed:
        web_proxy["url_logging"]["enabled"] = True
        web_proxy["url_logging"]["retention_days"] = 90
    
    # DNS logging check
    dns_logging = {"query_logging": {"enabled": False}}
    if os_type == "windows":
        output, rc = run_powershell(
            "Get-DnsServerDiagnostics -ErrorAction SilentlyContinue | Select-Object -ExpandProperty EnableLoggingForPluginDllEvent"
        )
        if rc == 0 and "True" in output:
            dns_logging["query_logging"]["enabled"] = True
    
    # Command line auditing
    cmd_audit = {"audit_logging": {"enabled": False}}
    if os_type == "windows":
        output, rc = run_powershell(
            "auditpol /get /subcategory:'Process Creation' | Select-String 'Success'"
        )
        if rc == 0 and output:
            cmd_audit["audit_logging"]["enabled"] = True
    elif os_type == "linux":
        if check_file_exists("/etc/audit/rules.d/"):
            output, _, rc = run_command(["grep", "-r", "execve", "/etc/audit/rules.d/"])
            if rc == 0:
                cmd_audit["audit_logging"]["enabled"] = True
    
    # WAF check
    waf = {"deployed": False, "vendor": None}
    waf_tools = ['ModSecurity', 'WAF', 'F5', 'Imperva', 'Cloudflare']
    installed, waf_tool = check_installed_software(waf_tools)
    if installed:
        waf["deployed"] = True
        waf["vendor"] = waf_tool
    
    return {
        "browsers": browsers_info,
        "email": email_security,
        "web_proxy": web_proxy,
        "dns": dns_logging,
        "command_line": cmd_audit,
        "application_security": {
            "sdlc": {"implemented": False},
            "sast": {"enabled": False},
            "dast": {"enabled": False},
            "code_review": {"mandatory": False},
            "waf": waf
        }
    }

def collect_backup_recovery() -> Dict[str, Any]:
    """Collect backup and disaster recovery data with enhanced detection."""
    os_type = get_os_type()
    
    backup = {"enabled": False, "frequency": None, "solution": None, "last_backup": None}
    
    if os_type == "windows":
        # Check Windows Backup
        output, rc = run_powershell(
            "Get-WBPolicy -ErrorAction SilentlyContinue | Select-Object Schedule | ConvertTo-Json"
        )
        if rc == 0 and output:
            backup["enabled"] = True
            backup["frequency"] = "daily"
            backup["solution"] = "Windows Backup"
        
        # Check for third-party backup solutions
        for backup_tool in SECURITY_TOOLS['backup']:
            installed, tool = check_installed_software([backup_tool])
            if installed:
                backup["enabled"] = True
                backup["solution"] = tool
                backup["frequency"] = "scheduled"
                break
            
            running, service = check_service_running([backup_tool])
            if running:
                backup["enabled"] = True
                backup["solution"] = service
                backup["frequency"] = "scheduled"
                break
    
    elif os_type == "linux":
        # Check for backup tools
        backup_tools = ['bacula', 'rsync', 'duplicity', 'restic']
        for tool in backup_tools:
            output, _, rc = run_command(["which", tool])
            if rc == 0:
                backup["enabled"] = True
                backup["solution"] = tool
                break
        
        # Check cron for backup jobs
        if check_file_exists("/etc/cron.d/"):
            output, _, rc = run_command(["grep", "-r", "backup", "/etc/cron.d/"])
            if rc == 0 and output:
                backup["enabled"] = True
                backup["frequency"] = "scheduled"
    
    # Backup encryption check
    backup_protection = {"enabled": backup["enabled"], "encryption": False}
    if backup["enabled"] and backup["solution"]:
        # Many modern backup solutions encrypt by default
        if any(tool in str(backup["solution"]) for tool in ['Veeam', 'Acronis', 'Commvault']):
            backup_protection["encryption"] = True
    
    return {
        "backup": {
            "automated": backup,
            "complete_system": {"enabled": backup["enabled"]},
            "testing": {"regular": False, "last_test_days": 999},
            "protection": backup_protection,
            "offline": {"available": False}
        },
        "business_continuity": {
            "plan": {"exists": False},
            "disaster_recovery": {"plan_exists": False},
            "testing": {"last_days": 999},
            "rto": {"defined": False},
            "rpo": {"defined": False}
        }
    }

def collect_access_control() -> Dict[str, Any]:
    """Collect access control data with enhanced detection."""
    os_type = get_os_type()
    
    # Privileged access management
    privileged_access = {"managed": False, "admin_count": None}
    if os_type == "windows":
        output, rc = run_powershell(
            "Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc == 0 and output.isdigit():
            admin_count = int(output)
            privileged_access["managed"] = admin_count <= 5
            privileged_access["admin_count"] = admin_count
    elif os_type == "linux":
        output, _, rc = run_command(["getent", "group", "sudo"])
        if rc == 0:
            users = output.split(':')[-1].split(',') if ':' in output else []
            privileged_access["admin_count"] = len(users)
            privileged_access["managed"] = len(users) <= 5
    
    # PAM system check
    pam_system = {"deployed": False, "vendor": None}
    for pam_tool in SECURITY_TOOLS['pam']:
        installed, tool = check_installed_software([pam_tool])
        if installed:
            pam_system["deployed"] = True
            pam_system["vendor"] = tool
            break
    
    # MFA check
    mfa_enabled = {"privileged_users": False, "customer_access": False}
    
    if os_type == "windows":
        # Check for MFA providers
        mfa_tools = ['Duo', 'Okta', 'Azure MFA', 'Google Authenticator']
        installed, mfa_tool = check_installed_software(mfa_tools)
        if installed:
            mfa_enabled["privileged_users"] = True
            mfa_enabled["customer_access"] = True
        
        # Check Windows Hello
        output, rc = run_powershell(
            "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\DeviceLock' -Name 'DevicePasswordEnabled' -ErrorAction SilentlyContinue"
        )
        if rc == 0:
            mfa_enabled["privileged_users"] = True
    
    # Password policy check
    password_robust = {"robust": False, "min_length": 0, "complexity": False, "max_age": None}
    
    if os_type == "windows":
        output, rc = run_powershell(
            "net accounts"
        )
        if rc == 0:
            # Parse minimum password length
            length_match = re.search(r'Minimum password length\s*:\s*(\d+)', output)
            if length_match:
                min_length = int(length_match.group(1))
                password_robust["min_length"] = min_length
                password_robust["robust"] = min_length >= 8
            
            # Check password age
            age_match = re.search(r'Maximum password age \(days\)\s*:\s*(\d+)', output)
            if age_match:
                password_robust["max_age"] = int(age_match.group(1))
        
        # Check complexity requirements
        output, rc = run_powershell(
            "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters' -ErrorAction SilentlyContinue"
        )
        if rc == 0:
            password_robust["complexity"] = True
    
    elif os_type == "linux":
        if check_file_exists("/etc/security/pwquality.conf"):
            output, _, rc = run_command(["grep", "minlen", "/etc/security/pwquality.conf"])
            if rc == 0:
                match = re.search(r'minlen\s*=\s*(\d+)', output)
                if match:
                    min_length = int(match.group(1))
                    password_robust["min_length"] = min_length
                    password_robust["robust"] = min_length >= 8
    
    return {
        "access_control": {
            "policy": {"exists": False},
            "privileged_users": mfa_enabled,
            "customer_access": mfa_enabled,
            "pam_system": pam_system,
            "session_recording": {"enabled": pam_system["deployed"]},
            "rights_review": {"last_days": 999}
        },
        "users": {
            "registration_process": {"formal": False},
            "access_provisioning": {"controlled": False},
            "privileged_access": privileged_access,
            "access_review": {"regular": False},
            "access_removal": {"timely": False},
            "authentication_responsibilities": {"understood": False}
        },
        "authentication": {"secret_management": {"secure": mfa_enabled["privileged_users"]}},
        "systems": {
            "access_restriction": {"implemented": True},
            "secure_logon": {"implemented": True},
            "password_management": password_robust,
            "privileged_utilities": {"controlled": privileged_access["managed"]}
        },
        "development": {"source_code_access": {"controlled": False}}
    }

def collect_cryptography() -> Dict[str, Any]:
    """Collect cryptography and data protection data with enhanced detection."""
    os_type = get_os_type()
    
    encryption = {"encrypted_at_rest": False, "encrypted_in_transit": False}
    
    # Disk encryption check (at rest)
    if os_type == "windows":
        output, rc = run_powershell(
            "Get-BitLockerVolume | Where-Object {$_.VolumeStatus -eq 'FullyEncrypted'} | Measure-Object | Select-Object -ExpandProperty Count"
        )
        if rc == 0 and output.isdigit() and int(output) > 0:
            encryption["encrypted_at_rest"] = True
    elif os_type == "linux":
        output, _, rc = run_command(["lsblk", "-f"])
        if rc == 0 and "crypto_LUKS" in output:
            encryption["encrypted_at_rest"] = True
    
    # TLS/SSL check (in transit)
    tls_check = {"encrypted_in_transit": False, "protocols": []}
    
    if os_type == "windows":
        # Check TLS settings
        output, rc = run_powershell(
            "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.2\\Server' -Name 'Enabled' -ErrorAction SilentlyContinue"
        )
        if rc == 0 and "1" in output:
            tls_check["encrypted_in_transit"] = True
            tls_check["protocols"].append("TLS 1.2")
        
        output, rc = run_powershell(
            "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.3\\Server' -Name 'Enabled' -ErrorAction SilentlyContinue"
        )
        if rc == 0 and "1" in output:
            tls_check["protocols"].append("TLS 1.3")
    
    encryption["encrypted_in_transit"] = tls_check["encrypted_in_transit"]
    
    # Key management check
    key_management = {"implemented": False, "solution": None}
    km_tools = ['KeyVault', 'HSM', 'KMS', 'Key Management']
    installed, km_tool = check_installed_software(km_tools)
    if installed:
        key_management["implemented"] = True
        key_management["solution"] = km_tool
    
    return {
        "cryptography": {
            "policy": {"exists": False},
            "key_management": key_management,
            "tls_protocols": tls_check["protocols"]
        },
        "data_protection": {
            "customer_data": encryption,
            "database_monitoring": {"enabled": False},
            "data_masking": {"non_production": False},
            "retention_policy": {"implemented": False}
        }
    }

def collect_physical_security() -> Dict[str, Any]:
    """Collect physical security data (mostly manual checks)."""
    return {
        "physical": {
            "security_perimeter": {"defined": False},
            "entry_controls": {"implemented": False},
            "environmental_protection": {"implemented": False},
            "secure_areas": {"procedures": False, "access_controlled": False},
            "delivery_areas": {"controlled": False}
        },
        "equipment": {
            "siting_protection": {"implemented": False},
            "utilities": {"protected": False},
            "cabling": {"protected": False},
            "maintenance": {"controlled": False},
            "removal": {"authorized": False},
            "offsite": {"protected": False},
            "disposal": {"secure": False},
            "unattended": {"protected": False}
        },
        "workplace": {"clear_desk_screen": {"enforced": False}}
    }

def collect_operations_governance() -> Dict[str, Any]:
    """Collect operations and governance data."""
    os_type = get_os_type()
    
    # Check for documented procedures
    procedures_documented = {"documented": False, "location": None}
    common_doc_locations = [
        "C:\\Documentation",
        "C:\\IT\\Procedures",
        "/usr/share/doc",
        "/opt/documentation"
    ]
    
    for location in common_doc_locations:
        if check_file_exists(location):
            procedures_documented["documented"] = True
            procedures_documented["location"] = location
            break
    
    # Environment separation check
    env_separation = {"implemented": False, "environments": []}
    if os_type == "windows":
        # Check for multiple network profiles or domains
        output, rc = run_powershell(
            "Get-NetConnectionProfile | Select-Object NetworkCategory | ConvertTo-Json"
        )
        data = parse_json_output(output, [])
        if isinstance(data, list) and len(data) > 1:
            env_separation["implemented"] = True
    
    return {
        "operations": {
            "procedures": procedures_documented,
            "change_management": {"implemented": False},
            "capacity_management": {"monitored": False},
            "environment_separation": env_separation
        },
        "governance": {
            "board_approved_policy": {"exists": False},
            "security_strategy": {"documented": False},
            "ciso": {"appointed": False},
            "security_committee": {"established": False}
        },
        "policies": {"information_security": {"exists": False, "last_review_days": 999}},
        "organization": {
            "roles_responsibilities": {"defined": False},
            "segregation_of_duties": {"implemented": False},
            "authority_contacts": {"maintained": False},
            "special_groups": {"contact": False}
        },
        "projects": {"security_integration": {"mandatory": False}},
        "mobile_devices": {"policy": {"exists": False}},
        "teleworking": {"policy": {"exists": False}}
    }

def collect_hr_training() -> Dict[str, Any]:
    """Collect HR and training data (mostly manual/policy checks)."""
    return {
        "hr": {
            "background_screening": {"mandatory": False},
            "employment_terms": {"security_clauses": False},
            "management": {"security_responsibilities": False},
            "disciplinary_process": {"defined": False},
            "termination": {"security_procedures": False}
        },
        "training": {
            "security_awareness": {"regular": False},
            "cybersecurity": {"annual": False},
            "phishing_simulation": {"regular": False},
            "awareness_metrics": {"tracked": False},
            "role_based": {"implemented": False},
            "culture_assessment": {"conducted": False}
        }
    }

def collect_asset_information() -> Dict[str, Any]:
    """Collect asset and information management data."""
    return {
        "assets": {
            "inventory": {"maintained": True},
            "ownership": {"assigned": False},
            "acceptable_use": {"policy": False},
            "return_procedures": {"defined": False}
        },
        "information": {
            "classification": {"implemented": False},
            "labelling": {"implemented": False},
            "handling_procedures": {"defined": False}
        },
        "media": {
            "removable": {"management_procedures": False},
            "disposal": {"secure_procedures": False},
            "transfer": {"protected": False}
        }
    }

def collect_incident_response() -> Dict[str, Any]:
    """Collect incident response data."""
    os_type = get_os_type()
    
    # Check for incident response tools
    ir_tools = ['TheHive', 'Incident', 'Response', 'SOAR']
    ir_capability = {"capability": False, "tools": []}
    
    installed, tool = check_installed_software(ir_tools)
    if installed:
        ir_capability["capability"] = True
        ir_capability["tools"].append(tool)
    
    return {
        "plan": {"exists": False},
        "team": {"established": False},
        "rbi_reporting": {"within_2_hours": False},
        "testing": {"last_days": 999},
        "forensics": ir_capability
    }

def collect_third_party() -> Dict[str, Any]:
    """Collect third-party management data (mostly manual/policy checks)."""
    return {
        "risk_assessment": {"conducted": False},
        "security_standards": {"enforced": False},
        "continuous_monitoring": {"enabled": False},
        "data_sharing_agreements": {"signed": False},
        "audit_rights": {"established": False}
    }

# ---------------------------------------------------------------------
# MAIN ORCHESTRATOR
# ---------------------------------------------------------------------
def collect_all_compliance_data() -> Dict[str, Any]:
    """Main orchestrator function to collect all compliance data."""
    LOG.info("=" * 70)
    LOG.info("🚀 Starting Enhanced Compliance Data Collection")
    LOG.info("=" * 70)
    
    os_type = get_os_type()
    LOG.info(f"📊 Operating System: {platform.system()} ({platform.release()})")
    LOG.info(f"💻 Hostname: {platform.node()}")
    LOG.info(f"🔧 Platform: {platform.platform()}")
    LOG.info("")
    
    # Initialize compliance data structure
    compliance_data = {
        "company_name": os.getenv("COMPANY_NAME", "Collected System"),
        "company_type": os.getenv("COMPANY_TYPE", "Unknown"),
        "evaluation_date": datetime.now().strftime("%Y-%m-%d"),
        "collection_timestamp": datetime.now().isoformat(),
        "system_info": {
            "os_type": platform.system(),
            "os_version": platform.release(),
            "hostname": platform.node(),
            "platform": platform.platform(),
            "python_version": platform.python_version()
        }
    }
    
    # Collect all compliance data with progress tracking
    sections = [
        ("Asset Management", "asset_management", collect_asset_management),
        ("Network Security", "network", collect_network_security),
        ("Endpoint Security", "endpoint_security", collect_endpoint_security),
        ("Operating System Security", "operating_systems", collect_os_security),
        ("Deployment & Configuration", "deployment", collect_deployment),
        ("Vulnerability & Patch Management", "vulnerability", collect_vulnerability_management),
        ("Logging & Monitoring", "logging", collect_logging_monitoring),
        ("Application Security", "application", collect_application_security),
        ("Backup & DR", "backup", collect_backup_recovery),
        ("Access Control", "access_control", collect_access_control),
        ("Cryptography & Data Protection", "cryptography", collect_cryptography),
        ("Physical Security", "physical", collect_physical_security),
        ("Operations & Governance", "operations", collect_operations_governance),
        ("HR & Training", "hr", collect_hr_training),
        ("Asset & Information Management", "assets", collect_asset_information),
        ("Incident Response", "incident_response", collect_incident_response),
        ("Third Party Management", "third_party", collect_third_party),
    ]
    
    for display_name, key, collector_func in sections:
        LOG.info(f"📦 Collecting {display_name}...")
        try:
            result = collector_func()
            # Handle functions that return nested data
            if isinstance(result, dict) and len(result) > 1 and key not in result:
                compliance_data.update(result)
            else:
                compliance_data[key] = result
        except Exception as e:
            LOG.error(f"❌ Error collecting {display_name}: {e}")
            compliance_data[key] = {"error": str(e)}
    
    LOG.info("")
    LOG.info("=" * 70)
    LOG.info("✅ Enhanced Compliance Data Collection Complete")
    LOG.info("=" * 70)
    
    return compliance_data

# ---------------------------------------------------------------------
# OO WRAPPER FOR INTEGRATION
# ---------------------------------------------------------------------
class ComplianceCollector:
    """Thin wrapper to integrate functional collector with orchestrator."""
    
    def collect_all(self) -> Dict[str, Any]:
        """Collect a single compliance snapshot."""
        return collect_all_compliance_data()
    
    def collect_realtime(self, output_path: Path, interval: int = DEFAULT_INTERVAL) -> bool:
        """Continuously collect snapshots at a fixed interval until interrupted."""
        try:
            LOG.info(f"🔄 Real-time collection started (interval: {interval}s)")
            iteration = 0
            while True:
                iteration += 1
                LOG.info(f"\n📊 Collection iteration #{iteration}")
                data = collect_all_compliance_data()
                save_compliance_data(data, output_path)
                LOG.info(f"⏳ Sleeping for {interval}s...")
                time.sleep(interval)
        except KeyboardInterrupt:
            LOG.info("\n🛑 Real-time collection stopped by user")
            return True
        except Exception as e:
            LOG.error(f"❌ Real-time collection failed: {e}")
            return False

# ---------------------------------------------------------------------
# FILE OPERATIONS
# ---------------------------------------------------------------------
def save_compliance_data(data: Dict[str, Any], output_path: Path) -> None:
    """Save compliance data to JSON file."""
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        LOG.info(f"💾 Compliance snapshot saved to: {output_path}")
        LOG.info(f"📊 File size: {output_path.stat().st_size / 1024:.2f} KB")
        
    except Exception as e:
        LOG.error(f"❌ Failed to save compliance data: {e}")
        raise

# ---------------------------------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------------------------------
def main():
    """Main entry point for the compliance collector."""
    parser = argparse.ArgumentParser(
        description="Enhanced Real-Time Compliance Posture Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single collection
  python realtime_collector.py
  
  # Continuous real-time collection (every 5 minutes)
  python realtime_collector.py --realtime
  
  # Custom interval (every 10 minutes)
  python realtime_collector.py --realtime --interval 600
  
  # Custom output location
  python realtime_collector.py --output /path/to/output.json
        """
    )
    
    parser.add_argument(
        "--realtime",
        action="store_true",
        help="Enable continuous real-time collection mode"
    )
    
    parser.add_argument(
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        help=f"Collection interval in seconds (default: {DEFAULT_INTERVAL})"
    )
    
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_FILE,
        help=f"Output file path (default: {OUTPUT_FILE})"
    )
    
    args = parser.parse_args()
    
    try:
        if args.realtime:
            LOG.info(f"🔄 Real-time mode enabled (interval: {args.interval}s)")
            LOG.info("Press Ctrl+C to stop")
            LOG.info("")
            
            iteration = 0
            while True:
                iteration += 1
                LOG.info(f"🔄 Collection iteration #{iteration}")
                
                compliance_data = collect_all_compliance_data()
                save_compliance_data(compliance_data, args.output)
                
                LOG.info(f"⏳ Waiting {args.interval} seconds until next collection...")
                LOG.info("")
                time.sleep(args.interval)
        else:
            # Single collection
            compliance_data = collect_all_compliance_data()
            save_compliance_data(compliance_data, args.output)
            
            print("\n" + "=" * 70)
            print("✅ Compliance snapshot collected successfully.")
            print(f"📁 Saved to: {args.output.absolute()}")
            print("=" * 70)
    
    except KeyboardInterrupt:
        LOG.info("\n🛑 Collection stopped by user")
        sys.exit(0)
    except Exception as e:
        LOG.error(f"\n❌ Fatal error: {e}")
        LOG.exception(e)
        sys.exit(1)

if __name__ == "__main__":
    main()