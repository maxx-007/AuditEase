"""
Compliance AI - Real-Time Data Collection Module
================================================
Collects compliance posture data from live systems.
"""

import logging
import platform
import subprocess
import os
import time
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime

from modules.utils import save_json_file, safe_bool_to_int


class ComplianceCollector:
    """Real-time compliance data collector."""
    
    def __init__(self, company_name: Optional[str] = None, company_type: Optional[str] = None):
        """
        Initialize collector.
        
        Args:
            company_name: Company name for assessment
            company_type: Company type/industry
        """
        self.logger = logging.getLogger("ComplianceAI.Collector")
        self.company_name = company_name or os.getenv("COMPANY_NAME", "Collected System")
        self.company_type = company_type or os.getenv("COMPANY_TYPE", "Unknown")
        self.os_type = platform.system().lower()
    
    def collect_once(self, output_path: Path) -> bool:
        """
        Collect compliance data snapshot once.
        
        Args:
            output_path: Path for output JSON file
        
        Returns:
            True if successful
        """
        try:
            self.logger.info("=" * 70)
            self.logger.info("Starting Compliance Data Collection")
            self.logger.info("=" * 70)
            
            data = self._collect_all_data()
            
            if save_json_file(data, output_path):
                file_size = output_path.stat().st_size / 1024
                self.logger.info(f"💾 Data saved: {output_path} ({file_size:.2f} KB)")
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.exception(f"Collection failed: {e}")
            return False
    
    def collect_realtime(self, output_path: Path, interval: int = 300) -> bool:
        """
        Continuously collect compliance data at intervals.
        
        Args:
            output_path: Path for output JSON file
            interval: Collection interval in seconds
        
        Returns:
            True if successful (runs until interrupted)
        """
        iteration = 0
        
        try:
            while True:
                iteration += 1
                self.logger.info(f"🔄 Collection iteration #{iteration}")
                
                if not self.collect_once(output_path):
                    self.logger.warning("Collection iteration failed")
                
                self.logger.info(f"⏳ Waiting {interval} seconds...")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.logger.info("Collection stopped by user")
            return True
        except Exception as e:
            self.logger.exception(f"Real-time collection failed: {e}")
            return False
    
    def _collect_all_data(self) -> Dict[str, Any]:
        """Orchestrate collection of all compliance data."""
        data = {
            "company_name": self.company_name,
            "company_type": self.company_type,
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
        
        # Collect all compliance sections
        sections = [
            ("Asset Management", self._collect_asset_management),
            ("Network Security", self._collect_network_security),
            ("Endpoint Security", self._collect_endpoint_security),
            ("Vulnerability Management", self._collect_vulnerability_management),
            ("Logging & Monitoring", self._collect_logging_monitoring),
            ("Application Security", self._collect_application_security),
            ("Backup & Recovery", self._collect_backup_recovery),
            ("Access Control", self._collect_access_control),
            ("Cryptography", self._collect_cryptography),
            ("Physical Security", self._collect_physical_security),
            ("Operations & Governance", self._collect_operations_governance),
            ("HR & Training", self._collect_hr_training),
            ("Incident Response", self._collect_incident_response),
            ("Third Party", self._collect_third_party),
        ]
        
        for name, collector_func in sections:
            self.logger.info(f"📦 Collecting {name}...")
            try:
                result = collector_func()
                if isinstance(result, dict):
                    data.update(result)
            except Exception as e:
                self.logger.error(f"Failed to collect {name}: {e}")
                data[name.lower().replace(" ", "_")] = {"error": str(e)}
        
        return data
    
    def _run_command(self, command: List[str], timeout: int = 30) -> Tuple[str, str, int]:
        """Execute system command safely."""
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
            return "", "Timeout", -1
        except Exception as e:
            return "", str(e), -1
    
    def _run_powershell(self, command: str) -> Tuple[str, int]:
        """Execute PowerShell command (Windows only)."""
        if self.os_type != "windows":
            return "", -1
        stdout, stderr, rc = self._run_command(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command]
        )
        return stdout, rc
    
    def _check_service_running(self, service_name: str) -> bool:
        """Check if a service is running."""
        if self.os_type == "windows":
            output, rc = self._run_powershell(
                f"Get-Service -Name '{service_name}' -ErrorAction SilentlyContinue | "
                f"Where-Object {{$_.Status -eq 'Running'}}"
            )
            return rc == 0 and output != ""
        elif self.os_type == "linux":
            output, _, rc = self._run_command(["systemctl", "is-active", service_name])
            return rc == 0 and "active" in output
        return False
    
    def _check_file_exists(self, path: str) -> bool:
        """Check if file exists."""
        return Path(path).exists()
    
    # Collection methods for each compliance area
    
    def _collect_asset_management(self) -> Dict[str, Any]:
        """Collect asset management data."""
        software_inventory = {"maintained": False, "count": 0}
        
        if self.os_type == "windows":
            output, rc = self._run_powershell(
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | "
                "Measure-Object | Select-Object -ExpandProperty Count"
            )
            if rc == 0 and output.isdigit():
                count = int(output)
                software_inventory = {
                    "maintained": count > 0,
                    "count": count,
                    "last_updated": datetime.now().strftime("%Y-%m-%d")
                }
        
        return {
            "software_inventory": software_inventory,
            "unauthorized_software": {"detected": False},
            "sam_tools": {"deployed": False},
            "hardware_inventory": {"maintained": True, "automated": False}
        }
    
    def _collect_network_security(self) -> Dict[str, Any]:
        """Collect network security data."""
        firewall_enabled = False
        
        if self.os_type == "windows":
            output, rc = self._run_powershell(
                "Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $true} | Measure-Object"
            )
            firewall_enabled = rc == 0 and "Count" in output
        
        return {
            "network": {
                "network": {
                    "unauthorized_devices": {"blocked": False},
                    "devices": {"secure_configuration": False},
                    "services": {"approved_only": False, "whitelist_enforced": False},
                    "perimeter": {"filtering_configured": firewall_enabled}
                },
                "network_security": {
                    "segmentation": {"implemented": False, "vlans_count": 0},
                    "dmz": {"implemented": False},
                    "ids": {"deployed": False},
                    "ips": {"deployed": False}
                }
            }
        }
    
    def _collect_endpoint_security(self) -> Dict[str, Any]:
        """Collect endpoint security data."""
        antimalware = {"deployed": False, "centrally_managed": False, 
                      "auto_update": {"enabled": False}, "real_time_protection": False}
        
        if self.os_type == "windows":
            output, rc = self._run_powershell(
                "Get-MpComputerStatus | Select-Object AMServiceEnabled, RealTimeProtectionEnabled"
            )
            if rc == 0 and "True" in output:
                antimalware = {
                    "deployed": True,
                    "centrally_managed": False,
                    "auto_update": {"enabled": True},
                    "real_time_protection": True
                }
        
        encryption = {"enabled": False, "volumes_encrypted": 0}
        
        if self.os_type == "windows":
            output, rc = self._run_powershell(
                "Get-BitLockerVolume | Where-Object {$_.VolumeStatus -eq 'FullyEncrypted'} | Measure-Object"
            )
            if rc == 0 and "Count" in output:
                encryption["enabled"] = True
        
        return {
            "antimalware": antimalware,
            "servers": {"firewall": {"enabled": False, "centrally_managed": False, "policy_enforced": False}},
            "workstations": {"firewall": {"enabled": False, "centrally_managed": False, "policy_enforced": False}},
            "endpoint_security": {
                "edr": {"deployed": False, "features": []},
                "encryption": encryption,
                "mdm": {"deployed": False},
                "usb_controls": {"enabled": False},
                "application_whitelisting": {"enabled": False}
            }
        }
    
    def _collect_vulnerability_management(self) -> Dict[str, Any]:
        """Collect vulnerability and patch management data."""
        patching = {"enabled": False, "os": False, "applications": False}
        
        if self.os_type == "windows":
            if self._check_service_running("wuauserv"):
                patching = {"enabled": True, "os": True, "applications": False}
        
        return {
            "vulnerability_management": {
                "automated_scanning": {"enabled": False},
                "authenticated_scanning": {"enabled": False},
                "assessment_accounts": {"protected": False},
                "assessment": {"last_days": 999},
                "penetration_test": {"last_days": 999},
                "critical_patching": {"within_72_hours": False}
            },
            "patch_management": {
                "automated_patching": patching,
                "software_patching": {"enabled": patching["applications"]}
            }
        }
    
    def _collect_logging_monitoring(self) -> Dict[str, Any]:
        """Collect logging and monitoring data."""
        audit_enabled = False
        
        if self.os_type == "windows":
            output, rc = self._run_powershell("auditpol /get /category:*")
            audit_enabled = rc == 0 and "Success" in output
        
        return {
            "logging": {
                "logging": {
                    "central_management": {"enabled": False},
                    "audit": {"enabled": audit_enabled},
                    "storage": {"retention_days": 90},
                    "analysis": {"central": False}
                },
                "siem": {"deployed": False, "tuning": {"regular": False}},
                "security_monitoring": {
                    "soc": {"operational": False},
                    "realtime": {"enabled": False},
                    "automated_response": {"enabled": False}
                }
            }
        }
    
    def _collect_application_security(self) -> Dict[str, Any]:
        """Collect application security data."""
        return {
            "application_security": {
                "sdlc": {"implemented": False},
                "sast": {"enabled": False},
                "dast": {"enabled": False},
                "code_review": {"mandatory": False},
                "waf": {"deployed": False}
            }
        }
    
    def _collect_backup_recovery(self) -> Dict[str, Any]:
        """Collect backup and recovery data."""
        backup_enabled = False
        
        if self.os_type == "windows":
            output, rc = self._run_powershell(
                "Get-WBPolicy -ErrorAction SilentlyContinue"
            )
            backup_enabled = rc == 0 and output != ""
        
        return {
            "backup": {
                "backup": {
                    "automated": {"enabled": backup_enabled},
                    "complete_system": {"enabled": backup_enabled},
                    "testing": {"regular": False},
                    "protection": {"encryption": False},
                    "offline": {"available": False}
                },
                "business_continuity": {
                    "plan": {"exists": False},
                    "disaster_recovery": {"plan_exists": False},
                    "rto": {"defined": False},
                    "rpo": {"defined": False}
                }
            }
        }
    
    def _collect_access_control(self) -> Dict[str, Any]:
        """Collect access control data."""
        admin_count = 0
        
        if self.os_type == "windows":
            output, rc = self._run_powershell(
                "Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | "
                "Measure-Object | Select-Object -ExpandProperty Count"
            )
            if rc == 0 and output.isdigit():
                admin_count = int(output)
        
        return {
            "access_control": {
                "access_control": {
                    "policy": {"exists": False},
                    "pam_system": {"deployed": False},
                    "session_recording": {"enabled": False},
                    "rights_review": {"last_days": 999}
                },
                "users": {
                    "registration_process": {"formal": False},
                    "access_provisioning": {"controlled": False},
                    "privileged_access": {
                        "managed": admin_count <= 5,
                        "admin_count": admin_count
                    },
                    "access_review": {"regular": False}
                },
                "systems": {
                    "password_management": {
                        "robust": False,
                        "min_length": 0,
                        "complexity": False,
                        "max_age": 999
                    }
                }
            }
        }
    
    def _collect_cryptography(self) -> Dict[str, Any]:
        """Collect cryptography data."""
        encryption_at_rest = False
        
        if self.os_type == "windows":
            output, rc = self._run_powershell(
                "Get-BitLockerVolume | Where-Object {$_.VolumeStatus -eq 'FullyEncrypted'}"
            )
            encryption_at_rest = rc == 0 and output != ""
        
        return {
            "cryptography": {
                "cryptography": {
                    "policy": {"exists": False},
                    "key_management": {"implemented": False},
                    "tls_protocols": []
                },
                "data_protection": {
                    "customer_data": {
                        "encrypted_at_rest": encryption_at_rest,
                        "encrypted_in_transit": False
                    },
                    "database_monitoring": {"enabled": False},
                    "data_masking": {"non_production": False}
                }
            }
        }
    
    def _collect_physical_security(self) -> Dict[str, Any]:
        """Collect physical security data (manual checks)."""
        return {
            "physical": {
                "physical": {
                    "security_perimeter": {"defined": False},
                    "entry_controls": {"implemented": False},
                    "environmental_protection": {"implemented": False}
                }
            }
        }
    
    def _collect_operations_governance(self) -> Dict[str, Any]:
        """Collect operations and governance data."""
        return {
            "operations": {
                "governance": {
                    "board_approved_policy": {"exists": False},
                    "security_strategy": {"documented": False},
                    "ciso": {"appointed": False},
                    "security_committee": {"established": False}
                },
                "operations": {
                    "procedures": {"documented": False},
                    "change_management": {"implemented": False},
                    "environment_separation": {"implemented": False}
                }
            }
        }
    
    def _collect_hr_training(self) -> Dict[str, Any]:
        """Collect HR and training data."""
        return {
            "hr": {
                "hr": {
                    "background_screening": {"mandatory": False},
                    "employment_terms": {"security_clauses": False}
                },
                "training": {
                    "security_awareness": {"regular": False},
                    "cybersecurity": {"annual": False},
                    "phishing_simulation": {"regular": False},
                    "awareness_metrics": {"tracked": False}
                }
            }
        }
    
    def _collect_incident_response(self) -> Dict[str, Any]:
        """Collect incident response data."""
        return {
            "plan": {"exists": False},
            "team": {"established": False},
            "rbi_reporting": {"within_2_hours": False},
            "forensics": {"capability": False}
        }
    
    def _collect_third_party(self) -> Dict[str, Any]:
        """Collect third party management data."""
        return {
            "risk_assessment": {"conducted": False},
            "continuous_monitoring": {"enabled": False},
            "audit_rights": {"established": False}
        }