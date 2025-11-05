"""
Compliance AI - Automated Setup Script
======================================
Sets up the entire project structure and generates sample configurations.
"""

import os
import json
from pathlib import Path
import shutil

def create_directory_structure():
    """Create complete directory structure."""
    directories = [
        "core",
        "services",
        "utils",
        "models",
        "data/synthetic",
        "data/collected",
        "data/validated",
        "reports/json",
        "reports/pdf",
        "reports/excel",
        "reports/charts",
        "config/frameworks",
        "config/rules",
        "config/remediation",
        "logs",
        "tests"
    ]
    
    print("📁 Creating directory structure...")
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        # Create __init__.py for Python packages
        if directory in ["core", "services", "utils", "tests"]:
            (Path(directory) / "__init__.py").touch()
    
    print("✓ Directory structure created")


def create_sample_framework_iso27001():
    """Create sample ISO 27001 framework rules."""
    iso27001_rules = [
        {
            "id": "ISO-A.5.1.1",
            "description": "Policies for information security",
            "category": "Information Security Policies",
            "field": "operations.policies.information_security.exists",
            "operator": "==",
            "expected_value": True,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Develop and document comprehensive information security policies approved by management.",
            "references": ["ISO/IEC 27001:2013 - A.5.1.1"]
        },
        {
            "id": "ISO-A.6.1.1",
            "description": "Information security roles and responsibilities",
            "category": "Organization of Information Security",
            "field": "operations.organization.roles_responsibilities.defined",
            "operator": "==",
            "expected_value": True,
            "weight": 7,
            "severity": "HIGH",
            "remediation": "Define and document all information security roles and responsibilities.",
            "references": ["ISO/IEC 27001:2013 - A.6.1.1"]
        },
        {
            "id": "ISO-A.9.1.1",
            "description": "Access control policy",
            "category": "Access Control",
            "field": "access_control.access_control.policy.exists",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Establish, document and review access control policy based on business and information security requirements.",
            "references": ["ISO/IEC 27001:2013 - A.9.1.1"]
        },
        {
            "id": "ISO-A.9.2.1",
            "description": "User registration and de-registration",
            "category": "Access Control",
            "field": "access_control.users.registration_process.formal",
            "operator": "==",
            "expected_value": True,
            "weight": 6,
            "severity": "MEDIUM",
            "remediation": "Implement formal user registration and de-registration process for granting and revoking access.",
            "references": ["ISO/IEC 27001:2013 - A.9.2.1"]
        },
        {
            "id": "ISO-A.9.2.4",
            "description": "Management of secret authentication information",
            "category": "Access Control",
            "field": "access_control.authentication.secret_management.secure",
            "operator": "==",
            "expected_value": True,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Implement secure processes for managing user secret authentication information (passwords, keys, tokens).",
            "references": ["ISO/IEC 27001:2013 - A.9.2.4"]
        },
        {
            "id": "ISO-A.9.4.1",
            "description": "Information access restriction",
            "category": "Access Control",
            "field": "access_control.systems.access_restriction.implemented",
            "operator": "==",
            "expected_value": True,
            "weight": 7,
            "severity": "HIGH",
            "remediation": "Restrict access to information and application system functions in accordance with access control policy.",
            "references": ["ISO/IEC 27001:2013 - A.9.4.1"]
        },
        {
            "id": "ISO-A.10.1.1",
            "description": "Policy on the use of cryptographic controls",
            "category": "Cryptography",
            "field": "cryptography.cryptography.policy.exists",
            "operator": "==",
            "expected_value": True,
            "weight": 7,
            "severity": "HIGH",
            "remediation": "Develop and implement policy on the use of cryptographic controls for protection of information.",
            "references": ["ISO/IEC 27001:2013 - A.10.1.1"]
        },
        {
            "id": "ISO-A.10.1.2",
            "description": "Key management",
            "category": "Cryptography",
            "field": "cryptography.cryptography.key_management.implemented",
            "operator": "==",
            "expected_value": True,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Implement policy on the use, protection and lifetime of cryptographic keys through their whole lifecycle.",
            "references": ["ISO/IEC 27001:2013 - A.10.1.2"]
        },
        {
            "id": "ISO-A.12.3.1",
            "description": "Information backup",
            "category": "Operations Security",
            "field": "backup.backup.automated.enabled",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Implement backup copies of information, software and system images shall be taken and tested regularly.",
            "references": ["ISO/IEC 27001:2013 - A.12.3.1"]
        },
        {
            "id": "ISO-A.12.4.1",
            "description": "Event logging",
            "category": "Operations Security",
            "field": "logging.logging.audit.enabled",
            "operator": "==",
            "expected_value": True,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Event logs recording user activities, exceptions, faults and information security events shall be produced, kept and regularly reviewed.",
            "references": ["ISO/IEC 27001:2013 - A.12.4.1"]
        },
        {
            "id": "ISO-A.12.6.1",
            "description": "Management of technical vulnerabilities",
            "category": "Operations Security",
            "field": "vulnerability_management.automated_scanning.enabled",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Obtain timely information about technical vulnerabilities, evaluate exposure, and take appropriate measures.",
            "references": ["ISO/IEC 27001:2013 - A.12.6.1"]
        },
        {
            "id": "ISO-A.13.1.1",
            "description": "Network controls",
            "category": "Communications Security",
            "field": "network.network.perimeter.filtering_configured",
            "operator": "==",
            "expected_value": True,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Implement controls to ensure security of information in networks and protection of connected services.",
            "references": ["ISO/IEC 27001:2013 - A.13.1.1"]
        },
        {
            "id": "ISO-A.14.2.1",
            "description": "Secure development policy",
            "category": "System Acquisition, Development and Maintenance",
            "field": "application_security.sdlc.implemented",
            "operator": "==",
            "expected_value": True,
            "weight": 7,
            "severity": "MEDIUM",
            "remediation": "Rules for the development of software and systems shall be established and applied.",
            "references": ["ISO/IEC 27001:2013 - A.14.2.1"]
        },
        {
            "id": "ISO-A.16.1.1",
            "description": "Responsibilities and procedures",
            "category": "Incident Management",
            "field": "plan.exists",
            "operator": "==",
            "expected_value": True,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Establish management responsibilities and procedures to ensure quick, effective and orderly response to information security incidents.",
            "references": ["ISO/IEC 27001:2013 - A.16.1.1"]
        },
        {
            "id": "ISO-A.17.1.1",
            "description": "Planning information security continuity",
            "category": "Business Continuity Management",
            "field": "backup.business_continuity.plan.exists",
            "operator": "==",
            "expected_value": True,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Determine requirements for information security and continuity of information security management.",
            "references": ["ISO/IEC 27001:2013 - A.17.1.1"]
        }
    ]
    
    output_path = Path("config/frameworks/iso27001.json")
    with open(output_path, 'w') as f:
        json.dump(iso27001_rules, f, indent=2)
    
    print(f"✓ Created ISO 27001 framework: {len(iso27001_rules)} rules")
    return output_path


def create_sample_framework_cis():
    """Create sample CIS Controls framework rules."""
    cis_rules = [
        {
            "id": "CIS-1.1",
            "description": "Establish and Maintain Detailed Enterprise Asset Inventory",
            "category": "Asset Management",
            "field": "assets.assets.inventory.maintained",
            "operator": "==",
            "expected_value": True,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Establish and maintain accurate, detailed, and up-to-date inventory of all enterprise assets.",
            "references": ["CIS Controls v8 - 1.1"]
        },
        {
            "id": "CIS-2.1",
            "description": "Establish and Maintain Software Inventory",
            "category": "Asset Management",
            "field": "software_inventory.maintained",
            "operator": "==",
            "expected_value": True,
            "weight": 7,
            "severity": "HIGH",
            "remediation": "Establish and maintain detailed inventory of all authorized software.",
            "references": ["CIS Controls v8 - 2.1"]
        },
        {
            "id": "CIS-4.1",
            "description": "Establish and Maintain Secure Configuration Process",
            "category": "Secure Configuration",
            "field": "secure_configuration.applied",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Establish and maintain secure configuration process for enterprise assets and software.",
            "references": ["CIS Controls v8 - 4.1"]
        },
        {
            "id": "CIS-5.1",
            "description": "Establish and Maintain Account Management Process",
            "category": "Account Management",
            "field": "access_control.users.registration_process.formal",
            "operator": "==",
            "expected_value": True,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Establish and maintain account management process including creation, enabling, modification, disabling, and removal.",
            "references": ["CIS Controls v8 - 5.1"]
        },
        {
            "id": "CIS-6.1",
            "description": "Establish Access Control Management Process",
            "category": "Access Control",
            "field": "access_control.access_control.policy.exists",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Establish and maintain access control management process for enterprise assets and software.",
            "references": ["CIS Controls v8 - 6.1"]
        },
        {
            "id": "CIS-7.1",
            "description": "Establish and Maintain Vulnerability Management Process",
            "category": "Vulnerability Management",
            "field": "vulnerability_management.automated_scanning.enabled",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Establish and maintain vulnerability management process to find, prioritize, remediate, and validate.",
            "references": ["CIS Controls v8 - 7.1"]
        },
        {
            "id": "CIS-8.1",
            "description": "Establish and Maintain Audit Log Management Process",
            "category": "Audit Log Management",
            "field": "logging.logging.central_management.enabled",
            "operator": "==",
            "expected_value": True,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Establish and maintain audit log management process that defines retention, review, and response.",
            "references": ["CIS Controls v8 - 8.1"]
        },
        {
            "id": "CIS-10.1",
            "description": "Deploy and Maintain Anti-Malware Software",
            "category": "Malware Defenses",
            "field": "antimalware.deployed",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Deploy and maintain anti-malware software on all enterprise assets.",
            "references": ["CIS Controls v8 - 10.1"]
        },
        {
            "id": "CIS-11.1",
            "description": "Establish and Maintain Data Recovery Process",
            "category": "Data Recovery",
            "field": "backup.backup.automated.enabled",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Establish and maintain data recovery process including backup, restoration, and security.",
            "references": ["CIS Controls v8 - 11.1"]
        },
        {
            "id": "CIS-13.1",
            "description": "Centralize Security Event Alerting",
            "category": "Security Monitoring",
            "field": "logging.siem.deployed",
            "operator": "==",
            "expected_value": True,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Aggregate security event logs from enterprise assets to centralized system for analysis and response.",
            "references": ["CIS Controls v8 - 13.1"]
        }
    ]
    
    output_path = Path("config/frameworks/cis.json")
    with open(output_path, 'w') as f:
        json.dump(cis_rules, f, indent=2)
    
    print(f"✓ Created CIS Controls framework: {len(cis_rules)} rules")
    return output_path


def create_sample_framework_rbi():
    """Create sample RBI Guidelines framework rules."""
    rbi_rules = [
        {
            "id": "RBI-2.1",
            "description": "Information Security Governance",
            "category": "Governance",
            "field": "operations.governance.board_approved_policy.exists",
            "operator": "==",
            "expected_value": True,
            "weight": 10,
            "severity": "CRITICAL",
            "remediation": "Establish information security governance with board-approved policies and CISO appointment.",
            "references": ["RBI Guidelines on Information Security, Electronic Banking, Technology Risk Management"]
        },
        {
            "id": "RBI-2.2",
            "description": "Appointment of CISO",
            "category": "Governance",
            "field": "operations.governance.ciso.appointed",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Appoint a Chief Information Security Officer (CISO) responsible for information security.",
            "references": ["RBI Guidelines on Information Security"]
        },
        {
            "id": "RBI-3.1",
            "description": "Cyber Crisis Management Plan",
            "category": "Incident Management",
            "field": "plan.exists",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Establish comprehensive Cyber Crisis Management Plan (CCMP) with incident response procedures.",
            "references": ["RBI Cyber Security Framework"]
        },
        {
            "id": "RBI-3.2",
            "description": "Incident Reporting to RBI",
            "category": "Incident Management",
            "field": "rbi_reporting.within_2_hours",
            "operator": "==",
            "expected_value": True,
            "weight": 10,
            "severity": "CRITICAL",
            "remediation": "Report cyber security incidents to RBI within 2-6 hours of detection as per guidelines.",
            "references": ["RBI Cyber Security Framework"]
        },
        {
            "id": "RBI-4.1",
            "description": "Customer Data Protection",
            "category": "Data Protection",
            "field": "cryptography.data_protection.customer_data.encrypted_at_rest",
            "operator": "==",
            "expected_value": True,
            "weight": 10,
            "severity": "CRITICAL",
            "remediation": "Ensure customer data is encrypted at rest and in transit with strong cryptographic controls.",
            "references": ["RBI Guidelines on Data Security"]
        },
        {
            "id": "RBI-5.1",
            "description": "Vulnerability Assessment and Penetration Testing",
            "category": "Vulnerability Management",
            "field": "vulnerability_management.penetration_test.last_days",
            "operator": "<=",
            "expected_value": 180,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Conduct Vulnerability Assessment and Penetration Testing (VAPT) at least twice a year.",
            "references": ["RBI Cyber Security Framework"]
        },
        {
            "id": "RBI-6.1",
            "description": "Patch Management",
            "category": "Patch Management",
            "field": "patch_management.automated_patching.enabled",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Implement robust patch management process with timely application of critical security patches.",
            "references": ["RBI Guidelines on IT Governance"]
        },
        {
            "id": "RBI-7.1",
            "description": "Security Awareness Training",
            "category": "Training",
            "field": "hr.training.security_awareness.regular",
            "operator": "==",
            "expected_value": True,
            "weight": 7,
            "severity": "MEDIUM",
            "remediation": "Conduct regular security awareness training for all employees including phishing simulations.",
            "references": ["RBI Guidelines on Information Security"]
        },
        {
            "id": "RBI-8.1",
            "description": "Third Party Risk Management",
            "category": "Third Party Management",
            "field": "risk_assessment.conducted",
            "operator": "==",
            "expected_value": True,
            "weight": 8,
            "severity": "HIGH",
            "remediation": "Conduct comprehensive risk assessment for all third-party service providers.",
            "references": ["RBI Guidelines on Managing Risks and Code of Conduct in Outsourcing"]
        },
        {
            "id": "RBI-9.1",
            "description": "Business Continuity and Disaster Recovery",
            "category": "Business Continuity",
            "field": "backup.business_continuity.disaster_recovery.plan_exists",
            "operator": "==",
            "expected_value": True,
            "weight": 9,
            "severity": "CRITICAL",
            "remediation": "Establish and test Business Continuity Plan (BCP) and Disaster Recovery Plan (DRP) regularly.",
            "references": ["RBI Guidelines on Business Continuity Planning"]
        }
    ]
    
    output_path = Path("config/frameworks/rbi.json")
    with open(output_path, 'w') as f:
        json.dump(rbi_rules, f, indent=2)
    
    print(f"✓ Created RBI Guidelines framework: {len(rbi_rules)} rules")
    return output_path


def create_sample_dataset():
    """Create a small sample synthetic dataset."""
    # Use the provided sample from the uploaded file
    sample_file = Path("synthetic_json_dataset.json")
    
    if sample_file.exists():
        print("✓ Found existing synthetic dataset")
        # Copy to data directory
        target = Path("data/synthetic/sample_bfsi_dataset.json")
        shutil.copy(sample_file, target)
        print(f"✓ Copied to {target}")
    else:
        print("ℹ️  No sample dataset found. Use your own synthetic data in data/synthetic/")


def create_requirements():
    """Create requirements.txt file."""
    requirements = """# Core Dependencies
pandas>=2.0.0
numpy>=1.24.0
scikit-learn>=1.3.0
joblib>=1.3.0

# Data Processing
pyyaml>=6.0
python-dotenv>=1.0.0

# ML & Analytics
xgboost>=2.0.0

# Visualization
matplotlib>=3.7.0
seaborn>=0.12.0
plotly>=5.14.0

# Reporting
reportlab>=4.0.0
openpyxl>=3.1.0
xlsxwriter>=3.1.0

# API (Optional)
fastapi>=0.100.0
uvicorn>=0.23.0
pydantic>=2.0.0

# Utilities
tqdm>=4.65.0
colorlog>=6.7.0
"""
    
    with open("requirements.txt", 'w') as f:
        f.write(requirements)
    
    print("✓ Created requirements.txt")


def create_config():
    """Create config.yaml file."""
    config = """# Compliance AI - Configuration File
# ===================================

project:
  name: "Compliance AI Engine"
  version: "1.0.0"
  environment: "production"

paths:
  data_dir: "data"
  models_dir: "models"
  reports_dir: "reports"
  logs_dir: "logs"
  config_dir: "config"

ml:
  train:
    test_size: 0.2
    random_state: 42
    cv_folds: 5
    algorithms:
      - "RandomForest"
      - "GradientBoosting"
  
  inference:
    batch_size: 32
    confidence_threshold: 0.75

audit:
  frameworks:
    - "ISO27001"
    - "RBI"
    - "CIS"
  
  scoring:
    weights:
      critical: 10
      high: 7
      medium: 5
      low: 3
  
  thresholds:
    compliant: 85
    partial: 60
    non_compliant: 0

reporting:
  formats:
    - "json"
    - "pdf"
    - "excel"
  
  charts:
    - "heatmap"
    - "radar"
    - "bar"
    - "trend"
  
  retention_days: 90

logging:
  level: "INFO"
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  max_bytes: 10485760  # 10MB
  backup_count: 5

api:
  host: "0.0.0.0"
  port: 8000
  cors_origins:
    - "http://localhost:3000"
    - "http://localhost:5173"
"""
    
    with open("config.yaml", 'w') as f:
        f.write(config)
    
    print("✓ Created config.yaml")


def create_gitignore():
    """Create .gitignore file."""
    gitignore = """# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# ML Models
models/*.joblib
models/*.pkl

# Data
data/collected/*.json
data/validated/*.json

# Reports
reports/**/*.pdf
reports/**/*.xlsx
reports/**/*.png

# Logs
logs/*.log

# Environment
.env
.venv
*.local

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db
"""
    
    with open(".gitignore", 'w') as f:
        f.write(gitignore)
    
    print("✓ Created .gitignore")


def main():
    """Main setup function."""
    print("\n" + "="*70)
    print("🚀 Compliance AI - Automated Setup")
    print("="*70 + "\n")
    
    # Create structure
    create_directory_structure()
    
    # Create configuration files
    create_config()
    create_requirements()
    create_gitignore()
    
    # Create framework rules
    print("\n📋 Creating compliance framework rules...")
    create_sample_framework_iso27001()
    create_sample_framework_cis()
    create_sample_framework_rbi()
    
    # Copy sample dataset
    print("\n📊 Setting up sample dataset...")
    create_sample_dataset()
    
    print("\n" + "="*70)
    print("✅ Setup Complete!")
    print("="*70)
    print("\n📝 Next Steps:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Copy your code files to their respective directories:")
    print("   - core/collector.py")
    print("   - core/validator.py")
    print("   - services/ml_service.py")
    print("   - services/audit_service.py")
    print("   - services/report_service.py")
    print("   - utils/logger.py")
    print("   - main.py")
    print("\n3. Train a model:")
    print("   python main.py train --dataset data/synthetic/sample_bfsi_dataset.json")
    print("\n4. Run audit:")
    print("   python main.py collect")
    print("   python main.py audit --input data/collected/snapshot_*.json")
    print("\n5. Start API server:")
    print("   python main.py serve --port 8000")
    print("\n" + "="*70 + "\n")


if __name__ == "__main__":
    main()