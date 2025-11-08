# AuditEase Report Generator Module

Production-ready compliance report generation for ISO 27001, CIS Controls v8, and RBI Guidelines.

## Features

✅ **Comprehensive Analysis**
- Rule-by-rule compliance assessment
- Evidence extraction and root cause analysis
- CVE correlation and vulnerability mapping
- Historical trend and delta analysis

✅ **Multi-Format Outputs**
- **JSON**: Machine-readable detailed reports
- **Excel**: 20+ sheets with pivot-ready data, charts, and remediation playbooks
- **PDF**: 8+ pages with executive summary, technical appendix, and embedded visualizations

✅ **Rich Visualizations**
- Compliance heatmaps by framework and category
- Severity distribution charts
- Framework comparison bar charts
- Trend analysis time-series
- Risk matrices and donut charts

✅ **Detailed Remediation**
- Step-by-step remediation guidance
- Platform-specific commands (Windows, Linux, macOS)
- Effort and cost estimates
- Validation commands
- Compliance framework references

✅ **Enterprise-Grade**
- Bulletproof error handling
- Comprehensive logging
- Input validation
- Pytest test suite
- Production-ready code

## Installation

The module is already integrated into the AuditEase backend. No additional installation required.

### Dependencies

```bash
# Core dependencies (already in requirements.txt)
pandas>=2.0.0
openpyxl>=3.1.0
matplotlib>=3.7.0
seaborn>=0.12.0
plotly>=5.14.0
reportlab>=4.0.0
```

## Quick Start

### Method 1: Generate from JSON File

```python
from report_generator import generate_and_return_summary

result = generate_and_return_summary(
    input_json_path="reports/audit_results.json",
    output_dir="reports/generated"
)

print(f"Report ID: {result['run_id']}")
print(f"Excel: {result['files']['excel']}")
print(f"PDF: {result['files']['pdf']}")
```

### Method 2: Generate from Dictionary

```python
from report_generator import generate_comprehensive_report

snapshot = {
    "dashboard_summary": {...},
    "key_metrics": {...},
    "detailed_frameworks": {...}
}

result = generate_comprehensive_report(
    snapshot=snapshot,
    output_dir="reports/generated"
)
```

### Method 3: Using Class Interface

```python
from report_generator import ReportGenerator

generator = ReportGenerator(output_dir="reports/generated")
result = generator.generate_from_file("reports/audit_results.json")
```

## Module Structure

```
backend/report_generator/
├── __init__.py                  # Module exports
├── schema.py                    # Data structures and validation
├── integrated_generator.py      # Main generator (wraps existing services)
├── generator.py                 # Advanced generator with remediation DB
├── visuals.py                   # Chart and visualization generation
├── xlsx_writer.py               # Excel report writer
├── pdf_report.py                # PDF report generator
└── README.md                    # This file

backend/examples/
└── run_report.py                # Usage examples

backend/tests/
└── test_generator.py            # Pytest test suite
```

## API Reference

### Main Functions

#### `generate_and_return_summary(input_json_path, output_dir)`

Generate comprehensive reports from JSON file.

**Parameters:**
- `input_json_path` (str): Path to audit results JSON file
- `output_dir` (str): Directory to save generated reports

**Returns:**
```python
{
    "run_id": "report_20251108_120000_abc123",
    "summary": {
        "company_name": "Organization",
        "overall_score": 65.5,
        "risk_level": "MEDIUM",
        "total_rules": 150,
        "passed_rules": 98,
        "failed_rules": 52,
        "pass_rate": 65.33,
        "frameworks": [...],
        "top_gaps": [...]
    },
    "files": {
        "report_json": "path/to/report.json",
        "report_summary": "path/to/summary.json",
        "excel": "path/to/report.xlsx",
        "pdf": "path/to/report.pdf",
        "charts": ["path/to/chart1.png", ...]
    }
}
```

#### `generate_comprehensive_report(snapshot, output_dir, previous_snapshot=None)`

Generate reports from snapshot dictionary.

**Parameters:**
- `snapshot` (dict): Compliance snapshot data
- `output_dir` (str): Output directory
- `previous_snapshot` (dict, optional): Previous snapshot for trend analysis

**Returns:** Same structure as `generate_and_return_summary`

### Classes

#### `ReportGenerator`

Object-oriented interface for report generation.

```python
generator = ReportGenerator(output_dir="reports")

# Generate from dictionary
result = generator.generate(snapshot=data)

# Generate from file
result = generator.generate_from_file("audit.json")
```

### Enums

#### `RuleStatus`
- `MET`: Control requirement met
- `PARTIAL`: Partially compliant
- `UNMET`: Non-compliant
- `SKIPPED`: Not assessed
- `ERROR`: Assessment error

#### `Priority`
- `CRITICAL`: Immediate action required
- `HIGH`: High priority
- `MEDIUM`: Medium priority
- `LOW`: Low priority
- `INFO`: Informational

#### `Framework`
- `CIS`: CIS Controls v8
- `ISO27001`: ISO 27001
- `RBI`: RBI Guidelines
- `NIST`: NIST 800-53
- `PCI_DSS`: PCI DSS
- `HIPAA`: HIPAA
- `GDPR`: GDPR

## Input Data Format

The module expects audit data in the following structure:

```json
{
  "meta": {
    "version": "1.0.0",
    "generated_at": "2025-11-08T12:00:00Z"
  },
  "dashboard_summary": {
    "company": {
      "name": "Organization Name",
      "type": "Enterprise"
    },
    "overall_score": 65.5,
    "risk_level": "MEDIUM"
  },
  "key_metrics": {
    "total_rules_checked": 150,
    "rules_passed": 98,
    "rules_failed": 52
  },
  "framework_scores": [...],
  "detailed_frameworks": {
    "CIS": {
      "overall": {...},
      "critical_gaps": [...]
    }
  },
  "priority_issues": [...]
}
```

## Output Files

### JSON Report
- Complete machine-readable report
- All rule results with evidence
- Framework and category summaries
- Remediation guidance

### Excel Report (20+ Sheets)
1. **Executive Summary**: High-level overview
2. **Framework Analysis**: Per-framework breakdown
3. **All Rules**: Complete rule listing
4. **Remediation Strategies**: Detailed remediation for failed rules
5. **Risk Matrix**: Risk assessment matrix
6. **Timeline & Cost**: Implementation planning
7. **Category Breakdown**: Analysis by category
8. **Severity Distribution**: Issues by severity
9. **Evidence**: Supporting evidence
10. **Compliance References**: Framework mappings

### PDF Report (8+ Pages)
1. **Cover Page**: Title and metadata
2. **Executive Summary**: Non-technical overview
3. **Dashboard**: Key metrics and scores
4. **Risk Heatmap**: Visual risk assessment
5. **Framework Analysis**: Detailed framework scores
6. **Findings**: Critical gaps and issues
7. **Remediation**: Action items and guidance
8. **Technical Appendix**: Detailed technical data

## Testing

Run the test suite:

```bash
cd backend
pytest tests/test_generator.py -v
```

## Examples

See `backend/examples/run_report.py` for comprehensive usage examples:

```bash
cd backend
python examples/run_report.py
```

## Integration with Backend API

The module is integrated into the FastAPI backend. Reports are automatically generated when users click download buttons in the Reports tab.

### API Endpoints

- `GET /api/reports/download/pdf` - Download PDF report
- `GET /api/reports/download/json` - Download JSON report
- `GET /api/reports/enhanced/excel` - Download Excel report

## Troubleshooting

### No audit data found
**Error:** `No audit results available. Please run a scan first.`

**Solution:** Run a compliance scan from the Dashboard tab first.

### Import errors
**Error:** `ModuleNotFoundError: No module named 'report_generator'`

**Solution:** Ensure you're running from the `backend` directory and the module is in the Python path.

### Missing dependencies
**Error:** `ModuleNotFoundError: No module named 'pandas'`

**Solution:** Install dependencies:
```bash
pip install -r requirements.txt
```

## Version History

### v2.0.0 (2025-11-08)
- Integrated with existing comprehensive report services
- Added schema validation
- Enhanced visualization generation
- Production-ready error handling
- Comprehensive test suite

### v1.0.0 (Initial)
- Basic report generation
- JSON, Excel, PDF outputs

## License

Copyright © 2025 AuditEase Security Team. All rights reserved.

