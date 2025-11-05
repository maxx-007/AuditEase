"""
Core Validator Module
=====================
Validates compliance data against defined schemas and business rules.
"""

from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import json
import yaml
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger("validator")


class ComplianceDataValidator:
    """Validates compliance data structure and content."""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize validator with configuration."""
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        
        self.required_fields = self._load_required_fields()
        self.validation_rules = self._load_validation_rules()
    
    def _load_required_fields(self) -> Dict[str, List[str]]:
        """Load required fields for different data types."""
        return {
            "compliance_record": [
                "company_name",
                "company_type",
                "evaluation_date",
                "network",
                "endpoint_security",
                "access_control",
                "logging"
            ],
            "training_data": [
                "company_name",
                "company_type",
                "compliance_status",
                "compliance_score"
            ]
        }
    
    def _load_validation_rules(self) -> Dict[str, Any]:
        """Load validation rules."""
        return {
            "company_name": {
                "type": str,
                "min_length": 3,
                "max_length": 100
            },
            "company_type": {
                "type": str,
                "allowed_values": [
                    "Bank",
                    "NBFC",
                    "Insurance",
                    "Financial Services",
                    "Fintech",
                    "Payment Service Provider"
                ]
            },
            "compliance_status": {
                "type": str,
                "allowed_values": ["Compliant", "Non-Compliant", "Partial"]
            },
            "compliance_score": {
                "type": (int, float),
                "min_value": 0,
                "max_value": 100
            },
            "evaluation_date": {
                "type": str,
                "format": "date"
            }
        }
    
    def validate_structure(
        self, 
        data: Dict[str, Any], 
        data_type: str = "compliance_record"
    ) -> Tuple[bool, List[str]]:
        """
        Validate data structure.
        
        Args:
            data: Data to validate
            data_type: Type of data (compliance_record or training_data)
        
        Returns:
            Tuple of (is_valid, list of errors)
        """
        errors = []
        
        # Check required fields
        required = self.required_fields.get(data_type, [])
        for field in required:
            if field not in data or data[field] is None:
                errors.append(f"Missing required field: {field}")
        
        return len(errors) == 0, errors
    
    def validate_content(
        self, 
        data: Dict[str, Any]
    ) -> Tuple[bool, List[str]]:
        """
        Validate data content against rules.
        
        Args:
            data: Data to validate
        
        Returns:
            Tuple of (is_valid, list of errors)
        """
        errors = []
        
        for field, rules in self.validation_rules.items():
            if field not in data:
                continue
            
            value = data[field]
            
            # Type validation
            expected_type = rules.get("type")
            if expected_type and not isinstance(value, expected_type):
                errors.append(
                    f"Field '{field}' has invalid type. "
                    f"Expected {expected_type}, got {type(value)}"
                )
                continue
            
            # String length validation
            if isinstance(value, str):
                min_len = rules.get("min_length")
                max_len = rules.get("max_length")
                
                if min_len and len(value) < min_len:
                    errors.append(
                        f"Field '{field}' is too short. "
                        f"Minimum length: {min_len}"
                    )
                
                if max_len and len(value) > max_len:
                    errors.append(
                        f"Field '{field}' is too long. "
                        f"Maximum length: {max_len}"
                    )
            
            # Numeric range validation
            if isinstance(value, (int, float)):
                min_val = rules.get("min_value")
                max_val = rules.get("max_value")
                
                if min_val is not None and value < min_val:
                    errors.append(
                        f"Field '{field}' is below minimum value. "
                        f"Minimum: {min_val}"
                    )
                
                if max_val is not None and value > max_val:
                    errors.append(
                        f"Field '{field}' exceeds maximum value. "
                        f"Maximum: {max_val}"
                    )
            
            # Allowed values validation
            allowed_values = rules.get("allowed_values")
            if allowed_values and value not in allowed_values:
                errors.append(
                    f"Field '{field}' has invalid value. "
                    f"Allowed values: {allowed_values}"
                )
            
            # Date format validation
            if rules.get("format") == "date":
                try:
                    datetime.strptime(value, "%Y-%m-%d")
                except ValueError:
                    errors.append(
                        f"Field '{field}' has invalid date format. "
                        f"Expected: YYYY-MM-DD"
                    )
        
        return len(errors) == 0, errors
    
    def validate_nested_structure(
        self, 
        data: Dict[str, Any]
    ) -> Tuple[bool, List[str]]:
        """
        Validate nested compliance data structure.
        
        Args:
            data: Data to validate
        
        Returns:
            Tuple of (is_valid, list of errors)
        """
        errors = []
        
        # Define expected nested structures
        expected_structures = {
            "network": ["network_security", "perimeter"],
            "endpoint_security": ["edr", "encryption", "antimalware"],
            "access_control": ["access_control", "users", "systems"],
            "logging": ["logging", "siem", "security_monitoring"]
        }
        
        for parent, children in expected_structures.items():
            if parent not in data:
                continue
            
            parent_data = data[parent]
            if not isinstance(parent_data, dict):
                errors.append(
                    f"Field '{parent}' should be a dictionary"
                )
                continue
            
            # Check for at least some expected child fields
            found_children = sum(
                1 for child in children 
                if child in parent_data
            )
            
            if found_children == 0:
                errors.append(
                    f"Field '{parent}' is missing all expected child fields: "
                    f"{children}"
                )
        
        return len(errors) == 0, errors
    
    def validate_compliance_record(
        self, 
        data: Dict[str, Any]
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Comprehensive validation for compliance records.
        
        Args:
            data: Compliance record to validate
        
        Returns:
            Tuple of (is_valid, validation_report)
        """
        validation_report = {
            "is_valid": True,
            "timestamp": datetime.now().isoformat(),
            "errors": [],
            "warnings": [],
            "data_quality_score": 100.0
        }
        
        # Structure validation
        structure_valid, structure_errors = self.validate_structure(
            data, "compliance_record"
        )
        if not structure_valid:
            validation_report["errors"].extend(structure_errors)
        
        # Content validation
        content_valid, content_errors = self.validate_content(data)
        if not content_valid:
            validation_report["errors"].extend(content_errors)
        
        # Nested structure validation
        nested_valid, nested_errors = self.validate_nested_structure(data)
        if not nested_valid:
            validation_report["warnings"].extend(nested_errors)
        
        # Calculate data quality score
        total_checks = len(structure_errors) + len(content_errors) + len(nested_errors)
        if total_checks > 0:
            validation_report["data_quality_score"] = max(
                0, 
                100 - (len(validation_report["errors"]) * 10) - 
                (len(validation_report["warnings"]) * 5)
            )
        
        validation_report["is_valid"] = len(validation_report["errors"]) == 0
        
        if validation_report["is_valid"]:
            logger.info(
                f"✓ Validation passed for {data.get('company_name', 'Unknown')} "
                f"(Quality score: {validation_report['data_quality_score']:.1f})"
            )
        else:
            logger.error(
                f"✗ Validation failed for {data.get('company_name', 'Unknown')}. "
                f"Errors: {len(validation_report['errors'])}"
            )
        
        return validation_report["is_valid"], validation_report
    
    def validate_training_dataset(
        self, 
        dataset: List[Dict[str, Any]]
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate entire training dataset.
        
        Args:
            dataset: List of training records
        
        Returns:
            Tuple of (is_valid, validation_report)
        """
        validation_report = {
            "is_valid": True,
            "timestamp": datetime.now().isoformat(),
            "total_records": len(dataset),
            "valid_records": 0,
            "invalid_records": 0,
            "errors_by_record": {},
            "overall_quality_score": 100.0
        }
        
        quality_scores = []
        
        for idx, record in enumerate(dataset):
            structure_valid, structure_errors = self.validate_structure(
                record, "training_data"
            )
            content_valid, content_errors = self.validate_content(record)
            
            errors = structure_errors + content_errors
            
            if errors:
                validation_report["invalid_records"] += 1
                validation_report["errors_by_record"][idx] = errors
            else:
                validation_report["valid_records"] += 1
            
            # Calculate quality score for this record
            record_score = max(0, 100 - (len(errors) * 10))
            quality_scores.append(record_score)
        
        # Calculate overall quality score
        if quality_scores:
            validation_report["overall_quality_score"] = sum(quality_scores) / len(quality_scores)
        
        validation_report["is_valid"] = validation_report["invalid_records"] == 0
        
        logger.info(
            f"Dataset validation: {validation_report['valid_records']}/{validation_report['total_records']} "
            f"records valid (Quality: {validation_report['overall_quality_score']:.1f})"
        )
        
        return validation_report["is_valid"], validation_report