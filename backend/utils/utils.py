"""
Training Utilities Module
=========================
Utility functions for ML training pipeline.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
import logging

from utils.helpers import safe_bool_convert, safe_int_convert, safe_float_convert
from utils.validators import ComplianceDataValidator

logger = logging.getLogger("ComplianceAI.Trainer.Utils")


def load_json_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """Load JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load {file_path}: {e}")
        return None


def save_json_file(data: Any, file_path: Path, indent: int = 2) -> bool:
    """Save data to JSON file."""
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, default=str)
        return True
    except Exception as e:
        logger.error(f"Failed to save {file_path}: {e}")
        return False


def extract_records_from_payload(payload: Any) -> List[Dict[str, Any]]:
    """
    Extract records from JSON payload.
    Supports multiple formats: single dict, list of dicts, or dict with 'records'/'data' key.
    """
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    
    if isinstance(payload, dict):
        # Check for common container keys
        for key in ['records', 'data', 'samples', 'items', 'dataset']:
            if isinstance(payload.get(key), list):
                return [r for r in payload.get(key, []) if isinstance(r, dict)]
        # Otherwise treat as single record
        return [payload]
    
    return []


def validate_compliance_record(record: Dict[str, Any]) -> bool:
    """Basic validation for compliance record."""
    if not isinstance(record, dict):
        return False
    
    # Check for basic required fields
    required_fields = ['company_name', 'company_type']
    return all(field in record for field in required_fields)


def safe_bool_to_int(val: Any) -> int:
    """Convert boolean/string to int safely."""
    return 1 if safe_bool_convert(val, False) else 0


def safe_numeric(val: Any, default: float = 0.0) -> float:
    """Convert to numeric safely."""
    return safe_float_convert(val, default)


class ProgressTracker:
    """Simple progress tracker for training."""
    
    def __init__(self, total: int, description: str = ""):
        self.total = total
        self.description = description
        self.current = 0
        self.logger = logging.getLogger("ComplianceAI.Trainer")
    
    def update(self, step: int = 1):
        """Update progress."""
        self.current += step
        if self.total > 0:
            percent = (self.current / self.total) * 100
            self.logger.info(
                f"{self.description}: {self.current}/{self.total} ({percent:.1f}%)"
            )
    
    def complete(self):
        """Mark as complete."""
        self.current = self.total
        self.logger.info(f"{self.description}: Complete ✓")

