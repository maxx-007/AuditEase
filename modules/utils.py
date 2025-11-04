"""
Compliance AI - Utility Functions
=================================
Shared utilities for logging, validation, JSON handling, and path management.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
import pandas as pd


def setup_logging(level: int = logging.INFO, log_file: Optional[Path] = None) -> logging.Logger:
    """
    Configure application-wide logging with consistent formatting.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for log output
    
    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("ComplianceAI")
    logger.setLevel(level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(console_formatter)
        logger.addHandler(file_handler)
    
    return logger


def validate_path(path: Union[str, Path], must_exist: bool = False) -> bool:
    """
    Validate a file or directory path.
    
    Args:
        path: Path to validate
        must_exist: If True, path must already exist
    
    Returns:
        True if path is valid, False otherwise
    """
    path = Path(path)
    
    if must_exist and not path.exists():
        return False
    
    return True


def create_directory_structure() -> None:
    """Create standard directory structure for Compliance AI."""
    directories = [
        Path("datasets"),
        Path("models"),
        Path("outputs"),
        Path("logs")
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


def load_json_file(file_path: Path) -> Optional[Any]:
    """
    Safely load a JSON file with error handling.
    
    Args:
        file_path: Path to JSON file
    
    Returns:
        Parsed JSON data or None if loading fails
    """
    logger = logging.getLogger("ComplianceAI")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {file_path.name}: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to load {file_path.name}: {e}")
        return None


def save_json_file(data: Any, file_path: Path, indent: int = 2) -> bool:
    """
    Safely save data to a JSON file.
    
    Args:
        data: Data to serialize
        file_path: Output file path
        indent: JSON indentation level
    
    Returns:
        True if successful, False otherwise
    """
    logger = logging.getLogger("ComplianceAI")
    
    try:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        return True
    except Exception as e:
        logger.error(f"Failed to save {file_path.name}: {e}")
        return False


def flatten_json(data: Dict[str, Any], parent_key: str = '', sep: str = '_') -> Dict[str, Any]:
    """
    Flatten nested JSON structure for ML compatibility.
    
    Args:
        data: Nested dictionary
        parent_key: Parent key for recursion
        sep: Separator for flattened keys
    
    Returns:
        Flattened dictionary
    """
    items = []
    
    for key, value in data.items():
        new_key = f"{parent_key}{sep}{key}" if parent_key else key
        
        if isinstance(value, dict):
            items.extend(flatten_json(value, new_key, sep=sep).items())
        elif isinstance(value, list):
            # Convert lists to their length or join strings
            if value and isinstance(value[0], dict):
                items.append((f"{new_key}_count", len(value)))
            elif value and isinstance(value[0], str):
                items.append((new_key, ','.join(value)))
            else:
                items.append((f"{new_key}_count", len(value)))
        else:
            items.append((new_key, value))
    
    return dict(items)


def extract_records_from_payload(payload: Any) -> List[Dict[str, Any]]:
    """
    Extract record list from various JSON payload structures.
    
    Supports:
    - Single record: {...}
    - List of records: [{...}, {...}]
    - Nested records: {"records": [...], "data": [...]}
    
    Args:
        payload: JSON payload
    
    Returns:
        List of record dictionaries
    """
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    
    if isinstance(payload, dict):
        # Check common nested keys
        for key in ['records', 'data', 'samples', 'items', 'dataset']:
            if isinstance(payload.get(key), list):
                return [r for r in payload[key] if isinstance(r, dict)]
        
        # Treat dict itself as single record
        return [payload]
    
    return []


def validate_compliance_record(record: Dict[str, Any]) -> bool:
    """
    Validate that a compliance record has minimum required fields.
    
    Args:
        record: Compliance data record
    
    Returns:
        True if valid, False otherwise
    """
    # Check for at least some compliance-related fields
    required_categories = [
        'network', 'antimalware', 'logging', 'backup',
        'access_control', 'vulnerability_management'
    ]
    
    found = sum(1 for cat in required_categories if cat in record)
    return found >= 2  # At least 2 categories present


def safe_bool_to_int(val: Any) -> int:
    """
    Convert boolean or string values to integer (0/1).
    
    Args:
        val: Value to convert
    
    Returns:
        1 for truthy values, 0 for falsy
    """
    if isinstance(val, bool):
        return 1 if val else 0
    if isinstance(val, str):
        return 1 if val.lower() in ['true', 'yes', 'enabled', 'deployed', 
                                      'implemented', 'compliant'] else 0
    if isinstance(val, (int, float)):
        return 1 if val > 0 else 0
    return 0


def safe_numeric(val: Any, default: float = 0.0) -> float:
    """
    Safely convert value to numeric type.
    
    Args:
        val: Value to convert
        default: Default value if conversion fails
    
    Returns:
        Numeric value or default
    """
    try:
        if val is None:
            return default
        if isinstance(val, (int, float)):
            return float(val)
        if isinstance(val, str):
            if val.lower() in ['null', 'none', '', 'n/a']:
                return default
            return float(val)
        return default
    except (ValueError, TypeError):
        return default


def timestamp_filename(base_name: str, extension: str = "json") -> str:
    """
    Generate timestamped filename.
    
    Args:
        base_name: Base name for file
        extension: File extension
    
    Returns:
        Timestamped filename
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{base_name}_{timestamp}.{extension}"


def calculate_file_hash(file_path: Path) -> str:
    """
    Calculate SHA256 hash of a file.
    
    Args:
        file_path: Path to file
    
    Returns:
        Hex string of file hash
    """
    import hashlib
    
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def dataframe_to_json_safe(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """
    Convert DataFrame to JSON-serializable format.
    
    Args:
        df: pandas DataFrame
    
    Returns:
        List of dictionaries
    """
    # Replace NaN with None for proper JSON serialization
    df_clean = df.where(pd.notna(df), None)
    return df_clean.to_dict('records')


class ProgressTracker:
    """Simple progress tracker for long-running operations."""
    
    def __init__(self, total: int, description: str = "Processing"):
        self.total = total
        self.current = 0
        self.description = description
        self.logger = logging.getLogger("ComplianceAI")
    
    def update(self, step: int = 1) -> None:
        """Update progress by step amount."""
        self.current += step
        percent = (self.current / self.total) * 100 if self.total > 0 else 0
        self.logger.info(f"{self.description}: {self.current}/{self.total} ({percent:.1f}%)")
    
    def complete(self) -> None:
        """Mark progress as complete."""
        self.logger.info(f"{self.description}: Complete ✓")


def get_nested_value(data: Dict[str, Any], path: str, default: Any = None) -> Any:
    """
    Get value from nested dictionary using dot notation.
    
    Args:
        data: Dictionary to search
        path: Dot-separated path (e.g., 'network.firewall.enabled')
        default: Default value if path not found
    
    Returns:
        Value at path or default
    """
    keys = path.split('.')
    value = data
    
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        else:
            return default
    
    return value if value is not None else default


def merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deep merge two dictionaries.
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary (takes precedence)
    
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dicts(result[key], value)
        else:
            result[key] = value
    
    return result