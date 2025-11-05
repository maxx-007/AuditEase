"""
Utility Helpers Module
=====================
Common helper functions used across the application.
"""

from typing import Dict, Any, Optional, Union
from pathlib import Path
from datetime import datetime
import hashlib
import json


def get_nested_value(
    data: Dict[str, Any], 
    path: str, 
    default: Any = None,
    separator: str = '.'
) -> Any:
    """
    Get value from nested dictionary using dot notation.
    
    Args:
        data: Dictionary to search
        path: Dot-separated path (e.g., 'network.firewall.enabled')
        default: Default value if path not found
        separator: Path separator character
    
    Returns:
        Value at path or default
    
    Examples:
        >>> data = {'network': {'firewall': {'enabled': True}}}
        >>> get_nested_value(data, 'network.firewall.enabled')
        True
        >>> get_nested_value(data, 'network.missing.field', default=False)
        False
    """
    if not path:
        return default
    
    keys = path.split(separator)
    value = data
    
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
            if value is None:
                return default
        else:
            return default
    
    return value if value is not None else default


def set_nested_value(
    data: Dict[str, Any],
    path: str,
    value: Any,
    separator: str = '.',
    create_missing: bool = True
) -> bool:
    """
    Set value in nested dictionary using dot notation.
    
    Args:
        data: Dictionary to modify
        path: Dot-separated path
        value: Value to set
        separator: Path separator character
        create_missing: Whether to create missing intermediate dictionaries
    
    Returns:
        True if successful
    
    Examples:
        >>> data = {}
        >>> set_nested_value(data, 'network.firewall.enabled', True)
        True
        >>> data
        {'network': {'firewall': {'enabled': True}}}
    """
    if not path:
        return False
    
    keys = path.split(separator)
    current = data
    
    # Navigate to parent
    for key in keys[:-1]:
        if key not in current:
            if create_missing:
                current[key] = {}
            else:
                return False
        current = current[key]
        
        if not isinstance(current, dict):
            return False
    
    # Set value
    current[keys[-1]] = value
    return True


def flatten_dict(
    data: Dict[str, Any],
    parent_key: str = '',
    separator: str = '_'
) -> Dict[str, Any]:
    """
    Flatten nested dictionary structure.
    
    Args:
        data: Nested dictionary
        parent_key: Parent key for recursion
        separator: Separator for flattened keys
    
    Returns:
        Flattened dictionary
    
    Examples:
        >>> data = {'a': {'b': {'c': 1}}, 'd': 2}
        >>> flatten_dict(data)
        {'a_b_c': 1, 'd': 2}
    """
    items = []
    
    for key, value in data.items():
        new_key = f"{parent_key}{separator}{key}" if parent_key else key
        
        if isinstance(value, dict):
            items.extend(flatten_dict(value, new_key, separator=separator).items())
        elif isinstance(value, list):
            # Handle lists
            if value and isinstance(value[0], dict):
                items.append((f"{new_key}_count", len(value)))
                # Optionally flatten first item
                if len(value) > 0:
                    items.extend(
                        flatten_dict(value[0], f"{new_key}_0", separator=separator).items()
                    )
            else:
                items.append((f"{new_key}_count", len(value)))
        else:
            items.append((new_key, value))
    
    return dict(items)


def unflatten_dict(
    data: Dict[str, Any],
    separator: str = '_'
) -> Dict[str, Any]:
    """
    Unflatten dictionary back to nested structure.
    
    Args:
        data: Flattened dictionary
        separator: Separator used in flattened keys
    
    Returns:
        Nested dictionary
    """
    result = {}
    
    for key, value in data.items():
        parts = key.split(separator)
        current = result
        
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        
        current[parts[-1]] = value
    
    return result


def calculate_risk_level(compliance_percentage: float) -> str:
    """
    Calculate risk level based on compliance percentage.
    
    Args:
        compliance_percentage: Compliance score (0-100)
    
    Returns:
        Risk level (CRITICAL/HIGH/MEDIUM/LOW/EXCELLENT)
    """
    if compliance_percentage >= 90:
        return "EXCELLENT"
    elif compliance_percentage >= 80:
        return "LOW"
    elif compliance_percentage >= 60:
        return "MEDIUM"
    elif compliance_percentage >= 40:
        return "HIGH"
    else:
        return "CRITICAL"


def calculate_file_hash(file_path: Path, algorithm: str = 'sha256') -> str:
    """
    Calculate hash of a file.
    
    Args:
        file_path: Path to file
        algorithm: Hash algorithm (md5, sha1, sha256)
    
    Returns:
        Hex string of file hash
    """
    hash_func = hashlib.new(algorithm)
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()


def ensure_directory(path: Union[str, Path]) -> Path:
    """
    Ensure directory exists, create if necessary.
    
    Args:
        path: Directory path
    
    Returns:
        Path object
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def timestamp_filename(
    base_name: str,
    extension: str = 'json',
    include_date: bool = True,
    include_time: bool = True
) -> str:
    """
    Generate timestamped filename.
    
    Args:
        base_name: Base name for file
        extension: File extension (without dot)
        include_date: Include date in timestamp
        include_time: Include time in timestamp
    
    Returns:
        Timestamped filename
    
    Examples:
        >>> timestamp_filename('report', 'pdf')
        'report_20250115_103045.pdf'
        >>> timestamp_filename('audit', 'json', include_time=False)
        'audit_20250115.json'
    """
    timestamp_parts = []
    
    if include_date:
        timestamp_parts.append(datetime.now().strftime("%Y%m%d"))
    
    if include_time:
        timestamp_parts.append(datetime.now().strftime("%H%M%S"))
    
    timestamp = "_".join(timestamp_parts)
    
    return f"{base_name}_{timestamp}.{extension}"


def format_bytes(size: int) -> str:
    """
    Format bytes to human-readable string.
    
    Args:
        size: Size in bytes
    
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.
    
    Args:
        seconds: Duration in seconds
    
    Returns:
        Formatted string (e.g., "2h 30m 15s")
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    
    minutes = seconds / 60
    if minutes < 60:
        return f"{int(minutes)}m {int(seconds % 60)}s"
    
    hours = minutes / 60
    minutes = minutes % 60
    return f"{int(hours)}h {int(minutes)}m"


def safe_bool_convert(value: Any, default: bool = False) -> bool:
    """
    Safely convert value to boolean.
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
    
    Returns:
        Boolean value
    """
    if isinstance(value, bool):
        return value
    
    if isinstance(value, str):
        return value.lower() in ['true', 'yes', 'enabled', 'deployed', 
                                  'implemented', 'compliant', '1', 'on']
    
    if isinstance(value, (int, float)):
        return value > 0
    
    if isinstance(value, dict):
        # Check common boolean indicator fields
        for key in ['enabled', 'deployed', 'implemented', 'exists']:
            if key in value:
                return safe_bool_convert(value[key], default)
    
    return default


def safe_int_convert(value: Any, default: int = 0) -> int:
    """
    Safely convert value to integer.
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
    
    Returns:
        Integer value
    """
    try:
        if value is None:
            return default
        
        if isinstance(value, bool):
            return 1 if value else 0
        
        if isinstance(value, str):
            if value.lower() in ['null', 'none', '', 'n/a']:
                return default
            return int(float(value))
        
        return int(value)
    except (ValueError, TypeError):
        return default


def safe_float_convert(value: Any, default: float = 0.0) -> float:
    """
    Safely convert value to float.
    
    Args:
        value: Value to convert
        default: Default value if conversion fails
    
    Returns:
        Float value
    """
    try:
        if value is None:
            return default
        
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        
        if isinstance(value, str):
            if value.lower() in ['null', 'none', '', 'n/a']:
                return default
            return float(value)
        
        return float(value)
    except (ValueError, TypeError):
        return default


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


def chunk_list(lst: list, chunk_size: int) -> list:
    """
    Split list into chunks.
    
    Args:
        lst: List to split
        chunk_size: Size of each chunk
    
    Returns:
        List of chunks
    """
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]


def deduplicate_list(lst: list, key: Optional[str] = None) -> list:
    """
    Remove duplicates from list while preserving order.
    
    Args:
        lst: List to deduplicate
        key: Optional key function for dict comparison
    
    Returns:
        Deduplicated list
    """
    if not lst:
        return []
    
    seen = set()
    result = []
    
    for item in lst:
        if key and isinstance(item, dict):
            item_key = item.get(key)
            if item_key not in seen:
                seen.add(item_key)
                result.append(item)
        else:
            # For hashable items
            try:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            except TypeError:
                # For unhashable items (like dicts), use JSON serialization
                item_str = json.dumps(item, sort_keys=True)
                if item_str not in seen:
                    seen.add(item_str)
                    result.append(item)
    
    return result


def truncate_string(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate string to maximum length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
    
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def sanitize_filename(filename: str, replacement: str = '_') -> str:
    """
    Sanitize filename by removing invalid characters.
    
    Args:
        filename: Filename to sanitize
        replacement: Replacement character for invalid chars
    
    Returns:
        Sanitized filename
    """
    invalid_chars = '<>:"/\\|?*'
    
    for char in invalid_chars:
        filename = filename.replace(char, replacement)
    
    return filename


def compare_versions(version1: str, version2: str) -> int:
    """
    Compare two version strings.
    
    Args:
        version1: First version (e.g., "1.2.3")
        version2: Second version (e.g., "1.3.0")
    
    Returns:
        -1 if version1 < version2
        0 if version1 == version2
        1 if version1 > version2
    """
    v1_parts = [int(x) for x in version1.split('.')]
    v2_parts = [int(x) for x in version2.split('.')]
    
    # Pad shorter version with zeros
    max_len = max(len(v1_parts), len(v2_parts))
    v1_parts.extend([0] * (max_len - len(v1_parts)))
    v2_parts.extend([0] * (max_len - len(v2_parts)))
    
    for v1, v2 in zip(v1_parts, v2_parts):
        if v1 < v2:
            return -1
        elif v1 > v2:
            return 1
    
    return 0


class ProgressBar:
    """Simple console progress bar."""
    
    def __init__(self, total: int, prefix: str = '', width: int = 50):
        """
        Initialize progress bar.
        
        Args:
            total: Total number of items
            prefix: Prefix text
            width: Width of progress bar
        """
        self.total = total
        self.prefix = prefix
        self.width = width
        self.current = 0
    
    def update(self, step: int = 1):
        """Update progress by step amount."""
        self.current += step
        self._print()
    
    def _print(self):
        """Print progress bar."""
        percent = self.current / self.total if self.total > 0 else 0
        filled = int(self.width * percent)
        bar = '█' * filled + '░' * (self.width - filled)
        
        print(f'\r{self.prefix} |{bar}| {percent*100:.1f}% ({self.current}/{self.total})', end='')
        
        if self.current >= self.total:
            print()  # New line when complete
    
    def complete(self):
        """Mark as complete."""
        self.current = self.total
        self._print()