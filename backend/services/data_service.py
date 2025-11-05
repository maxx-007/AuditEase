"""
Data Service Module
==================
Manages data loading, saving, transformation, and dataset operations.
"""

from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import json
import yaml
from datetime import datetime
import pandas as pd
from utils.logger import setup_logger
from utils.validators import DataValidator
from utils.helpers import calculate_file_hash, ensure_directory

logger = setup_logger("data_service")


class DataService:
    """Comprehensive data management service."""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize data service."""
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        
        self.data_dir = Path(self.config['paths']['data_dir'])
        self.validator = DataValidator()
        
        # Ensure data directories exist
        for subdir in ['synthetic', 'collected', 'validated']:
            ensure_directory(self.data_dir / subdir)
    
    def load_json(self, file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """
        Load JSON file with error handling.
        
        Args:
            file_path: Path to JSON file
        
        Returns:
            Loaded data or None if failed
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            logger.debug(f"Loaded JSON from {file_path.name}")
            return data
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path.name}: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to load {file_path.name}: {e}")
            return None
    
    def save_json(
        self,
        data: Any,
        file_path: Union[str, Path],
        indent: int = 2,
        ensure_ascii: bool = False
    ) -> bool:
        """
        Save data to JSON file.
        
        Args:
            data: Data to save
            file_path: Output file path
            indent: JSON indentation
            ensure_ascii: Whether to escape non-ASCII characters
        
        Returns:
            True if successful
        """
        file_path = Path(file_path)
        
        try:
            # Ensure parent directory exists
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=indent, ensure_ascii=ensure_ascii, default=str)
            
            logger.debug(f"Saved JSON to {file_path.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save {file_path.name}: {e}")
            return False
    
    def load_dataset(
        self,
        dataset_path: Union[str, Path],
        validate: bool = True
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Load dataset with optional validation.
        
        Args:
            dataset_path: Path to dataset file
            validate: Whether to validate data
        
        Returns:
            List of records or None if failed
        """
        dataset_path = Path(dataset_path)
        
        logger.info(f"Loading dataset from {dataset_path.name}")
        
        # Load data
        data = self.load_json(dataset_path)
        if data is None:
            return None
        
        # Extract records
        records = self._extract_records(data)
        
        if not records:
            logger.error("No records found in dataset")
            return None
        
        logger.info(f"Extracted {len(records)} records")
        
        # Validate if requested
        if validate:
            valid_records = []
            invalid_count = 0
            
            for idx, record in enumerate(records):
                is_valid, errors = self.validator.validate_record(record)
                
                if is_valid:
                    valid_records.append(record)
                else:
                    invalid_count += 1
                    logger.debug(f"Record {idx} validation failed: {errors}")
            
            logger.info(f"Validation: {len(valid_records)} valid, {invalid_count} invalid")
            
            if not valid_records:
                logger.error("No valid records found")
                return None
            
            return valid_records
        
        return records
    
    def save_dataset(
        self,
        records: List[Dict[str, Any]],
        output_path: Union[str, Path],
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Save dataset with metadata.
        
        Args:
            records: List of records to save
            output_path: Output file path
            metadata: Optional metadata to include
        
        Returns:
            True if successful
        """
        output_path = Path(output_path)
        
        # Prepare dataset with metadata
        dataset = {
            "metadata": {
                "record_count": len(records),
                "created_at": datetime.now().isoformat(),
                "version": "1.0",
                **(metadata or {})
            },
            "records": records
        }
        
        return self.save_json(dataset, output_path)
    
    def _extract_records(self, data: Any) -> List[Dict[str, Any]]:
        """
        Extract records from various data structures.
        
        Supports:
        - Single record: {...}
        - List of records: [{...}, {...}]
        - Nested records: {"records": [...]}
        """
        # Single record
        if isinstance(data, dict) and "records" not in data:
            # Check if it looks like a single record
            if any(key in data for key in ["company_name", "network", "endpoint_security"]):
                return [data]
        
        # List of records
        if isinstance(data, list):
            return [r for r in data if isinstance(r, dict)]
        
        # Nested records
        if isinstance(data, dict):
            for key in ['records', 'data', 'samples', 'items', 'dataset']:
                if key in data and isinstance(data[key], list):
                    return [r for r in data[key] if isinstance(r, dict)]
        
        return []
    
    def merge_datasets(
        self,
        dataset_paths: List[Union[str, Path]],
        output_path: Union[str, Path]
    ) -> bool:
        """
        Merge multiple datasets into one.
        
        Args:
            dataset_paths: List of dataset file paths
            output_path: Output file path for merged dataset
        
        Returns:
            True if successful
        """
        logger.info(f"Merging {len(dataset_paths)} datasets")
        
        all_records = []
        
        for path in dataset_paths:
            records = self.load_dataset(path, validate=False)
            if records:
                all_records.extend(records)
                logger.debug(f"Added {len(records)} records from {Path(path).name}")
        
        if not all_records:
            logger.error("No records to merge")
            return False
        
        metadata = {
            "source_files": [str(p) for p in dataset_paths],
            "merged_at": datetime.now().isoformat()
        }
        
        return self.save_dataset(all_records, output_path, metadata)
    
    def split_dataset(
        self,
        dataset_path: Union[str, Path],
        train_path: Union[str, Path],
        test_path: Union[str, Path],
        test_size: float = 0.2,
        random_state: int = 42
    ) -> bool:
        """
        Split dataset into train and test sets.
        
        Args:
            dataset_path: Input dataset path
            train_path: Output path for training set
            test_path: Output path for test set
            test_size: Proportion of test set (0.0 to 1.0)
            random_state: Random seed for reproducibility
        
        Returns:
            True if successful
        """
        from sklearn.model_selection import train_test_split
        
        logger.info(f"Splitting dataset (test_size={test_size})")
        
        # Load dataset
        records = self.load_dataset(dataset_path, validate=False)
        if not records:
            return False
        
        # Split
        train_records, test_records = train_test_split(
            records,
            test_size=test_size,
            random_state=random_state
        )
        
        logger.info(f"Train: {len(train_records)}, Test: {len(test_records)}")
        
        # Save splits
        train_success = self.save_dataset(
            train_records,
            train_path,
            {"split": "train", "test_size": test_size}
        )
        
        test_success = self.save_dataset(
            test_records,
            test_path,
            {"split": "test", "test_size": test_size}
        )
        
        return train_success and test_success
    
    def get_dataset_info(
        self,
        dataset_path: Union[str, Path]
    ) -> Optional[Dict[str, Any]]:
        """
        Get information about a dataset.
        
        Args:
            dataset_path: Path to dataset
        
        Returns:
            Dataset information
        """
        dataset_path = Path(dataset_path)
        
        records = self.load_dataset(dataset_path, validate=False)
        if not records:
            return None
        
        # Analyze records
        company_types = set()
        compliance_statuses = set()
        
        for record in records:
            company_types.add(record.get("company_type", "Unknown"))
            compliance_statuses.add(record.get("compliance_status", "Unknown"))
        
        return {
            "file_name": dataset_path.name,
            "file_path": str(dataset_path),
            "file_size_mb": dataset_path.stat().st_size / (1024 * 1024),
            "file_hash": calculate_file_hash(dataset_path),
            "record_count": len(records),
            "company_types": list(company_types),
            "compliance_statuses": list(compliance_statuses),
            "sample_record_keys": list(records[0].keys()) if records else []
        }
    
    def list_datasets(
        self,
        directory: Optional[Union[str, Path]] = None
    ) -> List[Dict[str, Any]]:
        """
        List all datasets in a directory.
        
        Args:
            directory: Directory to search (default: synthetic)
        
        Returns:
            List of dataset information
        """
        if directory is None:
            directory = self.data_dir / "synthetic"
        else:
            directory = Path(directory)
        
        if not directory.exists():
            logger.warning(f"Directory not found: {directory}")
            return []
        
        datasets = []
        
        for json_file in directory.glob("*.json"):
            info = self.get_dataset_info(json_file)
            if info:
                datasets.append(info)
        
        return datasets
    
    def export_to_csv(
        self,
        dataset_path: Union[str, Path],
        output_path: Union[str, Path],
        flatten: bool = True
    ) -> bool:
        """
        Export dataset to CSV format.
        
        Args:
            dataset_path: Input dataset path
            output_path: Output CSV path
            flatten: Whether to flatten nested structures
        
        Returns:
            True if successful
        """
        records = self.load_dataset(dataset_path, validate=False)
        if not records:
            return False
        
        try:
            if flatten:
                # Flatten nested dictionaries
                from utils.helpers import flatten_dict
                flat_records = [flatten_dict(r) for r in records]
                df = pd.DataFrame(flat_records)
            else:
                df = pd.DataFrame(records)
            
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            df.to_csv(output_path, index=False)
            logger.info(f"Exported to CSV: {output_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"CSV export failed: {e}")
            return False
    
    def import_from_csv(
        self,
        csv_path: Union[str, Path],
        output_path: Union[str, Path]
    ) -> bool:
        """
        Import CSV to JSON dataset.
        
        Args:
            csv_path: Input CSV path
            output_path: Output JSON path
        
        Returns:
            True if successful
        """
        try:
            df = pd.read_csv(csv_path)
            
            # Convert to records
            records = df.to_dict('records')
            
            # Clean None values
            records = [
                {k: v for k, v in r.items() if pd.notna(v)}
                for r in records
            ]
            
            return self.save_dataset(records, output_path)
            
        except Exception as e:
            logger.error(f"CSV import failed: {e}")
            return False
    
    def clean_dataset(
        self,
        dataset_path: Union[str, Path],
        output_path: Union[str, Path],
        remove_duplicates: bool = True,
        validate: bool = True
    ) -> bool:
        """
        Clean and sanitize dataset.
        
        Args:
            dataset_path: Input dataset path
            output_path: Output cleaned dataset path
            remove_duplicates: Whether to remove duplicate records
            validate: Whether to remove invalid records
        
        Returns:
            True if successful
        """
        logger.info("Cleaning dataset...")
        
        records = self.load_dataset(dataset_path, validate=False)
        if not records:
            return False
        
        original_count = len(records)
        
        # Remove duplicates
        if remove_duplicates:
            seen = set()
            unique_records = []
            
            for record in records:
                # Create hash of record for comparison
                record_hash = json.dumps(record, sort_keys=True)
                if record_hash not in seen:
                    seen.add(record_hash)
                    unique_records.append(record)
            
            records = unique_records
            logger.info(f"Removed {original_count - len(records)} duplicates")
        
        # Validate and remove invalid records
        if validate:
            valid_records = []
            
            for record in records:
                is_valid, _ = self.validator.validate_record(record)
                if is_valid:
                    valid_records.append(record)
            
            records = valid_records
            logger.info(f"Removed {len(records) - len(valid_records)} invalid records")
        
        # Save cleaned dataset
        metadata = {
            "cleaned_at": datetime.now().isoformat(),
            "original_count": original_count,
            "final_count": len(records),
            "removed_count": original_count - len(records)
        }
        
        return self.save_dataset(records, output_path, metadata)