"""
Dataset Combiner Script
=======================
Combines multiple single-record datasets into one multi-record dataset for training.
"""

import json
from pathlib import Path
from datetime import datetime

def combine_datasets(input_files, output_file):
    """
    Combine multiple JSON datasets into one.
    
    Args:
        input_files: List of input file paths
        output_file: Output file path
    """
    print("="*70)
    print("📦 DATASET COMBINER")
    print("="*70)
    
    all_records = []
    
    for input_file in input_files:
        input_path = Path(input_file)
        
        if not input_path.exists():
            print(f"⚠️  File not found: {input_file}")
            continue
        
        print(f"\n📂 Loading: {input_path.name}")
        
        with open(input_path) as f:
            data = json.load(f)
        
        # Handle different formats
        if isinstance(data, dict):
            if "records" in data:
                records = data["records"]
            else:
                records = [data]
        elif isinstance(data, list):
            records = data
        else:
            records = [data]
        
        print(f"   ✓ Found {len(records)} record(s)")
        
        # Add to combined dataset
        for record in records:
            # Ensure required fields
            if "compliance_status" not in record and "compliance_score" in record:
                score = record["compliance_score"]
                record["compliance_status"] = "Compliant" if score >= 80 else "Non-Compliant"
            
            all_records.append(record)
    
    # Create combined dataset
    combined_dataset = {
        "metadata": {
            "created_at": datetime.now().isoformat(),
            "total_records": len(all_records),
            "source_files": [str(f) for f in input_files],
            "description": "Combined dataset from multiple sources"
        },
        "records": all_records
    }
    
    # Save
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(combined_dataset, f, indent=2, ensure_ascii=False)
    
    print(f"\n{'='*70}")
    print(f"✅ COMBINED DATASET CREATED")
    print(f"{'='*70}")
    print(f"📊 Total Records: {len(all_records)}")
    print(f"💾 Output File: {output_path}")
    print(f"📏 File Size: {output_path.stat().st_size / 1024:.2f} KB")
    
    # Show class distribution
    statuses = {}
    for record in all_records:
        status = record.get("compliance_status", "Unknown")
        statuses[status] = statuses.get(status, 0) + 1
    
    print(f"\n📈 Class Distribution:")
    for status, count in statuses.items():
        print(f"   {status}: {count} records ({count/len(all_records)*100:.1f}%)")
    
    print(f"{'='*70}\n")
    
    return output_path


if __name__ == "__main__":
    # Combine your 3 datasets
    input_files = [
        "data/synthetic/synthetic_json_dataset.json",
        "data/synthetic/synthetic_json_dataset2.json",
        "data/synthetic/synthetic_json_dataset3.json"
    ]
    
    output_file = "data/synthetic/combined_training_dataset.json"
    
    combine_datasets(input_files, output_file)
    
    print("✅ Done! Now you can train with:")
    print(f"   python main.py train --dataset {output_file}")