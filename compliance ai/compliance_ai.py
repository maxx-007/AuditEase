#!/usr/bin/env python3
"""
Compliance AI - Unified ML-Driven Compliance Automation System
===============================================================
Production-grade CLI for training models, collecting real-time data,
and performing compliance inference with detailed reporting.

Author: Compliance AI Team
Version: 1.0.0
"""

import sys
import argparse
import logging
from pathlib import Path
from typing import Optional

from modules.trainer import ComplianceTrainer
from modules.collector import ComplianceCollector
from modules.inference import ComplianceInference
from modules.utils import setup_logging, validate_path, create_directory_structure


# Version information
__version__ = "1.0.0"
__author__ = "Compliance AI Team"


def setup_argparse() -> argparse.ArgumentParser:
    """Configure command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="compliance_ai",
        description="Unified ML-Driven Compliance Automation System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train a compliance model
  python compliance_ai.py train --data datasets/ --out models/ --model-type rf

  # Collect real-time compliance data
  python compliance_ai.py collect --source live_system --out outputs/snapshot.json

  # Run inference on collected data
  python compliance_ai.py infer --model models/compliance_model.joblib \\
                                 --data outputs/snapshot.json \\
                                 --out outputs/inference_summary.json

  # Continuous real-time collection
  python compliance_ai.py collect --source live_system --realtime --interval 300

  # Full pipeline: collect → infer
  python compliance_ai.py collect --source live_system --out outputs/snapshot.json
  python compliance_ai.py infer --model models/compliance_model.joblib \\
                                 --data outputs/snapshot.json

For more information: https://github.com/compliance-ai
        """
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging output"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Train command
    train_parser = subparsers.add_parser(
        "train",
        help="Train compliance prediction model from JSON datasets"
    )
    train_parser.add_argument(
        "--data",
        required=True,
        type=Path,
        help="Directory containing JSON training datasets or single JSON file"
    )
    train_parser.add_argument(
        "--out",
        type=Path,
        default=Path("models"),
        help="Output directory for trained model (default: models/)"
    )
    train_parser.add_argument(
        "--model-name",
        type=str,
        default="compliance_model",
        help="Name for the trained model (default: compliance_model)"
    )
    train_parser.add_argument(
        "--model-type",
        choices=["rf", "gb", "lr", "lgbm"],
        default="rf",
        help="Model type: rf=RandomForest, gb=GradientBoosting, lr=LogisticRegression, lgbm=LightGBM"
    )
    train_parser.add_argument(
        "--test-size",
        type=float,
        default=0.2,
        help="Test set size (0.0-0.5, default: 0.2)"
    )
    train_parser.add_argument(
        "--cv-folds",
        type=int,
        default=5,
        help="Number of cross-validation folds (default: 5)"
    )
    train_parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)"
    )
    
    # Collect command
    collect_parser = subparsers.add_parser(
        "collect",
        help="Collect real-time compliance posture data"
    )
    collect_parser.add_argument(
        "--source",
        choices=["live_system", "manual"],
        default="live_system",
        help="Data source (default: live_system)"
    )
    collect_parser.add_argument(
        "--out",
        type=Path,
        default=Path("outputs/compliance_snapshot.json"),
        help="Output file path (default: outputs/compliance_snapshot.json)"
    )
    collect_parser.add_argument(
        "--realtime",
        action="store_true",
        help="Enable continuous real-time collection mode"
    )
    collect_parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Collection interval in seconds for realtime mode (default: 300)"
    )
    collect_parser.add_argument(
        "--company-name",
        type=str,
        help="Company name for the assessment"
    )
    collect_parser.add_argument(
        "--company-type",
        type=str,
        help="Company type/industry"
    )
    
    # Infer command
    infer_parser = subparsers.add_parser(
        "infer",
        help="Run compliance inference and generate detailed reports"
    )
    infer_parser.add_argument(
        "--model",
        required=True,
        type=Path,
        help="Path to trained model bundle (.joblib)"
    )
    infer_parser.add_argument(
        "--data",
        required=True,
        type=Path,
        help="Input JSON file or directory containing compliance data"
    )
    infer_parser.add_argument(
        "--out",
        type=Path,
        default=Path("outputs/inference_summary.json"),
        help="Output file path (default: outputs/inference_summary.json)"
    )
    infer_parser.add_argument(
        "--format",
        choices=["json", "text", "both"],
        default="both",
        help="Output format (default: both)"
    )
    infer_parser.add_argument(
        "--detailed",
        action="store_true",
        help="Include detailed analysis in reports"
    )
    
    return parser


def command_train(args: argparse.Namespace, logger: logging.Logger) -> int:
    """Execute model training command."""
    try:
        logger.info("=" * 80)
        logger.info("COMPLIANCE AI - MODEL TRAINING")
        logger.info("=" * 80)
        
        # Validate inputs
        if not validate_path(args.data, must_exist=True):
            logger.error(f"Data path does not exist: {args.data}")
            return 1
        
        # Initialize trainer
        trainer = ComplianceTrainer(
            model_type=args.model_type,
            test_size=args.test_size,
            cv_folds=args.cv_folds,
            random_state=args.random_state
        )
        
        # Train model
        logger.info(f"Training model with data from: {args.data}")
        success = trainer.train(
            data_path=args.data,
            output_dir=args.out,
            model_name=args.model_name
        )
        
        if success:
            logger.info("=" * 80)
            logger.info("✅ MODEL TRAINING COMPLETED SUCCESSFULLY")
            logger.info("=" * 80)
            return 0
        else:
            logger.error("❌ Model training failed")
            return 1
            
    except Exception as e:
        logger.exception(f"Fatal error during training: {e}")
        return 1


def command_collect(args: argparse.Namespace, logger: logging.Logger) -> int:
    """Execute data collection command."""
    try:
        logger.info("=" * 80)
        logger.info("COMPLIANCE AI - DATA COLLECTION")
        logger.info("=" * 80)
        
        # Initialize collector
        collector = ComplianceCollector(
            company_name=args.company_name,
            company_type=args.company_type
        )
        
        # Collect data
        if args.realtime:
            logger.info(f"Starting real-time collection (interval: {args.interval}s)")
            logger.info("Press Ctrl+C to stop")
            success = collector.collect_realtime(
                output_path=args.out,
                interval=args.interval
            )
        else:
            logger.info("Collecting compliance data snapshot...")
            success = collector.collect_once(output_path=args.out)
        
        if success:
            logger.info("=" * 80)
            logger.info("✅ DATA COLLECTION COMPLETED SUCCESSFULLY")
            logger.info("=" * 80)
            return 0
        else:
            logger.error("❌ Data collection failed")
            return 1
            
    except KeyboardInterrupt:
        logger.info("\n🛑 Collection stopped by user")
        return 0
    except Exception as e:
        logger.exception(f"Fatal error during collection: {e}")
        return 1


def command_infer(args: argparse.Namespace, logger: logging.Logger) -> int:
    """Execute inference command."""
    try:
        logger.info("=" * 80)
        logger.info("COMPLIANCE AI - INFERENCE & REPORTING")
        logger.info("=" * 80)
        
        # Validate inputs
        if not validate_path(args.model, must_exist=True):
            logger.error(f"Model file does not exist: {args.model}")
            return 1
        
        if not validate_path(args.data, must_exist=True):
            logger.error(f"Data path does not exist: {args.data}")
            return 1
        
        # Initialize inference engine
        inference = ComplianceInference(model_path=args.model)
        
        # Run inference
        logger.info(f"Running inference on data from: {args.data}")
        success = inference.run_inference(
            data_path=args.data,
            output_path=args.out,
            output_format=args.format,
            detailed=args.detailed
        )
        
        if success:
            logger.info("=" * 80)
            logger.info("✅ INFERENCE COMPLETED SUCCESSFULLY")
            logger.info("=" * 80)
            return 0
        else:
            logger.error("❌ Inference failed")
            return 1
            
    except Exception as e:
        logger.exception(f"Fatal error during inference: {e}")
        return 1


def main() -> int:
    """Main entry point for Compliance AI CLI."""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logging(level=log_level)
    
    # Show help if no command specified
    if not args.command:
        parser.print_help()
        return 0
    
    # Create directory structure
    create_directory_structure()
    
    # Route to appropriate command handler
    if args.command == "train":
        return command_train(args, logger)
    elif args.command == "collect":
        return command_collect(args, logger)
    elif args.command == "infer":
        return command_infer(args, logger)
    else:
        logger.error(f"Unknown command: {args.command}")
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())