"""
Compliance AI - Main Orchestrator
=================================
Enterprise-grade compliance automation system with ML-driven analysis.

Usage:
    python main.py train --dataset data/synthetic/dataset1.json
    python main.py collect --realtime
    python main.py audit --input data/collected/snapshot.json
    python main.py report --company "CompanyName"
    python main.py serve --port 8000
"""

import argparse
import sys
from pathlib import Path
import yaml
import json
from datetime import datetime
from typing import Dict, Any, Optional

# Core imports
from core.validator import ComplianceDataValidator
from services.ml_service import MLService
from services.audit_service import AuditService
from services.report_service import ReportService
from utils.logger import setup_logger

logger = setup_logger("main")


class ComplianceAIOrchestrator:
    """Main orchestrator for Compliance AI system."""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize orchestrator."""
        logger.info("="  * 70)
        logger.info("🚀 Compliance AI Engine v1.0.0")
        logger.info("="  * 70)
        
        # Load configuration
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        
        # Initialize services
        self.validator = ComplianceDataValidator(config_path)
        self.ml_service = MLService(config_path)
        self.audit_service = AuditService(config_path)
        self.report_service = ReportService(config_path)
        
        # Setup paths
        self.data_dir = Path(self.config['paths']['data_dir'])
        self.models_dir = Path(self.config['paths']['models_dir'])
        self.reports_dir = Path(self.config['paths']['reports_dir'])
        
        # Create directories
        for directory in [self.data_dir, self.models_dir, self.reports_dir]:
            directory.mkdir(exist_ok=True)
        
        logger.info("✓ System initialized successfully")
    
    def train_pipeline(
        self, 
        dataset_path: str,
        algorithm: str = "RandomForest"
    ) -> Dict[str, Any]:
        """
        Execute ML training pipeline.
        
        Args:
            dataset_path: Path to training dataset
            algorithm: ML algorithm to use
        
        Returns:
            Training results
        """
        logger.info("\n" + "="  * 70)
        logger.info("📚 TRAINING PIPELINE")
        logger.info("="  * 70)
        
        dataset_path = Path(dataset_path)
        
        if not dataset_path.exists():
            logger.error(f"❌ Dataset not found: {dataset_path}")
            return {"success": False, "error": "Dataset not found"}
        
        try:
            # Load and validate dataset
            logger.info("🔍 Step 1: Validating dataset...")
            with open(dataset_path) as f:
                data = json.load(f)
            
            if isinstance(data, dict) and "records" in data:
                records = data["records"]
            elif isinstance(data, list):
                records = data
            else:
                records = [data]
            
            is_valid, validation_report = self.validator.validate_training_dataset(records)
            
            if not is_valid:
                logger.warning(
                    f"⚠️  Dataset has validation issues. "
                    f"Quality score: {validation_report['overall_quality_score']:.1f}"
                )
            else:
                logger.info(f"✓ Dataset validated successfully")
            
            # Train model
            logger.info(f"🎯 Step 2: Training {algorithm} model...")
            training_results = self.ml_service.train_model(
                dataset_path, 
                algorithm
            )
            
            if training_results["success"]:
                logger.info("\n" + "="  * 70)
                logger.info("✅ TRAINING COMPLETED SUCCESSFULLY")
                logger.info("="  * 70)
                logger.info(f"📊 Model Version: {training_results['version_id']}")
                logger.info(f"📈 Accuracy: {training_results['metrics']['accuracy']:.4f}")
                logger.info(f"📁 Model Path: {training_results['model_path']}")
                logger.info("="  * 70)
            
            return training_results
            
        except Exception as e:
            logger.error(f"❌ Training failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    def collect_pipeline(
        self, 
        realtime: bool = False,
        interval: int = 300,
        output_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute data collection pipeline.
        
        Args:
            realtime: Enable continuous collection
            interval: Collection interval (seconds)
            output_path: Custom output path
        
        Returns:
            Collection results
        """
        logger.info("\n" + "="  * 70)
        logger.info("📡 DATA COLLECTION PIPELINE")
        logger.info("="  * 70)
        
        try:
            # Import collector
            from core.collector import ComplianceCollector
            
            if output_path is None:
                output_path = self.data_dir / "collected" / f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            else:
                output_path = Path(output_path)
            
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            collector = ComplianceCollector()
            
            if realtime:
                logger.info(f"🔄 Real-time mode enabled (interval: {interval}s)")
                logger.info("Press Ctrl+C to stop")
                
                import time
                iteration = 0
                
                while True:
                    iteration += 1
                    logger.info(f"\n📊 Collection iteration #{iteration}")
                    
                    data = collector.collect_all()
                    
                    # Validate
                    is_valid, validation_report = self.validator.validate_compliance_record(data)
                    
                    if is_valid:
                        # Save validated data
                        validated_path = self.data_dir / "validated" / output_path.name
                        validated_path.parent.mkdir(parents=True, exist_ok=True)
                        
                        with open(validated_path, 'w') as f:
                            json.dump(data, f, indent=2)
                        
                        logger.info(f"✓ Data saved: {validated_path}")
                    
                    time.sleep(interval)
            else:
                logger.info("📊 Single collection mode")
                
                data = collector.collect_all()
                
                # Validate
                is_valid, validation_report = self.validator.validate_compliance_record(data)
                
                # Save
                with open(output_path, 'w') as f:
                    json.dump(data, f, indent=2)
                
                logger.info(f"✓ Data saved: {output_path}")
                
                if is_valid:
                    # Also save to validated directory
                    validated_path = self.data_dir / "validated" / output_path.name
                    validated_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    with open(validated_path, 'w') as f:
                        json.dump(data, f, indent=2)
                
                return {
                    "success": True,
                    "output_path": str(output_path),
                    "validated": is_valid,
                    "validation_report": validation_report
                }
                
        except KeyboardInterrupt:
            logger.info("\n🛑 Collection stopped by user")
            return {"success": True, "stopped_by_user": True}
        except Exception as e:
            logger.error(f"❌ Collection failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    def audit_pipeline(
        self, 
        input_path: str,
        frameworks: Optional[list] = None,
        generate_reports: bool = True
    ) -> Dict[str, Any]:
        """
        Execute compliance audit pipeline.
        
        Args:
            input_path: Path to compliance data
            frameworks: Frameworks to audit against
            generate_reports: Whether to generate reports
        
        Returns:
            Audit results
        """
        logger.info("\n" + "="  * 70)
        logger.info("🔒 COMPLIANCE AUDIT PIPELINE")
        logger.info("="  * 70)
        
        input_path = Path(input_path)
        
        if not input_path.exists():
            logger.error(f"❌ Input file not found: {input_path}")
            return {"success": False, "error": "Input file not found"}
        
        try:
            # Load data
            logger.info(f"📂 Loading data from: {input_path}")
            with open(input_path) as f:
                data = json.load(f)
            
            # Validate
            logger.info("🔍 Step 1: Validating compliance data...")
            is_valid, validation_report = self.validator.validate_compliance_record(data)
            
            if not is_valid:
                logger.warning(
                    f"⚠️  Data validation issues detected. "
                    f"Quality score: {validation_report['data_quality_score']:.1f}"
                )
                logger.warning(f"Errors: {validation_report['errors']}")
            
            # ML Inference
            logger.info("🤖 Step 2: Running ML inference...")
            try:
                ml_prediction = self.ml_service.predict(data)
                logger.info(
                    f"✓ ML Prediction: {ml_prediction['prediction']} "
                    f"(Confidence: {ml_prediction['confidence']:.1f}%)"
                )
            except Exception as e:
                logger.warning(f"⚠️  ML inference failed: {e}")
                ml_prediction = None
            
            # Compliance Audit
            logger.info("📋 Step 3: Running compliance audit...")
            if frameworks is None:
                frameworks = self.config['audit']['frameworks']
            
            audit_results = self.audit_service.audit_compliance(
                data, 
                frameworks
            )
            
            logger.info(f"✓ Audit completed for {len(frameworks)} frameworks")
            
            # Combine results
            comprehensive_results = {
                "company_name": data.get("company_name", "Unknown"),
                "audit_date": datetime.now().isoformat(),
                "data_validation": validation_report,
                "ml_prediction": ml_prediction,
                "audit_results": audit_results,
                "input_file": str(input_path)
            }
            
            # Save results
            results_dir = self.reports_dir / "json"
            results_dir.mkdir(parents=True, exist_ok=True)
            
            results_file = results_dir / f"audit_{data.get('company_name', 'unknown')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(results_file, 'w') as f:
                json.dump(comprehensive_results, f, indent=2, default=str)
            
            logger.info(f"💾 Results saved: {results_file}")
            
            # Generate reports
            if generate_reports:
                logger.info("📄 Step 4: Generating reports...")
                report_results = self.report_service.generate_all_reports(
                    comprehensive_results
                )
                comprehensive_results["generated_reports"] = report_results
            
            # Print summary
            self._print_audit_summary(comprehensive_results)
            
            return {
                "success": True,
                "results": comprehensive_results,
                "results_file": str(results_file)
            }
            
        except Exception as e:
            logger.error(f"❌ Audit failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    def _print_audit_summary(self, results: Dict[str, Any]):
        """Print audit summary."""
        logger.info("\n" + "="  * 70)
        logger.info("📊 AUDIT SUMMARY")
        logger.info("="  * 70)
        
        company_name = results.get("company_name", "Unknown")
        logger.info(f"🏢 Company: {company_name}")
        
        # ML Prediction
        if results.get("ml_prediction"):
            ml_pred = results["ml_prediction"]
            logger.info(
                f"🤖 ML Prediction: {ml_pred['prediction']} "
                f"({ml_pred['confidence']:.1f}% confidence)"
            )
        
        # Audit Results
        audit_results = results.get("audit_results", {})
        
        if "overall_compliance" in audit_results:
            overall = audit_results["overall_compliance"]
            logger.info(
                f"📈 Overall Compliance: {overall['compliance_percentage']:.1f}% "
                f"({overall['risk_level']})"
            )
        
        # Framework scores
        logger.info("\n📋 Framework Compliance:")
        for framework, metrics in audit_results.get("frameworks", {}).items():
            logger.info(
                f"  {framework}: {metrics['compliance_percentage']:.1f}% "
                f"({metrics['passed_rules']}/{metrics['total_rules']} rules passed)"
            )
        
        # Critical issues
        critical_count = audit_results.get("overall_compliance", {}).get("total_critical_issues", 0)
        high_count = audit_results.get("overall_compliance", {}).get("total_high_issues", 0)
        
        logger.info(f"\n🚨 Critical Issues: {critical_count}")
        logger.info(f"⚠️  High Priority Issues: {high_count}")
        
        logger.info("="  * 70)
    
    def report_pipeline(
        self, 
        company: Optional[str] = None,
        latest: bool = True
    ) -> Dict[str, Any]:
        """
        Generate comprehensive reports.
        
        Args:
            company: Company name filter
            latest: Use latest audit results
        
        Returns:
            Report generation results
        """
        logger.info("\n" + "="  * 70)
        logger.info("📄 REPORT GENERATION PIPELINE")
        logger.info("="  * 70)
        
        try:
            # Find audit results
            results_dir = self.reports_dir / "json"
            
            if not results_dir.exists():
                logger.error("❌ No audit results found")
                return {"success": False, "error": "No audit results found"}
            
            # Get latest or filter by company
            result_files = list(results_dir.glob("audit_*.json"))
            
            if not result_files:
                logger.error("❌ No audit result files found")
                return {"success": False, "error": "No audit result files found"}
            
            if company:
                result_files = [
                    f for f in result_files 
                    if company.lower() in f.stem.lower()
                ]
            
            if latest and result_files:
                result_files = [max(result_files, key=lambda f: f.stat().st_mtime)]
            
            generated_reports = []
            
            for result_file in result_files:
                logger.info(f"📂 Processing: {result_file.name}")
                
                with open(result_file) as f:
                    results = json.load(f)
                
                report_results = self.report_service.generate_all_reports(results)
                generated_reports.append(report_results)
                
                logger.info(f"✓ Reports generated for {results.get('company_name')}")
            
            logger.info("\n" + "="  * 70)
            logger.info(f"✅ Generated reports for {len(generated_reports)} companies")
            logger.info("="  * 70)
            
            return {
                "success": True,
                "reports": generated_reports,
                "count": len(generated_reports)
            }
            
        except Exception as e:
            logger.error(f"❌ Report generation failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    def serve_api(self, host: str = "0.0.0.0", port: int = 8000):
        """
        Start API server for frontend integration.
        
        Args:
            host: Server host
            port: Server port
        """
        logger.info("\n" + "="  * 70)
        logger.info("🌐 STARTING API SERVER")
        logger.info("="  * 70)
        
        try:
            from api.server import create_app
            import uvicorn
            
            app = create_app(self)
            
            logger.info(f"🚀 Server starting at http://{host}:{port}")
            logger.info("📡 API Documentation: http://{host}:{port}/docs")
            logger.info("Press Ctrl+C to stop")
            
            uvicorn.run(app, host=host, port=port)
            
        except ImportError:
            logger.error("❌ FastAPI not installed. Install with: pip install fastapi uvicorn")
        except KeyboardInterrupt:
            logger.info("\n🛑 Server stopped")
        except Exception as e:
            logger.error(f"❌ Server failed: {e}", exc_info=True)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Compliance AI - Enterprise Compliance Automation System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train a model
  python main.py train --dataset data/synthetic/bfsi_dataset.json
  
  # Collect real-time data
  python main.py collect --realtime --interval 300
  
  # Run compliance audit
  python main.py audit --input data/collected/snapshot.json
  
  # Generate reports
  python main.py report --company "SecureMax"
  
  # Start API server
  python main.py serve --port 8000
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Train command
    train_parser = subparsers.add_parser('train', help='Train ML model')
    train_parser.add_argument('--dataset', required=True, help='Path to training dataset')
    train_parser.add_argument('--algorithm', default='RandomForest', 
                             choices=['RandomForest', 'GradientBoosting'],
                             help='ML algorithm to use')
    
    # Collect command
    collect_parser = subparsers.add_parser('collect', help='Collect compliance data')
    collect_parser.add_argument('--realtime', action='store_true', 
                               help='Enable continuous collection')
    collect_parser.add_argument('--interval', type=int, default=300,
                               help='Collection interval in seconds')
    collect_parser.add_argument('--output', help='Output file path')
    
    # Audit command
    audit_parser = subparsers.add_parser('audit', help='Run compliance audit')
    audit_parser.add_argument('--input', required=True, 
                             help='Path to compliance data')
    audit_parser.add_argument('--frameworks', nargs='+',
                             help='Specific frameworks to audit')
    audit_parser.add_argument('--no-reports', action='store_true',
                             help='Skip report generation')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate reports')
    report_parser.add_argument('--company', help='Company name filter')
    report_parser.add_argument('--all', action='store_true',
                              help='Generate for all companies')
    
    # Serve command
    serve_parser = subparsers.add_parser('serve', help='Start API server')
    serve_parser.add_argument('--host', default='0.0.0.0', help='Server host')
    serve_parser.add_argument('--port', type=int, default=8000, help='Server port')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize orchestrator
    orchestrator = ComplianceAIOrchestrator()
    
    # Execute command
    try:
        if args.command == 'train':
            result = orchestrator.train_pipeline(
                args.dataset,
                args.algorithm
            )
        
        elif args.command == 'collect':
            result = orchestrator.collect_pipeline(
                realtime=args.realtime,
                interval=args.interval,
                output_path=args.output
            )
        
        elif args.command == 'audit':
            result = orchestrator.audit_pipeline(
                args.input,
                frameworks=args.frameworks,
                generate_reports=not args.no_reports
            )
        
        elif args.command == 'report':
            result = orchestrator.report_pipeline(
                company=args.company,
                latest=not args.all
            )
        
        elif args.command == 'serve':
            orchestrator.serve_api(args.host, args.port)
            result = {"success": True}
        
        # Exit with appropriate code
        sys.exit(0 if result.get("success", False) else 1)
        
    except KeyboardInterrupt:
        logger.info("\n🛑 Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()