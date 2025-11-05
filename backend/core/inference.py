"""
Compliance AI - Inference Engine Module
=======================================
Performs compliance predictions and generates detailed reports.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

import pandas as pd
import numpy as np
from joblib import load

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.utils import (
    load_json_file, save_json_file, extract_records_from_payload,
    validate_compliance_record, ProgressTracker, safe_bool_to_int
)
from utils.helpers import get_nested_value


class ComplianceScoreCalculator:
    """Calculates detailed compliance scores and identifies gaps."""
    
    def __init__(self, record: Dict[str, Any]):
        self.record = record
        self.category_scores = {}
        self.gaps = []
        self.strengths = []
        self.logger = logging.getLogger("ComplianceAI.Inference")
    
    def calculate_category_score(
        self,
        category_name: str,
        checks: List[Tuple[str, int]]
    ) -> float:
        """
        Calculate score for a compliance category.
        
        Args:
            category_name: Name of the compliance category
            checks: List of (path, weight) tuples
        
        Returns:
            Category score (0-100)
        """
        total_weight = sum(w for _, w in checks)
        achieved = 0
        
        for path, weight in checks:
            value = get_nested_value(self.record, path)
            if self._is_compliant(value):
                achieved += weight
            else:
                self.gaps.append({
                    'category': category_name,
                    'check': path,
                    'weight': weight,
                    'current_value': value
                })
        
        score = (achieved / total_weight * 100) if total_weight > 0 else 0
        self.category_scores[category_name] = round(score, 2)
        return score
    
    def _is_compliant(self, value: Any) -> bool:
        """Check if a value indicates compliance."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ['true', 'yes', 'enabled', 'deployed', 
                                     'implemented', 'compliant']
        if isinstance(value, (int, float)):
            return value > 0
        if isinstance(value, dict):
            return (value.get('enabled', False) or 
                   value.get('deployed', False) or 
                   value.get('implemented', False))
        return False
    
    def calculate_comprehensive_score(self) -> Dict[str, Any]:
        """Calculate comprehensive compliance score across all categories."""
        
        # Define compliance categories with checks and weights
        categories = {
            'Network Security': [
                ('network.network.unauthorized_devices.blocked', 3),
                ('network.network.devices.secure_configuration', 3),
                ('network.network.services.whitelist_enforced', 2),
                ('network.network.perimeter.filtering_configured', 2),
                ('network.network_security.segmentation.implemented', 2),
                ('network.network_security.ids.deployed', 1),
                ('network.network_security.ips.deployed', 1),
            ],
            'Endpoint Protection': [
                ('antimalware.deployed', 3),
                ('antimalware.centrally_managed', 2),
                ('antimalware.auto_update.enabled', 2),
                ('endpoint_security.edr.deployed', 3),
                ('endpoint_security.encryption.enabled', 2),
                ('endpoint_security.mdm.deployed', 1),
                ('endpoint_security.application_whitelisting.enabled', 2),
            ],
            'Vulnerability Management': [
                ('vulnerability_management.automated_scanning.enabled', 3),
                ('vulnerability_management.authenticated_scanning.enabled', 2),
                ('vulnerability_management.critical_patching.within_72_hours', 3),
                ('patch_management.automated_patching.enabled', 2),
                ('patch_management.automated_patching.os', 1),
                ('patch_management.automated_patching.applications', 1),
            ],
            'Logging & Monitoring': [
                ('logging.logging.central_management.enabled', 3),
                ('logging.logging.audit.enabled', 2),
                ('logging.siem.deployed', 3),
                ('logging.security_monitoring.soc.operational', 2),
                ('logging.security_monitoring.realtime.enabled', 1),
                ('logging.security_monitoring.automated_response.enabled', 1),
            ],
            'Access Control': [
                ('access_control.access_control.policy.exists', 2),
                ('access_control.access_control.pam_system.deployed', 3),
                ('access_control.access_control.session_recording.enabled', 2),
                ('access_control.users.privileged_access.managed', 2),
                ('access_control.users.access_review.regular', 1),
                ('access_control.systems.password_management.robust', 2),
            ],
            'Data Protection': [
                ('cryptography.cryptography.policy.exists', 2),
                ('cryptography.cryptography.key_management.implemented', 2),
                ('cryptography.data_protection.customer_data.encrypted_at_rest', 3),
                ('cryptography.data_protection.customer_data.encrypted_in_transit', 3),
            ],
            'Application Security': [
                ('application_security.sdlc.implemented', 2),
                ('application_security.sast.enabled', 2),
                ('application_security.dast.enabled', 2),
                ('application_security.code_review.mandatory', 1),
                ('application_security.waf.deployed', 3),
            ],
            'Backup & Recovery': [
                ('backup.backup.automated.enabled', 3),
                ('backup.backup.testing.regular', 2),
                ('backup.backup.protection.encryption', 2),
                ('backup.business_continuity.plan.exists', 1),
                ('backup.business_continuity.disaster_recovery.plan_exists', 2),
            ],
            'Governance': [
                ('operations.governance.board_approved_policy.exists', 2),
                ('operations.governance.security_strategy.documented', 2),
                ('operations.governance.ciso.appointed', 2),
                ('operations.governance.security_committee.established', 2),
            ],
            'HR & Training': [
                ('hr.hr.background_screening.mandatory', 2),
                ('hr.training.security_awareness.regular', 2),
                ('hr.training.cybersecurity.annual', 2),
                ('hr.training.phishing_simulation.regular', 2),
                ('hr.training.awareness_metrics.tracked', 2),
            ],
        }
        
        # Category weights for overall score
        weights = {
            'Network Security': 15,
            'Endpoint Protection': 15,
            'Vulnerability Management': 12,
            'Logging & Monitoring': 12,
            'Access Control': 12,
            'Data Protection': 10,
            'Application Security': 8,
            'Backup & Recovery': 8,
            'Governance': 8,
            'HR & Training': 5,
        }
        
        # Calculate scores for each category
        for category_name, checks in categories.items():
            self.calculate_category_score(category_name, checks)
        
        # Calculate weighted overall score
        overall_score = sum(
            self.category_scores.get(cat, 0) * (weight / 100)
            for cat, weight in weights.items()
        )
        
        # Identify top strengths
        sorted_categories = sorted(
            self.category_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )
        self.strengths = [
            {'category': cat, 'score': score}
            for cat, score in sorted_categories[:3]
            if score >= 80
        ]
        
        # Sort gaps by weight (priority)
        self.gaps.sort(key=lambda x: x['weight'], reverse=True)
        
        return {
            'overall_score': round(overall_score, 2),
            'category_scores': self.category_scores,
            'category_weights': weights,
            'top_strengths': self.strengths,
            'critical_gaps': self.gaps[:10],
            'total_gaps': len(self.gaps)
        }


class ReportGenerator:
    """Generates compliance reports in various formats."""
    
    @staticmethod
    def generate_text_report(result: Dict[str, Any]) -> str:
        """Generate human-readable text report."""
        lines = []
        lines.append("=" * 80)
        lines.append("COMPLIANCE ASSESSMENT REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Executive Summary
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Company: {result.get('company_name', 'N/A')}")
        lines.append(f"Assessment Date: {result.get('inference_date', 'N/A')}")
        lines.append(f"Predicted Status: {result['prediction']}")
        lines.append(f"Confidence: {result['confidence']:.1f}%")
        lines.append(f"Overall Score: {result['compliance_analysis']['overall_score']:.1f}/100")
        lines.append("")
        
        # Risk Level
        score = result['compliance_analysis']['overall_score']
        if score >= 90:
            risk = "LOW"
        elif score >= 70:
            risk = "MEDIUM"
        elif score >= 50:
            risk = "HIGH"
        else:
            risk = "CRITICAL"
        lines.append(f"Risk Level: {risk}")
        lines.append("")
        
        # Category Scores
        lines.append("CATEGORY SCORES")
        lines.append("-" * 80)
        for cat, score in result['compliance_analysis']['category_scores'].items():
            weight = result['compliance_analysis']['category_weights'].get(cat, 0)
            bar_filled = int(score / 5)
            bar = "█" * bar_filled + "░" * (20 - bar_filled)
            lines.append(f"{cat:<28} [{bar}] {score:5.1f}% (weight {weight}%)")
        lines.append("")
        
        # Strengths
        lines.append("TOP STRENGTHS")
        lines.append("-" * 80)
        strengths = result['compliance_analysis'].get('top_strengths', [])
        if strengths:
            for item in strengths:
                lines.append(f"✓ {item['category']}: {item['score']:.1f}%")
        else:
            lines.append("- None identified")
        lines.append("")
        
        # Critical Gaps
        lines.append("TOP CRITICAL GAPS")
        lines.append("-" * 80)
        gaps = result['compliance_analysis'].get('critical_gaps', [])
        if gaps:
            for gap in gaps:
                lines.append(f"✗ [{gap['category']}] {gap['check']} (priority: {gap['weight']})")
        else:
            lines.append("- None identified")
        lines.append("")
        
        lines.append("=" * 80)
        return "\n".join(lines)


class ComplianceInference:
    """Main inference engine for compliance predictions."""
    
    def __init__(self, model_path: Path):
        """
        Initialize inference engine.
        
        Args:
            model_path: Path to trained model bundle
        """
        self.logger = logging.getLogger("ComplianceAI.Inference")
        self.model_path = model_path
        
        # Load model bundle
        self.logger.info(f"Loading model from {model_path}")
        self.bundle = load(model_path)
        
        self.model = self.bundle['model']
        self.scaler = self.bundle['scaler']
        self.imputer = self.bundle['imputer']
        self.label_encoder = self.bundle['label_encoder']
        self.feature_names = self.bundle['feature_names']
        
        self.logger.info(f"✓ Model loaded: {self.bundle['model_type']}")
        self.logger.info(f"✓ Features: {len(self.feature_names)}")
        self.logger.info(f"✓ Classes: {list(self.label_encoder.classes_)}")
    
    def _extract_features(self, record: Dict[str, Any]) -> pd.DataFrame:
        """Extract features matching training format."""
        from core.trainer import FeatureExtractor
        
        extractor = FeatureExtractor()
        features = extractor.extract_features(record)
        
        df = pd.DataFrame([features])
        
        # Handle categorical encoding
        if 'company_type' in df.columns:
            df = pd.get_dummies(df, columns=['company_type'], prefix='company')
        
        # Align columns with training features
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0
        
        df = df[self.feature_names]
        return df
    
    def _predict_single(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Run prediction on a single record."""
        # Extract features
        X = self._extract_features(record)
        
        # Preprocess
        X_imp = self.imputer.transform(X)
        X_scaled = self.scaler.transform(X_imp)
        
        # Predict
        y_pred_idx = self.model.predict(X_scaled)[0]
        pred_label = self.label_encoder.inverse_transform([y_pred_idx])[0]
        
        # Get confidence
        if hasattr(self.model, 'predict_proba'):
            proba = self.model.predict_proba(X_scaled)[0]
            confidence = float(np.max(proba) * 100.0)
        else:
            confidence = 50.0
        
        # Calculate detailed compliance analysis
        calculator = ComplianceScoreCalculator(record)
        compliance_analysis = calculator.calculate_comprehensive_score()
        
        return {
            'prediction': pred_label,
            'confidence': confidence,
            'compliance_analysis': compliance_analysis,
            'final_compliance_score': compliance_analysis['overall_score']
        }
    
    def run_inference(
        self,
        data_path: Path,
        output_path: Path,
        output_format: str = 'both',
        detailed: bool = False
    ) -> bool:
        """
        Run inference on compliance data.
        
        Args:
            data_path: Path to input data
            output_path: Path for output
            output_format: Output format (json/text/both)
            detailed: Include detailed analysis
        
        Returns:
            True if successful
        """
        try:
            self.logger.info("=" * 70)
            self.logger.info("Starting Compliance Inference")
            self.logger.info("=" * 70)
            
            # Load input data
            input_files = []
            if data_path.is_file():
                input_files = [data_path]
            elif data_path.is_dir():
                input_files = sorted(data_path.glob('*.json'))
            else:
                self.logger.error(f"Invalid data path: {data_path}")
                return False
            
            if not input_files:
                self.logger.error(f"No JSON files found in {data_path}")
                return False
            
            self.logger.info(f"Found {len(input_files)} input files")
            
            all_results = []
            progress = ProgressTracker(len(input_files), "Processing files")
            
            for file in input_files:
                payload = load_json_file(file)
                if not payload:
                    continue
                
                records = extract_records_from_payload(payload)
                
                for idx, rec in enumerate(records):
                    if not validate_compliance_record(rec):
                        continue
                    
                    # Run prediction
                    prediction = self._predict_single(rec)
                    
                    # Build result
                    result = {
                        'source_file': file.name,
                        'record_index': idx,
                        'company_name': rec.get('company_name', 'Unknown'),
                        'inference_date': datetime.now().isoformat(),
                        **prediction
                    }
                    
                    all_results.append(result)
                    
                    # Save per-record reports if detailed
                    if detailed:
                        base = file.stem if len(records) == 1 else f"{file.stem}_{idx}"
                        
                        if output_format in ['json', 'both']:
                            json_out = output_path.parent / f"{base}_inference.json"
                            save_json_file(result, json_out)
                        
                        if output_format in ['text', 'both']:
                            txt_out = output_path.parent / f"{base}_report.txt"
                            report_text = ReportGenerator.generate_text_report(result)
                            txt_out.write_text(report_text, encoding='utf-8')
                
                progress.update()
            
            progress.complete()
            
            if not all_results:
                self.logger.warning("No valid records processed")
                return False
            
            # Save summary
            summary = {
                'model_path': str(self.model_path),
                'run_date': datetime.now().isoformat(),
                'num_files': len(input_files),
                'num_records': len(all_results),
                'results': all_results
            }
            
            if output_format in ['json', 'both']:
                if save_json_file(summary, output_path):
                    self.logger.info(f"💾 Results saved: {output_path}")
            
            if output_format in ['text', 'both']:
                # Generate summary report for first result
                if all_results:
                    report_path = output_path.parent / f"{output_path.stem}_report.txt"
                    report_text = ReportGenerator.generate_text_report(all_results[0])
                    report_path.write_text(report_text, encoding='utf-8')
                    self.logger.info(f"📄 Report saved: {report_path}")
            
            # Log summary statistics
            compliant_count = sum(1 for r in all_results if r['prediction'] == 'Compliant')
            avg_score = np.mean([r['final_compliance_score'] for r in all_results])
            
            self.logger.info("")
            self.logger.info("INFERENCE SUMMARY")
            self.logger.info("-" * 70)
            self.logger.info(f"Total Records: {len(all_results)}")
            self.logger.info(f"Compliant: {compliant_count} ({compliant_count/len(all_results)*100:.1f}%)")
            self.logger.info(f"Non-Compliant: {len(all_results)-compliant_count}")
            self.logger.info(f"Average Score: {avg_score:.2f}/100")
            
            return True
            
        except Exception as e:
            self.logger.exception(f"Inference failed: {e}")
            return False