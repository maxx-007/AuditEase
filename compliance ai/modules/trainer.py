"""
Compliance AI - Model Training Module
=====================================
Trains machine learning models for compliance prediction.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime
import traceback

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, accuracy_score, f1_score,
    precision_score, recall_score, confusion_matrix
)
from sklearn.impute import SimpleImputer
from joblib import dump

from modules.utils import (
    load_json_file, save_json_file, extract_records_from_payload,
    validate_compliance_record, ProgressTracker, safe_bool_to_int, safe_numeric
)


class FeatureExtractor:
    """Extracts ML features from compliance JSON data."""
    
    def __init__(self):
        self.logger = logging.getLogger("ComplianceAI.Trainer")
    
    def extract_features(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract comprehensive compliance features from JSON record.
        
        Args:
            record: Compliance data record
        
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # Basic info
        features['company_type'] = record.get('company_type', 'Unknown')
        features['compliance_score_orig'] = safe_numeric(record.get('compliance_score', 0))
        
        # Asset Management
        sw_inv = record.get('software_inventory', {})
        features['sw_maintained'] = safe_bool_to_int(sw_inv.get('maintained'))
        features['sw_count'] = safe_numeric(sw_inv.get('count', 0))
        
        hw_inv = record.get('hardware_inventory', {})
        features['hw_maintained'] = safe_bool_to_int(hw_inv.get('maintained'))
        features['hw_automated'] = safe_bool_to_int(hw_inv.get('automated'))
        
        sam = record.get('sam_tools', {})
        features['sam_deployed'] = safe_bool_to_int(sam.get('deployed'))
        
        # Network Security
        net = record.get('network', {}).get('network', {})
        features['net_unauth_blocked'] = safe_bool_to_int(net.get('unauthorized_devices', {}).get('blocked'))
        features['net_devices_secure'] = safe_bool_to_int(net.get('devices', {}).get('secure_configuration'))
        features['net_approved_only'] = safe_bool_to_int(net.get('services', {}).get('approved_only'))
        features['net_whitelist_enforced'] = safe_bool_to_int(net.get('services', {}).get('whitelist_enforced'))
        features['net_filtering'] = safe_bool_to_int(net.get('perimeter', {}).get('filtering_configured'))
        features['net_port_mapping'] = safe_bool_to_int(net.get('port_mapping', {}).get('complete'))
        features['net_port_scanning'] = safe_bool_to_int(net.get('port_scanning', {}).get('automated'))
        features['net_access_control'] = safe_bool_to_int(net.get('access_control', {}).get('implemented'))
        
        net_sec = record.get('network', {}).get('network_security', {})
        features['net_segmentation'] = safe_bool_to_int(net_sec.get('segmentation', {}).get('implemented'))
        features['net_vlans'] = safe_numeric(net_sec.get('segmentation', {}).get('vlans_count', 0))
        features['net_dmz'] = safe_bool_to_int(net_sec.get('dmz', {}).get('implemented'))
        features['net_ids'] = safe_bool_to_int(net_sec.get('ids', {}).get('deployed'))
        features['net_ips'] = safe_bool_to_int(net_sec.get('ips', {}).get('deployed'))
        features['net_ddos'] = safe_bool_to_int(net_sec.get('ddos_protection', {}).get('enabled'))
        
        # Firewall
        srv_fw = record.get('servers', {}).get('firewall', {})
        features['srv_fw_enabled'] = safe_bool_to_int(srv_fw.get('enabled'))
        features['srv_fw_managed'] = safe_bool_to_int(srv_fw.get('centrally_managed'))
        features['srv_fw_policy'] = safe_bool_to_int(srv_fw.get('policy_enforced'))
        
        ws_fw = record.get('workstations', {}).get('firewall', {})
        features['ws_fw_enabled'] = safe_bool_to_int(ws_fw.get('enabled'))
        features['ws_fw_managed'] = safe_bool_to_int(ws_fw.get('centrally_managed'))
        features['ws_fw_policy'] = safe_bool_to_int(ws_fw.get('policy_enforced'))
        
        # Antimalware
        am = record.get('antimalware', {})
        features['am_deployed'] = safe_bool_to_int(am.get('deployed'))
        features['am_managed'] = safe_bool_to_int(am.get('centrally_managed'))
        features['am_auto_update'] = safe_bool_to_int(am.get('auto_update', {}).get('enabled'))
        features['am_removable_scan'] = safe_bool_to_int(am.get('removable_media', {}).get('scanning'))
        features['am_logging'] = safe_bool_to_int(am.get('logging', {}).get('centralized'))
        features['am_realtime'] = safe_bool_to_int(am.get('real_time_protection'))
        
        # Endpoint Security
        ep_sec = record.get('endpoint_security', {})
        edr = ep_sec.get('edr', {})
        features['edr_deployed'] = safe_bool_to_int(edr.get('deployed'))
        features['edr_features_count'] = len(edr.get('features', []))
        
        enc = ep_sec.get('encryption', {})
        features['encryption_enabled'] = safe_bool_to_int(enc.get('enabled'))
        features['encryption_pct'] = safe_numeric(enc.get('volumes_encrypted', 0))
        
        features['mdm_deployed'] = safe_bool_to_int(ep_sec.get('mdm', {}).get('deployed'))
        features['usb_controls'] = safe_bool_to_int(ep_sec.get('usb_controls', {}).get('enabled'))
        features['app_whitelisting'] = safe_bool_to_int(ep_sec.get('application_whitelisting', {}).get('enabled'))
        
        # Secure Configuration
        sec_conf = record.get('secure_configuration', {})
        features['secure_config_applied'] = safe_bool_to_int(sec_conf.get('applied'))
        features['secure_config_checks'] = len(sec_conf.get('checks', []))
        
        # Anti-Exploitation
        anti_exp = record.get('anti_exploitation', {})
        features['anti_exploit_enabled'] = safe_bool_to_int(anti_exp.get('enabled'))
        features['anti_exploit_features'] = len(anti_exp.get('features', []))
        
        # Vulnerability Management
        vuln = record.get('vulnerability_management', {})
        features['vuln_auto_scan'] = safe_bool_to_int(vuln.get('automated_scanning', {}).get('enabled'))
        features['vuln_auth_scan'] = safe_bool_to_int(vuln.get('authenticated_scanning', {}).get('enabled'))
        features['vuln_accounts_protected'] = safe_bool_to_int(vuln.get('assessment_accounts', {}).get('protected'))
        features['vuln_assessment_days'] = safe_numeric(vuln.get('assessment', {}).get('last_days', 999))
        features['vuln_pentest_days'] = safe_numeric(vuln.get('penetration_test', {}).get('last_days', 999))
        features['vuln_critical_patch_72h'] = safe_bool_to_int(vuln.get('critical_patching', {}).get('within_72_hours'))
        
        # Patch Management
        patch = record.get('patch_management', {})
        auto_patch = patch.get('automated_patching', {})
        features['patch_automated'] = safe_bool_to_int(auto_patch.get('enabled'))
        features['patch_os'] = safe_bool_to_int(auto_patch.get('os'))
        features['patch_apps'] = safe_bool_to_int(auto_patch.get('applications'))
        features['patch_sw_enabled'] = safe_bool_to_int(patch.get('software_patching', {}).get('enabled'))
        
        # Logging & SIEM
        log = record.get('logging', {}).get('logging', {})
        features['log_central'] = safe_bool_to_int(log.get('central_management', {}).get('enabled'))
        features['log_audit'] = safe_bool_to_int(log.get('audit', {}).get('enabled'))
        features['log_retention_days'] = safe_numeric(log.get('storage', {}).get('retention_days', 0))
        features['log_analysis_central'] = safe_bool_to_int(log.get('analysis', {}).get('central'))
        
        siem = record.get('logging', {}).get('siem', {})
        features['siem_deployed'] = safe_bool_to_int(siem.get('deployed'))
        features['siem_tuning'] = safe_bool_to_int(siem.get('tuning', {}).get('regular'))
        
        sec_mon = record.get('logging', {}).get('security_monitoring', {})
        soc = sec_mon.get('soc', {})
        features['soc_operational'] = safe_bool_to_int(soc.get('operational'))
        features['soc_24x7'] = safe_bool_to_int(soc.get('staffing') == '24x7' if soc.get('staffing') else False)
        features['sec_mon_realtime'] = safe_bool_to_int(sec_mon.get('realtime', {}).get('enabled'))
        features['sec_mon_auto_response'] = safe_bool_to_int(sec_mon.get('automated_response', {}).get('enabled'))
        
        # Application Security
        app_sec = record.get('application_security', {})
        features['sdlc_implemented'] = safe_bool_to_int(app_sec.get('sdlc', {}).get('implemented'))
        features['sast_enabled'] = safe_bool_to_int(app_sec.get('sast', {}).get('enabled'))
        features['dast_enabled'] = safe_bool_to_int(app_sec.get('dast', {}).get('enabled'))
        features['code_review_mandatory'] = safe_bool_to_int(app_sec.get('code_review', {}).get('mandatory'))
        features['waf_deployed'] = safe_bool_to_int(app_sec.get('waf', {}).get('deployed'))
        
        # Backup & Recovery
        backup = record.get('backup', {}).get('backup', {})
        auto_backup = backup.get('automated', {})
        features['backup_automated'] = safe_bool_to_int(auto_backup.get('enabled'))
        features['backup_complete_system'] = safe_bool_to_int(backup.get('complete_system', {}).get('enabled'))
        features['backup_testing'] = safe_bool_to_int(backup.get('testing', {}).get('regular'))
        features['backup_encrypted'] = safe_bool_to_int(backup.get('protection', {}).get('encryption'))
        features['backup_offline'] = safe_bool_to_int(backup.get('offline', {}).get('available'))
        
        bc = record.get('backup', {}).get('business_continuity', {})
        features['bc_plan'] = safe_bool_to_int(bc.get('plan', {}).get('exists'))
        features['dr_plan'] = safe_bool_to_int(bc.get('disaster_recovery', {}).get('plan_exists'))
        features['rto_defined'] = safe_bool_to_int(bc.get('rto', {}).get('defined'))
        features['rpo_defined'] = safe_bool_to_int(bc.get('rpo', {}).get('defined'))
        
        # Access Control
        ac = record.get('access_control', {}).get('access_control', {})
        features['ac_policy'] = safe_bool_to_int(ac.get('policy', {}).get('exists'))
        features['pam_deployed'] = safe_bool_to_int(ac.get('pam_system', {}).get('deployed'))
        features['session_recording'] = safe_bool_to_int(ac.get('session_recording', {}).get('enabled'))
        features['rights_review_days'] = safe_numeric(ac.get('rights_review', {}).get('last_days', 999))
        
        users = record.get('access_control', {}).get('users', {})
        features['user_reg_formal'] = safe_bool_to_int(users.get('registration_process', {}).get('formal'))
        features['access_controlled'] = safe_bool_to_int(users.get('access_provisioning', {}).get('controlled'))
        features['priv_access_managed'] = safe_bool_to_int(users.get('privileged_access', {}).get('managed'))
        features['admin_count'] = safe_numeric(users.get('privileged_access', {}).get('admin_count', 0))
        features['access_review_regular'] = safe_bool_to_int(users.get('access_review', {}).get('regular'))
        
        sys = record.get('access_control', {}).get('systems', {})
        pw = sys.get('password_management', {})
        features['pw_robust'] = safe_bool_to_int(pw.get('robust'))
        features['pw_min_length'] = safe_numeric(pw.get('min_length', 0))
        features['pw_complexity'] = safe_bool_to_int(pw.get('complexity'))
        features['pw_max_age'] = safe_numeric(pw.get('max_age', 999))
        
        # Cryptography
        crypto = record.get('cryptography', {}).get('cryptography', {})
        features['crypto_policy'] = safe_bool_to_int(crypto.get('policy', {}).get('exists'))
        features['key_mgmt'] = safe_bool_to_int(crypto.get('key_management', {}).get('implemented'))
        tls = crypto.get('tls_protocols', [])
        features['tls_modern'] = safe_bool_to_int('TLSv1.3' in tls if isinstance(tls, list) else False)
        
        data_prot = record.get('cryptography', {}).get('data_protection', {})
        cust = data_prot.get('customer_data', {})
        features['data_encrypted_rest'] = safe_bool_to_int(cust.get('encrypted_at_rest'))
        features['data_encrypted_transit'] = safe_bool_to_int(cust.get('encrypted_in_transit'))
        features['db_monitoring'] = safe_bool_to_int(data_prot.get('database_monitoring', {}).get('enabled'))
        features['data_masking'] = safe_bool_to_int(data_prot.get('data_masking', {}).get('non_production'))
        
        # Physical Security
        phys = record.get('physical', {}).get('physical', {})
        features['phys_perimeter'] = safe_bool_to_int(phys.get('security_perimeter', {}).get('defined'))
        features['phys_entry_controls'] = safe_bool_to_int(phys.get('entry_controls', {}).get('implemented'))
        features['phys_env_protection'] = safe_bool_to_int(phys.get('environmental_protection', {}).get('implemented'))
        
        # HR & Training
        hr = record.get('hr', {}).get('hr', {})
        features['hr_background_check'] = safe_bool_to_int(hr.get('background_screening', {}).get('mandatory'))
        features['hr_security_clauses'] = safe_bool_to_int(hr.get('employment_terms', {}).get('security_clauses'))
        
        train = record.get('hr', {}).get('training', {})
        features['training_awareness'] = safe_bool_to_int(train.get('security_awareness', {}).get('regular'))
        features['training_cyber_annual'] = safe_bool_to_int(train.get('cybersecurity', {}).get('annual'))
        features['training_phishing'] = safe_bool_to_int(train.get('phishing_simulation', {}).get('regular'))
        features['training_metrics'] = safe_bool_to_int(train.get('awareness_metrics', {}).get('tracked'))
        
        # Governance
        gov = record.get('operations', {}).get('governance', {})
        features['board_policy'] = safe_bool_to_int(gov.get('board_approved_policy', {}).get('exists'))
        features['security_strategy'] = safe_bool_to_int(gov.get('security_strategy', {}).get('documented'))
        features['ciso_appointed'] = safe_bool_to_int(gov.get('ciso', {}).get('appointed'))
        features['security_committee'] = safe_bool_to_int(gov.get('security_committee', {}).get('established'))
        
        ops = record.get('operations', {}).get('operations', {})
        features['ops_procedures'] = safe_bool_to_int(ops.get('procedures', {}).get('documented'))
        features['change_mgmt'] = safe_bool_to_int(ops.get('change_management', {}).get('implemented'))
        features['env_separation'] = safe_bool_to_int(ops.get('environment_separation', {}).get('implemented'))
        
        # Incident Response & Compliance
        features['ir_plan'] = safe_bool_to_int(record.get('plan', {}).get('exists', False))
        features['ir_team'] = safe_bool_to_int(record.get('team', {}).get('established', False))
        features['rbi_reporting'] = safe_bool_to_int(record.get('rbi_reporting', {}).get('within_2_hours', False))
        features['forensics'] = safe_bool_to_int(record.get('forensics', {}).get('capability', False))
        features['risk_assessment'] = safe_bool_to_int(record.get('risk_assessment', {}).get('conducted', False))
        features['continuous_monitoring'] = safe_bool_to_int(record.get('continuous_monitoring', {}).get('enabled', False))
        features['audit_rights'] = safe_bool_to_int(record.get('audit_rights', {}).get('established', False))
        
        return features


class ComplianceTrainer:
    """Main training orchestrator for compliance models."""
    
    def __init__(
        self,
        model_type: str = 'rf',
        test_size: float = 0.2,
        cv_folds: int = 5,
        random_state: int = 42
    ):
        """
        Initialize trainer.
        
        Args:
            model_type: Type of model (rf, gb, lr, lgbm)
            test_size: Proportion of data for testing
            cv_folds: Number of cross-validation folds
            random_state: Random seed for reproducibility
        """
        self.model_type = model_type
        self.test_size = test_size
        self.cv_folds = cv_folds
        self.random_state = random_state
        
        self.logger = logging.getLogger("ComplianceAI.Trainer")
        self.feature_extractor = FeatureExtractor()
        self.label_encoder = LabelEncoder()
        self.scaler = StandardScaler()
        self.imputer = SimpleImputer(strategy='constant', fill_value=0)
        
        self.model = None
        self.feature_names = []
        self.feature_importance = {}
    
    def _get_model(self):
        """Initialize model based on type."""
        if self.model_type == 'rf':
            return RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=self.random_state,
                n_jobs=-1,
                class_weight='balanced'
            )
        elif self.model_type == 'gb':
            return GradientBoostingClassifier(
                n_estimators=100,
                learning_rate=0.1,
                max_depth=5,
                random_state=self.random_state
            )
        elif self.model_type == 'lr':
            return LogisticRegression(
                random_state=self.random_state,
                max_iter=1000,
                class_weight='balanced'
            )
        elif self.model_type == 'lgbm':
            try:
                import lightgbm as lgb
                return lgb.LGBMClassifier(
                    n_estimators=200,
                    learning_rate=0.05,
                    max_depth=10,
                    random_state=self.random_state,
                    n_jobs=-1
                )
            except ImportError:
                self.logger.warning("LightGBM not installed, falling back to RandomForest")
                return self._get_model_fallback()
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    def _get_model_fallback(self):
        """Fallback to RandomForest if preferred model unavailable."""
        return RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            random_state=self.random_state,
            n_jobs=-1
        )
    
    def _load_data(self, data_path: Path) -> Tuple[List[Dict], List[str]]:
        """
        Load training data from JSON files.
        
        Args:
            data_path: Path to JSON file or directory
        
        Returns:
            Tuple of (feature records, labels)
        """
        json_files = []
        
        if data_path.is_file():
            json_files = [data_path]
        elif data_path.is_dir():
            json_files = sorted(data_path.glob('*.json'))
        else:
            raise ValueError(f"Invalid data path: {data_path}")
        
        if not json_files:
            raise ValueError(f"No JSON files found in {data_path}")
        
        self.logger.info(f"Found {len(json_files)} JSON files")
        
        all_records = []
        all_labels = []
        
        progress = ProgressTracker(len(json_files), "Loading data files")
        
        for json_file in json_files:
            payload = load_json_file(json_file)
            if not payload:
                continue
            
            records = extract_records_from_payload(payload)
            
            for rec in records:
                if not validate_compliance_record(rec):
                    continue
                
                # Extract features
                features = self.feature_extractor.extract_features(rec)
                
                # Derive label
                label = rec.get('compliance_status')
                if label is None:
                    score = rec.get('compliance_score')
                    try:
                        score_val = float(score) if score is not None else None
                    except:
                        score_val = None
                    
                    if score_val is not None:
                        label = 'Compliant' if score_val >= 70 else 'Non-Compliant'
                    else:
                        label = 'Unknown'
                
                all_records.append(features)
                all_labels.append(label)
            
            progress.update()
        
        progress.complete()
        self.logger.info(f"Loaded {len(all_records)} training records")
        
        return all_records, all_labels
    
    def train(
        self,
        data_path: Path,
        output_dir: Path,
        model_name: str = "compliance_model"
    ) -> bool:
        """
        Train compliance prediction model.
        
        Args:
            data_path: Path to training data
            output_dir: Directory for model output
            model_name: Name for saved model
        
        Returns:
            True if training successful
        """
        try:
            # Load data
            records, labels = self._load_data(data_path)
            
            if len(records) == 0:
                self.logger.error("No valid records found for training")
                return False
            
            # Convert to DataFrame
            df = pd.DataFrame(records)
            
            # Handle categorical variables
            if 'company_type' in df.columns:
                df = pd.get_dummies(df, columns=['company_type'], prefix='company')
            
            self.feature_names = list(df.columns)
            self.logger.info(f"Extracted {len(self.feature_names)} features")
            
            # Encode labels
            y_encoded = self.label_encoder.fit_transform(labels)
            classes = list(self.label_encoder.classes_)
            self.logger.info(f"Classes: {classes}")
            
            # Train/test split
            if len(df) < 10:
                self.logger.warning(f"Limited data ({len(df)} samples), training without test split")
                X_train, y_train = df, y_encoded
                X_test, y_test = df, y_encoded
                actual_test_size = 0
            else:
                try:
                    X_train, X_test, y_train, y_test = train_test_split(
                        df, y_encoded,
                        test_size=self.test_size,
                        random_state=self.random_state,
                        stratify=y_encoded
                    )
                    actual_test_size = self.test_size
                except:
                    X_train, X_test, y_train, y_test = train_test_split(
                        df, y_encoded,
                        test_size=self.test_size,
                        random_state=self.random_state
                    )
                    actual_test_size = self.test_size
            
            self.logger.info(f"Training: {len(X_train)} samples, Test: {len(X_test)} samples")
            
            # Preprocessing
            X_train_imp = self.imputer.fit_transform(X_train)
            X_test_imp = self.imputer.transform(X_test)
            
            X_train_scaled = self.scaler.fit_transform(X_train_imp)
            X_test_scaled = self.scaler.transform(X_test_imp)
            
            # Train model
            self.logger.info(f"Training {self.model_type.upper()} model...")
            self.model = self._get_model()
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate
            y_pred = self.model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            
            metrics = {
                'accuracy': float(accuracy),
                'test_size': actual_test_size,
                'n_train': len(X_train),
                'n_test': len(X_test),
                'classes': classes,
                'model_type': self.model_type
            }
            
            if len(X_test) > 0:
                metrics['precision'] = float(precision_score(y_test, y_pred, average='weighted', zero_division=0))
                metrics['recall'] = float(recall_score(y_test, y_pred, average='weighted', zero_division=0))
                metrics['f1_score'] = float(f1_score(y_test, y_pred, average='weighted', zero_division=0))
                metrics['confusion_matrix'] = confusion_matrix(y_test, y_pred).tolist()
                metrics['classification_report'] = classification_report(
                    y_test, y_pred,
                    target_names=classes,
                    zero_division=0
                )
            
            # Feature importance
            if hasattr(self.model, 'feature_importances_'):
                importances = self.model.feature_importances_
                self.feature_importance = dict(zip(self.feature_names, importances))
                top_features = sorted(self.feature_importance.items(), key=lambda x: x[1], reverse=True)[:20]
                metrics['top_20_features'] = {k: float(v) for k, v in top_features}
            
            # Cross-validation
            if len(X_train) >= self.cv_folds:
                cv_scores = cross_val_score(
                    self.model, X_train_scaled, y_train,
                    cv=self.cv_folds,
                    scoring='accuracy'
                )
                metrics['cv_accuracy_mean'] = float(np.mean(cv_scores))
                metrics['cv_accuracy_std'] = float(np.std(cv_scores))
            
            self.logger.info(f"✓ Training complete - Accuracy: {accuracy:.4f}")
            
            # Save model
            self._save_model(output_dir, model_name, metrics)
            
            return True
            
        except Exception as e:
            self.logger.exception(f"Training failed: {e}")
            return False
    
    def _save_model(self, output_dir: Path, model_name: str, metrics: Dict) -> None:
        """Save trained model bundle."""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        bundle = {
            'model': self.model,
            'label_encoder': self.label_encoder,
            'scaler': self.scaler,
            'imputer': self.imputer,
            'feature_names': self.feature_names,
            'feature_importance': self.feature_importance,
            'metrics': metrics,
            'model_type': self.model_type,
            'training_date': datetime.now().isoformat()
        }
        
        model_path = output_dir / f"{model_name}.joblib"
        dump(bundle, model_path)
        self.logger.info(f"💾 Model saved: {model_path}")
        
        # Save summary
        summary = {
            'model_name': model_name,
            'model_type': self.model_type,
            'n_features': len(self.feature_names),
            'metrics': metrics,
            'training_date': datetime.now().isoformat()
        }
        
        summary_path = output_dir / f"{model_name}_summary.json"
        save_json_file(summary, summary_path)
        self.logger.info(f"📊 Summary saved: {summary_path}")