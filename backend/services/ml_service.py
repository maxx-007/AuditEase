"""
ML Service Module - FIXED PRODUCTION VERSION
=============================================
Handles small datasets, proper validation, and robust training.
"""

from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import json
import yaml
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
import joblib
from utils.logger import setup_logger

logger = setup_logger("ml_service")


class ModelRegistry:
    """Manages model versioning and metadata."""
    
    def __init__(self, registry_path: Path):
        """Initialize model registry."""
        self.registry_path = registry_path
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self._load_registry()
    
    def _load_registry(self):
        """Load existing registry or create new one."""
        if self.registry_path.exists():
            with open(self.registry_path) as f:
                self.registry = json.load(f)
        else:
            self.registry = {
                "models": {},
                "active_model": None,
                "version_counter": 0
            }
            self._save_registry()
    
    def _save_registry(self):
        """Save registry to file."""
        with open(self.registry_path, 'w') as f:
            json.dump(self.registry, f, indent=2)
    
    def register_model(
        self, 
        model_path: str, 
        metadata: Dict[str, Any]
    ) -> str:
        """Register a new model version."""
        version_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        self.registry["models"][version_id] = {
            "path": model_path,
            "metadata": metadata,
            "registered_at": datetime.now().isoformat()
        }
        
        # Set as active model
        if (self.registry["active_model"] is None or 
            metadata.get("accuracy", 0) > 
            self.registry["models"].get(self.registry.get("active_model", ""), {}).get("metadata", {}).get("accuracy", 0)):
            self.registry["active_model"] = version_id
        
        self._save_registry()
        logger.info(f"✓ Registered model {version_id}")
        
        return version_id
    
    def get_active_model(self) -> Optional[Dict[str, Any]]:
        """Get currently active model."""
        if self.registry["active_model"]:
            return self.registry["models"][self.registry["active_model"]]
        return None


class FeatureEngineering:
    """Handles feature extraction and engineering."""
    
    @staticmethod
    def extract_features(record: Dict[str, Any]) -> Dict[str, Any]:
        """Extract ML features from compliance record."""
        features = {}
        
        # Network features
        network = record.get("network", {})
        features.update({
            "network_firewall": FeatureEngineering._safe_bool(
                network.get("network", {}).get("perimeter", {}).get("filtering_configured")
            ),
            "network_segmentation": FeatureEngineering._safe_bool(
                network.get("network_security", {}).get("segmentation", {}).get("implemented")
            ),
            "network_ids": FeatureEngineering._safe_bool(
                network.get("network_security", {}).get("ids", {}).get("deployed")
            ),
            "network_ips": FeatureEngineering._safe_bool(
                network.get("network_security", {}).get("ips", {}).get("deployed")
            ),
        })
        
        # Endpoint features
        endpoint = record.get("endpoint_security", {})
        features.update({
            "edr_deployed": FeatureEngineering._safe_bool(
                endpoint.get("edr", {}).get("deployed")
            ),
            "encryption_enabled": FeatureEngineering._safe_bool(
                endpoint.get("encryption", {}).get("enabled")
            ),
            "mdm_deployed": FeatureEngineering._safe_bool(
                endpoint.get("mdm", {}).get("deployed")
            ),
        })
        
        # Antimalware features
        antimalware = record.get("antimalware", {})
        features.update({
            "antimalware_deployed": FeatureEngineering._safe_bool(
                antimalware.get("deployed")
            ),
            "antimalware_managed": FeatureEngineering._safe_bool(
                antimalware.get("centrally_managed")
            ),
            "antimalware_updated": FeatureEngineering._safe_bool(
                antimalware.get("auto_update", {}).get("enabled")
            ),
        })
        
        # Vulnerability management
        vuln_mgmt = record.get("vulnerability_management", {})
        features.update({
            "vuln_scanning": FeatureEngineering._safe_bool(
                vuln_mgmt.get("automated_scanning", {}).get("enabled")
            ),
            "critical_patching": FeatureEngineering._safe_bool(
                vuln_mgmt.get("critical_patching", {}).get("within_72_hours")
            ),
        })
        
        # Patch management
        patch_mgmt = record.get("patch_management", {})
        features.update({
            "auto_patching": FeatureEngineering._safe_bool(
                patch_mgmt.get("automated_patching", {}).get("enabled")
            ),
            "os_patching": FeatureEngineering._safe_bool(
                patch_mgmt.get("automated_patching", {}).get("os")
            ),
            "app_patching": FeatureEngineering._safe_bool(
                patch_mgmt.get("automated_patching", {}).get("applications")
            ),
        })
        
        # Logging
        logging_data = record.get("logging", {}).get("logging", {})
        features.update({
            "central_logging": FeatureEngineering._safe_bool(
                logging_data.get("central_management", {}).get("enabled")
            ),
            "audit_logging": FeatureEngineering._safe_bool(
                logging_data.get("audit", {}).get("enabled")
            ),
            "siem_deployed": FeatureEngineering._safe_bool(
                record.get("logging", {}).get("siem", {}).get("deployed")
            ),
        })
        
        # Backup
        backup = record.get("backup", {}).get("backup", {})
        features.update({
            "backup_automated": FeatureEngineering._safe_bool(
                backup.get("automated", {}).get("enabled")
            ),
            "backup_tested": FeatureEngineering._safe_bool(
                backup.get("testing", {}).get("regular")
            ),
            "backup_encrypted": FeatureEngineering._safe_bool(
                backup.get("protection", {}).get("encryption")
            ),
        })
        
        # Access control
        access_ctrl = record.get("access_control", {}).get("access_control", {})
        features.update({
            "pam_deployed": FeatureEngineering._safe_bool(
                access_ctrl.get("pam_system", {}).get("deployed")
            ),
            "mfa_enabled": FeatureEngineering._safe_bool(
                access_ctrl.get("privileged_users", {}).get("privileged_users")
            ),
            "password_robust": FeatureEngineering._safe_bool(
                record.get("access_control", {}).get("systems", {}).get("password_management", {}).get("robust")
            ),
        })
        
        # Cryptography
        crypto = record.get("cryptography", {})
        features.update({
            "data_encrypted_rest": FeatureEngineering._safe_bool(
                crypto.get("data_protection", {}).get("customer_data", {}).get("encrypted_at_rest")
            ),
            "data_encrypted_transit": FeatureEngineering._safe_bool(
                crypto.get("data_protection", {}).get("customer_data", {}).get("encrypted_in_transit")
            ),
            "key_management": FeatureEngineering._safe_bool(
                crypto.get("cryptography", {}).get("key_management", {}).get("implemented")
            ),
        })
        
        # Application security
        app_sec = record.get("application_security", {})
        features.update({
            "sdlc_implemented": FeatureEngineering._safe_bool(
                app_sec.get("sdlc", {}).get("implemented")
            ),
            "sast_enabled": FeatureEngineering._safe_bool(
                app_sec.get("sast", {}).get("enabled")
            ),
            "dast_enabled": FeatureEngineering._safe_bool(
                app_sec.get("dast", {}).get("enabled")
            ),
            "waf_deployed": FeatureEngineering._safe_bool(
                app_sec.get("waf", {}).get("deployed")
            ),
        })
        
        # Governance
        governance = record.get("operations", {}).get("governance", {})
        features.update({
            "security_policy": FeatureEngineering._safe_bool(
                governance.get("board_approved_policy", {}).get("exists")
            ),
            "ciso_appointed": FeatureEngineering._safe_bool(
                governance.get("ciso", {}).get("appointed")
            ),
            "security_committee": FeatureEngineering._safe_bool(
                governance.get("security_committee", {}).get("established")
            ),
        })
        
        # HR and training
        hr = record.get("hr", {}).get("hr", {})
        training = record.get("hr", {}).get("training", {})
        features.update({
            "background_checks": FeatureEngineering._safe_bool(
                hr.get("background_screening", {}).get("mandatory")
            ),
            "security_training": FeatureEngineering._safe_bool(
                training.get("security_awareness", {}).get("regular")
            ),
            "phishing_simulation": FeatureEngineering._safe_bool(
                training.get("phishing_simulation", {}).get("regular")
            ),
        })
        
        # Incident response
        incident = record.get("plan", {}) if isinstance(record.get("plan"), dict) else {}
        features.update({
            "incident_plan": FeatureEngineering._safe_bool(
                incident.get("exists") if isinstance(incident, dict) else record.get("plan")
            ),
            "incident_team": FeatureEngineering._safe_bool(
                record.get("team", {}).get("established") if isinstance(record.get("team"), dict) else record.get("team")
            ),
        })
        
        # Company type
        features["company_type"] = record.get("company_type", "Unknown")
        
        return features
    
    @staticmethod
    def _safe_bool(value: Any) -> int:
        """Safely convert value to boolean int."""
        if isinstance(value, bool):
            return 1 if value else 0
        if isinstance(value, (int, float)):
            return 1 if value > 0 else 0
        if isinstance(value, str):
            return 1 if value.lower() in ['true', 'yes', 'enabled'] else 0
        return 0


class MLService:
    """Main ML service orchestrator - FIXED VERSION."""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize ML service."""
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        
        self.models_dir = Path(self.config['paths']['models_dir'])
        self.models_dir.mkdir(exist_ok=True)
        
        self.registry = ModelRegistry(
            self.models_dir / "model_registry.json"
        )
        
        self.feature_engineering = FeatureEngineering()
    
    def train_model(
        self, 
        dataset_path: Path,
        algorithm: str = "RandomForest"
    ) -> Dict[str, Any]:
        """
        Train compliance prediction model - FIXED for small datasets.
        """
        logger.info(f"🚀 Starting ML training with {algorithm} algorithm")
        logger.info(f"📁 Dataset: {dataset_path}")
        
        # Load dataset
        with open(dataset_path) as f:
            raw_data = json.load(f)
        
        # Handle different data formats
        if isinstance(raw_data, dict):
            if "records" in raw_data:
                records = raw_data["records"]
            else:
                # Single record - wrap in list
                records = [raw_data]
        elif isinstance(raw_data, list):
            records = raw_data
        else:
            records = [raw_data]
        
        logger.info(f"📊 Loaded {len(records)} training record(s)")
        
        # CRITICAL FIX: Need minimum 3 samples for meaningful training
        if len(records) < 3:
            logger.warning(f"⚠️  Dataset too small ({len(records)} samples)")
            logger.warning("⚠️  Recommendation: Combine all 3 datasets or generate more synthetic data")
            logger.info("📌 Training basic model for inference purposes only")
        
        # Extract features and labels
        feature_list = []
        labels = []
        
        for record in records:
            features = self.feature_engineering.extract_features(record)
            feature_list.append(features)
            
            # Extract label - handle multiple possible fields
            status = record.get("compliance_status")
            if status is None:
                # Infer from score if available
                score = record.get("compliance_score", 50)
                status = "Compliant" if score >= 80 else "Non-Compliant"
            labels.append(status)
        
        # Convert to DataFrame
        df = pd.DataFrame(feature_list)
        
        # Handle categorical encoding
        if "company_type" in df.columns:
            df = pd.get_dummies(df, columns=["company_type"], prefix="company")
        
        # Prepare labels
        label_encoder = LabelEncoder()
        y = label_encoder.fit_transform(labels)
        
        logger.info(f"✓ Feature extraction complete: {df.shape[1]} features")
        logger.info(f"✓ Classes: {label_encoder.classes_.tolist()}")
        logger.info(f"✓ Class distribution: {dict(zip(*np.unique(labels, return_counts=True)))}")
        
        # Handle missing values
        imputer = SimpleImputer(strategy='median')
        X_imp = imputer.fit_transform(df)
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_imp)
        
        # Train model - handle small datasets
        if len(records) < 5:
            # TOO SMALL: Train on full dataset without split
            logger.warning("Limited data, training without test split")
            X_train = X_scaled
            y_train = y
            X_test = X_scaled
            y_test = y
        else:
            # NORMAL: Use train-test split
            ml_config = self.config['ml']['train']
            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y,
                test_size=ml_config['test_size'],
                random_state=ml_config['random_state'],
                stratify=y if len(np.unique(y)) > 1 else None
            )
        
        # Initialize model
        if algorithm == "RandomForest":
            model = RandomForestClassifier(
                n_estimators=min(50, len(records) * 10),  # Adaptive
                max_depth=min(5, len(records)),
                random_state=42,
                n_jobs=-1
            )
        elif algorithm == "GradientBoosting":
            model = GradientBoostingClassifier(
                n_estimators=min(50, len(records) * 10),
                max_depth=min(3, len(records)),
                random_state=42
            )
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Train
        logger.info(f"🎯 Training {algorithm} model...")
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        
        # Handle single-class case
        if len(np.unique(y_test)) == 1:
            logger.warning("⚠️  Only one class in test set - metrics may be limited")
            metrics = {
                "accuracy": float(accuracy_score(y_test, y_pred)),
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0
            }
        else:
            metrics = {
                "accuracy": float(accuracy_score(y_test, y_pred)),
                "precision": float(precision_score(y_test, y_pred, average='weighted', zero_division=0)),
                "recall": float(recall_score(y_test, y_pred, average='weighted', zero_division=0)),
                "f1_score": float(f1_score(y_test, y_pred, average='weighted', zero_division=0))
            }
        
        # Cross-validation (only if enough samples)
        if len(records) >= 5 and len(np.unique(y)) > 1:
            cv_folds = min(3, len(records) // 2)
            cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
            cv_scores = cross_val_score(model, X_train, y_train, cv=cv, scoring='accuracy')
        else:
            cv_scores = np.array([metrics['accuracy']])
        
        logger.info(f"✅ Model trained successfully")
        logger.info(f"📊 Accuracy: {metrics['accuracy']:.4f}")
        
        # Save model
        model_filename = f"compliance_model_{algorithm}.joblib"
        model_path = self.models_dir / model_filename
        
        model_bundle = {
            "model": model,
            "scaler": scaler,
            "imputer": imputer,
            "label_encoder": label_encoder,
            "feature_names": list(df.columns),
            "model_type": algorithm,
            "training_date": datetime.now().isoformat(),
            "metrics": metrics,
            "n_samples": len(records)
        }
        
        joblib.dump(model_bundle, model_path)
        logger.info(f"💾 Model saved: {model_path}")
        
        # Register model
        metadata = {
            "algorithm": algorithm,
            "dataset": str(dataset_path),
            "n_samples": len(records),
            "n_features": df.shape[1],
            "metrics": metrics,
            "cv_mean": float(cv_scores.mean()),
            "cv_std": float(cv_scores.std()),
            "classes": label_encoder.classes_.tolist()
        }
        
        version_id = self.registry.register_model(str(model_path), metadata)
        
        return {
            "success": True,
            "version_id": version_id,
            "model_path": str(model_path),
            "metrics": metrics,
            "cv_scores": {
                "mean": float(cv_scores.mean()),
                "std": float(cv_scores.std()),
                "scores": cv_scores.tolist()
            },
            "training_summary": {
                "algorithm": algorithm,
                "n_samples": len(records),
                "n_features": df.shape[1],
                "classes": label_encoder.classes_.tolist()
            }
        }
    
    def predict(
        self, 
        data: Dict[str, Any],
        model_version: Optional[str] = None
    ) -> Dict[str, Any]:
        """Make compliance prediction."""
        # Load model
        if model_version:
            model_info = self.registry.registry["models"].get(model_version)
        else:
            model_info = self.registry.get_active_model()
        
        if not model_info:
            raise ValueError("No model available for inference")
        
        model_bundle = joblib.load(model_info["path"])
        
        # Extract features
        features = self.feature_engineering.extract_features(data)
        df = pd.DataFrame([features])
        
        # Handle categorical encoding
        if "company_type" in df.columns:
            df = pd.get_dummies(df, columns=["company_type"], prefix="company")
        
        # Align with training features
        for col in model_bundle["feature_names"]:
            if col not in df.columns:
                df[col] = 0
        df = df[model_bundle["feature_names"]]
        
        # Preprocess
        X_imp = model_bundle["imputer"].transform(df)
        X_scaled = model_bundle["scaler"].transform(X_imp)
        
        # Predict
        prediction_idx = model_bundle["model"].predict(X_scaled)[0]
        prediction_label = model_bundle["label_encoder"].inverse_transform([prediction_idx])[0]
        
        # Get confidence
        if hasattr(model_bundle["model"], "predict_proba"):
            probabilities = model_bundle["model"].predict_proba(X_scaled)[0]
            confidence = float(np.max(probabilities) * 100)
            class_probabilities = {
                cls: float(prob * 100)
                for cls, prob in zip(model_bundle["label_encoder"].classes_, probabilities)
            }
        else:
            confidence = 50.0
            class_probabilities = {}
        
        return {
            "prediction": prediction_label,
            "confidence": confidence,
            "class_probabilities": class_probabilities,
            "model_version": model_version or self.registry.registry["active_model"],
            "model_type": model_bundle["model_type"],
            "timestamp": datetime.now().isoformat()
        }