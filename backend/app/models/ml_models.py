"""
ML Models Integration for IntelliGuard
Enhanced version of the existing high-performance models (96% accuracy)
"""

import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
import logging
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest
from sklearn.ensemble import IsolationForest
import warnings

from ..core.config import settings
from .data_models import AttackType, SeverityLevel, NetworkTrafficData

warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)


class IntelliGuardMLModels:
    """
    Enhanced ML Models for IntelliGuard
    Integrates the existing high-performance models with web API capabilities
    """
    
    def __init__(self):
        self.models = {}
        self.scaler = None
        self.feature_selector = None
        self.anomaly_detector = None
        self.model_performance = {}
        self.is_loaded = False
        self.model_version = settings.MODEL_VERSION
        
        # Attack type mapping
        self.attack_mapping = {
            0: AttackType.NORMAL,
            1: AttackType.DOS,
            2: AttackType.DDOS,
            3: AttackType.PORT_SCAN,
            4: AttackType.BOT,
            5: AttackType.INFILTRATION
        }
        
        # Severity mapping based on attack type and confidence
        self.severity_mapping = {
            AttackType.NORMAL: SeverityLevel.LOW,
            AttackType.DOS: SeverityLevel.HIGH,
            AttackType.DDOS: SeverityLevel.CRITICAL,
            AttackType.PORT_SCAN: SeverityLevel.MEDIUM,
            AttackType.BOT: SeverityLevel.HIGH,
            AttackType.INFILTRATION: SeverityLevel.CRITICAL,
            AttackType.ZERO_DAY: SeverityLevel.CRITICAL
        }
        
        # Load models on initialization
        self.load_models()
    
    def load_models(self) -> bool:
        """Load all trained models and preprocessors"""
        try:
            logger.info("Loading IntelliGuard ML models...")
            
            model_dir = os.path.join(settings.MODEL_DIR)
            
            # Model files mapping (using our existing high-performance models)
            model_files = {
                'Optimized XGBoost': 'optimized_xgboost_model.pkl',
                'Optimized Random Forest': 'optimized_random_forest_model.pkl',
                'Super Ensemble': 'super_ensemble_model.pkl',
                'Optimized Gradient Boosting': 'optimized_gradient_boosting_model.pkl',
                'Optimized SVM': 'optimized_svm_model.pkl',
                'Optimized Neural Network': 'optimized_neural_network_model.pkl'
            }
            
            # Load models if they exist, otherwise create placeholder
            for name, filename in model_files.items():
                filepath = os.path.join(model_dir, filename)
                if os.path.exists(filepath):
                    self.models[name] = joblib.load(filepath)
                    logger.info(f"✓ Loaded {name}")
                else:
                    logger.warning(f"⚠️  Model file not found: {filepath}")
            
            # Load preprocessors
            scaler_path = os.path.join(model_dir, 'scaler.pkl')
            selector_path = os.path.join(model_dir, 'feature_selector.pkl')
            
            if os.path.exists(scaler_path):
                self.scaler = joblib.load(scaler_path)
                logger.info("✓ Loaded feature scaler")
            
            if os.path.exists(selector_path):
                self.feature_selector = joblib.load(selector_path)
                logger.info("✓ Loaded feature selector")
            
            # Initialize anomaly detector for zero-day detection
            self.anomaly_detector = IsolationForest(
                contamination=0.1,
                n_estimators=200,
                random_state=42,
                n_jobs=-1
            )
            
            # Set model performance (from our existing results)
            self.model_performance = {
                'Optimized XGBoost': {
                    'accuracy': 0.9600, 'precision': 0.9553, 'recall': 0.9084, 
                    'f1_score': 0.9313, 'roc_auc': 0.9797
                },
                'Optimized Random Forest': {
                    'accuracy': 0.9593, 'precision': 0.9542, 'recall': 0.9073, 
                    'f1_score': 0.9301, 'roc_auc': 0.9794
                },
                'Super Ensemble': {
                    'accuracy': 0.9587, 'precision': 0.9530, 'recall': 0.9061, 
                    'f1_score': 0.9290, 'roc_auc': 0.9796
                }
            }
            
            self.is_loaded = len(self.models) > 0
            logger.info(f"Successfully loaded {len(self.models)} models!")
            
            return self.is_loaded
            
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
            return False
    
    def preprocess_data(self, data: List[NetworkTrafficData]) -> np.ndarray:
        """
        Preprocess network traffic data for prediction
        Enhanced version of our existing preprocessing
        """
        try:
            # Convert to DataFrame
            df = pd.DataFrame([item.dict() for item in data])
            
            # Feature engineering (same as our existing system)
            df['packet_byte_ratio'] = (df['flow_packets_per_sec'] + 1) / (df['flow_bytes_per_sec'] + 1)
            df['fwd_bwd_packet_ratio'] = (df['total_fwd_packets'] + 1) / (df['total_bwd_packets'] + 1)
            df['packet_size_ratio'] = (df['fwd_packet_length_mean'] + 1) / (df['bwd_packet_length_max'] + 1)
            df['iat_variation'] = df['flow_iat_std'] / (df['flow_iat_mean'] + 1)
            
            # Handle infinite and NaN values
            df = df.replace([np.inf, -np.inf], np.nan)
            df = df.fillna(df.median())
            
            # Apply feature selection if available
            if self.feature_selector:
                X_selected = self.feature_selector.transform(df)
            else:
                X_selected = df.values
            
            # Apply scaling if available
            if self.scaler:
                X_scaled = self.scaler.transform(X_selected)
            else:
                # Fallback scaling
                X_scaled = (X_selected - np.mean(X_selected, axis=0)) / (np.std(X_selected, axis=0) + 1e-8)
            
            return X_scaled
            
        except Exception as e:
            logger.error(f"Error in data preprocessing: {str(e)}")
            raise
    
    def predict_attack(self, data: List[NetworkTrafficData], model_name: str = 'Optimized XGBoost') -> List[Dict[str, Any]]:
        """
        Predict attacks using specified model
        """
        try:
            if not self.is_loaded:
                raise ValueError("Models not loaded")
            
            if model_name not in self.models:
                model_name = 'Optimized XGBoost'  # Fallback to best model
            
            # Preprocess data
            X_processed = self.preprocess_data(data)
            
            # Get model
            model = self.models[model_name]
            
            # Make predictions
            predictions = model.predict(X_processed)
            probabilities = model.predict_proba(X_processed) if hasattr(model, 'predict_proba') else None
            
            # Anomaly detection for zero-day attacks
            anomaly_scores = None
            if self.anomaly_detector:
                try:
                    # Train anomaly detector on current data (online learning)
                    self.anomaly_detector.fit(X_processed)
                    anomaly_predictions = self.anomaly_detector.predict(X_processed)
                    anomaly_scores = self.anomaly_detector.score_samples(X_processed)
                    # Normalize anomaly scores to 0-1 range
                    anomaly_scores = (anomaly_scores - anomaly_scores.min()) / (anomaly_scores.max() - anomaly_scores.min() + 1e-8)
                except Exception as e:
                    logger.warning(f"Anomaly detection failed: {str(e)}")
                    anomaly_scores = np.zeros(len(predictions))
            
            # Process results
            results = []
            for i, pred in enumerate(predictions):
                # Determine attack type
                if pred == 0:
                    attack_type = AttackType.NORMAL
                else:
                    attack_type = AttackType.DOS  # Simplified for binary classification
                
                # Get confidence score
                confidence = probabilities[i].max() if probabilities is not None else 0.8
                
                # Check for zero-day anomaly
                is_zero_day = False
                anomaly_score = 0.0
                if anomaly_scores is not None:
                    anomaly_score = float(anomaly_scores[i])
                    # High anomaly score indicates potential zero-day
                    if anomaly_score > 0.7 and pred == 1:
                        attack_type = AttackType.ZERO_DAY
                        is_zero_day = True
                
                # Determine severity
                severity = self.get_severity(attack_type, confidence, anomaly_score)
                
                results.append({
                    'attack_type': attack_type,
                    'confidence_score': float(confidence),
                    'severity_level': severity,
                    'anomaly_score': anomaly_score,
                    'is_zero_day': is_zero_day,
                    'model_used': model_name,
                    'timestamp': datetime.utcnow()
                })
            
            return results
            
        except Exception as e:
            logger.error(f"Error in attack prediction: {str(e)}")
            raise
    
    def predict_ensemble(self, data: List[NetworkTrafficData]) -> Dict[str, Any]:
        """
        Get ensemble predictions from multiple models
        Enhanced version of our existing ensemble method
        """
        try:
            if not self.is_loaded:
                raise ValueError("Models not loaded")
            
            X_processed = self.preprocess_data(data)
            
            all_predictions = {}
            attack_votes = 0
            total_confidence = 0
            model_count = 0
            
            # Get predictions from all available models
            for name, model in self.models.items():
                try:
                    pred = model.predict(X_processed)
                    prob = model.predict_proba(X_processed) if hasattr(model, 'predict_proba') else None
                    
                    all_predictions[name] = {
                        'predictions': pred,
                        'probabilities': prob
                    }
                    
                    # Count attack votes
                    attack_votes += np.sum(pred)
                    
                    if prob is not None:
                        total_confidence += np.mean(prob.max(axis=1))
                        model_count += 1
                        
                except Exception as e:
                    logger.warning(f"Error with model {name}: {str(e)}")
            
            # Ensemble decision
            total_samples = len(data)
            ensemble_predictions = []
            
            for i in range(total_samples):
                sample_votes = sum(
                    all_predictions[name]['predictions'][i] 
                    for name in all_predictions
                )
                
                # Majority voting
                is_attack = sample_votes > len(all_predictions) / 2
                
                # Average confidence
                confidences = []
                for name in all_predictions:
                    if all_predictions[name]['probabilities'] is not None:
                        confidences.append(all_predictions[name]['probabilities'][i].max())
                
                avg_confidence = np.mean(confidences) if confidences else 0.8
                
                attack_type = AttackType.DOS if is_attack else AttackType.NORMAL
                severity = self.get_severity(attack_type, avg_confidence)
                
                ensemble_predictions.append({
                    'attack_type': attack_type,
                    'confidence_score': float(avg_confidence),
                    'severity_level': severity,
                    'anomaly_score': 0.0,
                    'is_zero_day': False,
                    'model_used': 'Ensemble',
                    'timestamp': datetime.utcnow()
                })
            
            return {
                'predictions': ensemble_predictions,
                'ensemble_stats': {
                    'total_models': len(all_predictions),
                    'attack_votes': int(attack_votes),
                    'consensus_strength': attack_votes / (len(all_predictions) * total_samples) if all_predictions else 0,
                    'average_confidence': total_confidence / model_count if model_count > 0 else 0
                }
            }
            
        except Exception as e:
            logger.error(f"Error in ensemble prediction: {str(e)}")
            raise
    
    def get_severity(self, attack_type: AttackType, confidence: float, anomaly_score: float = 0.0) -> SeverityLevel:
        """
        Determine threat severity based on attack type, confidence, and anomaly score
        """
        base_severity = self.severity_mapping.get(attack_type, SeverityLevel.LOW)
        
        # Adjust severity based on confidence and anomaly score
        if attack_type == AttackType.NORMAL:
            return SeverityLevel.LOW
        
        # High confidence or high anomaly score increases severity
        if confidence > 0.9 or anomaly_score > 0.8:
            if base_severity == SeverityLevel.MEDIUM:
                return SeverityLevel.HIGH
            elif base_severity == SeverityLevel.HIGH:
                return SeverityLevel.CRITICAL
        
        # Low confidence decreases severity
        if confidence < 0.6 and anomaly_score < 0.3:
            if base_severity == SeverityLevel.CRITICAL:
                return SeverityLevel.HIGH
            elif base_severity == SeverityLevel.HIGH:
                return SeverityLevel.MEDIUM
        
        return base_severity
    
    def get_model_performance(self) -> Dict[str, Any]:
        """Get model performance metrics"""
        return self.model_performance
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get system status"""
        return {
            'models_loaded': self.is_loaded,
            'available_models': list(self.models.keys()),
            'model_version': self.model_version,
            'anomaly_detection_enabled': self.anomaly_detector is not None,
            'preprocessing_ready': self.scaler is not None and self.feature_selector is not None
        }


# Global model instance
ml_models = IntelliGuardMLModels()