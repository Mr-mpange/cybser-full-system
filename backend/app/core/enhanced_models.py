"""
Enhanced Machine Learning Models for Cyber Attack Detection
Optimized for higher accuracy and better performance
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest, GradientBoostingClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import GridSearchCV, cross_val_score
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                           f1_score, confusion_matrix, roc_auc_score, 
                           classification_report, roc_curve)
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif, RFE
from imblearn.over_sampling import SMOTE
from imblearn.combine import SMOTETomek
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os
import xgboost as xgb

class EnhancedCyberAttackDetector:
    """
    Enhanced machine learning system for cyber attack detection
    Optimized for maximum accuracy and performance
    """
    
    def __init__(self):
        self.models = {}
        self.results = {}
        self.feature_importance = {}
        self.best_params = {}
        self.feature_selector = None
        self.scaler = StandardScaler()
        
    def initialize_enhanced_models(self):
        """
        Initialize optimized machine learning models with better hyperparameters
        """
        print("Initializing enhanced machine learning models...")
        
        # Enhanced Supervised Learning Models with optimized parameters
        self.models = {
            'Enhanced Random Forest': RandomForestClassifier(
                n_estimators=200,
                max_depth=15,
                min_samples_split=5,
                min_samples_leaf=2,
                max_features='sqrt',
                bootstrap=True,
                random_state=42,
                n_jobs=-1,
                class_weight='balanced'
            ),
            'Enhanced SVM': SVC(
                kernel='rbf',
                C=10.0,
                gamma='scale',
                probability=True,
                random_state=42,
                class_weight='balanced'
            ),
            'Enhanced Logistic Regression': LogisticRegression(
                C=1.0,
                penalty='l2',
                solver='liblinear',
                random_state=42,
                max_iter=2000,
                class_weight='balanced'
            ),
            'Enhanced Neural Network': MLPClassifier(
                hidden_layer_sizes=(200, 100, 50),
                activation='relu',
                solver='adam',
                alpha=0.001,
                learning_rate='adaptive',
                max_iter=1000,
                random_state=42,
                early_stopping=True,
                validation_fraction=0.1
            ),
            'XGBoost': xgb.XGBClassifier(
                n_estimators=200,
                max_depth=8,
                learning_rate=0.1,
                subsample=0.8,
                colsample_bytree=0.8,
                random_state=42,
                eval_metric='logloss',
                use_label_encoder=False
            ),
            'Gradient Boosting': GradientBoostingClassifier(
                n_estimators=200,
                learning_rate=0.1,
                max_depth=8,
                min_samples_split=5,
                min_samples_leaf=2,
                subsample=0.8,
                random_state=42
            )
        }
        
        # Enhanced Unsupervised Model
        self.anomaly_detector = IsolationForest(
            contamination=0.15,  # Adjusted for better detection
            n_estimators=200,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        
        print("Enhanced models initialized successfully!")
        
    def apply_feature_engineering(self, X_train, X_test, y_train, feature_names):
        """
        Apply advanced feature engineering techniques
        
        Args:
            X_train: Training features
            X_test: Test features
            y_train: Training labels
            feature_names: List of feature names
            
        Returns:
            Enhanced feature sets
        """
        print("Applying advanced feature engineering...")
        
        # Convert to DataFrame for easier manipulation
        X_train_df = pd.DataFrame(X_train, columns=feature_names)
        X_test_df = pd.DataFrame(X_test, columns=feature_names)
        
        # Create interaction features for key network metrics
        network_features = [col for col in feature_names 
                          if any(keyword in col.lower() for keyword in 
                                ['packet', 'byte', 'flow', 'rate'])]
        
        if len(network_features) >= 2:
            # Packet rate to byte rate ratio
            if 'flow_packets_per_sec' in network_features and 'flow_bytes_per_sec' in network_features:
                X_train_df['packet_byte_ratio'] = (X_train_df['flow_packets_per_sec'] + 1) / (X_train_df['flow_bytes_per_sec'] + 1)
                X_test_df['packet_byte_ratio'] = (X_test_df['flow_packets_per_sec'] + 1) / (X_test_df['flow_bytes_per_sec'] + 1)
            
            # Forward to backward packet ratio
            fwd_cols = [col for col in network_features if 'fwd' in col.lower()]
            bwd_cols = [col for col in network_features if 'bwd' in col.lower()]
            
            if fwd_cols and bwd_cols:
                X_train_df['fwd_bwd_ratio'] = (X_train_df[fwd_cols[0]] + 1) / (X_train_df[bwd_cols[0]] + 1)
                X_test_df['fwd_bwd_ratio'] = (X_test_df[fwd_cols[0]] + 1) / (X_test_df[bwd_cols[0]] + 1)
        
        # Log transformation for skewed features
        skewed_features = []
        for col in X_train_df.columns:
            if X_train_df[col].dtype in ['float64', 'int64']:
                skewness = X_train_df[col].skew()
                if abs(skewness) > 2:  # Highly skewed
                    skewed_features.append(col)
        
        for col in skewed_features:
            X_train_df[f'{col}_log'] = np.log1p(X_train_df[col])
            X_test_df[f'{col}_log'] = np.log1p(X_test_df[col])
        
        # Handle any remaining NaN or infinite values
        X_train_df = X_train_df.replace([np.inf, -np.inf], np.nan)
        X_test_df = X_test_df.replace([np.inf, -np.inf], np.nan)
        
        # Fill NaN values with median
        X_train_df = X_train_df.fillna(X_train_df.median())
        X_test_df = X_test_df.fillna(X_train_df.median())  # Use training median for test
        
        # Feature selection using SelectKBest
        k_best = min(30, X_train_df.shape[1])  # Select top 30 features or all if less
        self.feature_selector = SelectKBest(score_func=f_classif, k=k_best)
        
        X_train_selected = self.feature_selector.fit_transform(X_train_df, y_train)
        X_test_selected = self.feature_selector.transform(X_test_df)
        
        # Get selected feature names
        selected_features = X_train_df.columns[self.feature_selector.get_support()].tolist()
        
        print(f"Feature engineering completed. Selected {len(selected_features)} features.")
        print(f"Top 10 selected features: {selected_features[:10]}")
        
        return X_train_selected, X_test_selected, selected_features
    
    def apply_data_balancing(self, X_train, y_train):
        """
        Apply advanced data balancing techniques
        
        Args:
            X_train: Training features
            y_train: Training labels
            
        Returns:
            Balanced training data
        """
        print("Applying data balancing techniques...")
        
        # Check class distribution
        unique, counts = np.unique(y_train, return_counts=True)
        print(f"Original class distribution: {dict(zip(unique, counts))}")
        
        # Apply SMOTE + Tomek links for better balancing
        smote_tomek = SMOTETomek(
            smote=SMOTE(random_state=42, k_neighbors=3),
            random_state=42
        )
        
        X_balanced, y_balanced = smote_tomek.fit_resample(X_train, y_train)
        
        # Check new distribution
        unique, counts = np.unique(y_balanced, return_counts=True)
        print(f"Balanced class distribution: {dict(zip(unique, counts))}")
        
        return X_balanced, y_balanced
    
    def hyperparameter_tuning(self, X_train, y_train):
        """
        Perform hyperparameter tuning for key models
        
        Args:
            X_train: Training features
            y_train: Training labels
        """
        print("Performing hyperparameter tuning...")
        
        # Random Forest tuning
        rf_params = {
            'n_estimators': [150, 200, 250],
            'max_depth': [12, 15, 18],
            'min_samples_split': [3, 5, 7],
            'min_samples_leaf': [1, 2, 3]
        }
        
        rf_grid = GridSearchCV(
            RandomForestClassifier(random_state=42, n_jobs=-1, class_weight='balanced'),
            rf_params,
            cv=3,
            scoring='f1',
            n_jobs=-1,
            verbose=0
        )
        
        # Use a subset for faster tuning
        sample_size = min(5000, len(X_train))
        sample_indices = np.random.choice(len(X_train), sample_size, replace=False)
        X_sample = X_train[sample_indices]
        y_sample = y_train[sample_indices]
        
        rf_grid.fit(X_sample, y_sample)
        self.best_params['Random Forest'] = rf_grid.best_params_
        
        # Update model with best parameters
        self.models['Enhanced Random Forest'].set_params(**rf_grid.best_params_)
        
        print(f"Best Random Forest parameters: {rf_grid.best_params_}")
        
        # XGBoost tuning
        xgb_params = {
            'n_estimators': [150, 200],
            'max_depth': [6, 8, 10],
            'learning_rate': [0.05, 0.1, 0.15]
        }
        
        xgb_grid = GridSearchCV(
            xgb.XGBClassifier(random_state=42, eval_metric='logloss', use_label_encoder=False),
            xgb_params,
            cv=3,
            scoring='f1',
            n_jobs=-1,
            verbose=0
        )
        
        xgb_grid.fit(X_sample, y_sample)
        self.best_params['XGBoost'] = xgb_grid.best_params_
        
        # Update model with best parameters
        self.models['XGBoost'].set_params(**xgb_grid.best_params_)
        
        print(f"Best XGBoost parameters: {xgb_grid.best_params_}")
        
    def create_ensemble_model(self):
        """
        Create an ensemble model combining the best performers
        """
        print("Creating ensemble model...")
        
        # Select top performing models for ensemble
        ensemble_models = [
            ('rf', self.models['Enhanced Random Forest']),
            ('xgb', self.models['XGBoost']),
            ('gb', self.models['Gradient Boosting'])
        ]
        
        # Create voting classifier
        self.models['Ensemble Voting'] = VotingClassifier(
            estimators=ensemble_models,
            voting='soft',  # Use probability predictions
            n_jobs=-1
        )
        
        print("Ensemble model created successfully!")
    
    def train_enhanced_models(self, X_train, y_train, feature_names):
        """
        Train all enhanced models with optimizations
        
        Args:
            X_train: Training features
            y_train: Training labels
            feature_names: List of feature names
        """
        print("Training enhanced models with optimizations...")
        
        # Apply feature engineering
        X_train_enhanced, X_test_temp, selected_features = self.apply_feature_engineering(
            X_train, X_train, y_train, feature_names  # Using train set for both to get feature names
        )
        
        # Apply data balancing
        X_balanced, y_balanced = self.apply_data_balancing(X_train_enhanced, y_train)
        
        # Hyperparameter tuning
        self.hyperparameter_tuning(X_balanced, y_balanced)
        
        # Create ensemble model
        self.create_ensemble_model()
        
        # Train all models
        for name, model in self.models.items():
            print(f"Training {name}...")
            
            try:
                model.fit(X_balanced, y_balanced)
                
                # Store feature importance for tree-based models
                if hasattr(model, 'feature_importances_'):
                    self.feature_importance[name] = model.feature_importances_
                elif hasattr(model, 'estimators_') and hasattr(model.estimators_[0], 'feature_importances_'):
                    # For ensemble models
                    importances = []
                    for estimator in model.estimators_:
                        if hasattr(estimator, 'feature_importances_'):
                            importances.append(estimator.feature_importances_)
                    if importances:
                        self.feature_importance[name] = np.mean(importances, axis=0)
                        
            except Exception as e:
                print(f"Error training {name}: {str(e)}")
                continue
                
        print("Enhanced models training completed!")
        
        # Store the enhanced training data for evaluation
        self.X_train_enhanced = X_balanced
        self.y_train_enhanced = y_balanced
        self.selected_features = selected_features
        
    def evaluate_enhanced_models(self, X_test, y_test, feature_names):
        """
        Evaluate all enhanced models
        
        Args:
            X_test: Test features
            y_test: Test labels
            feature_names: List of feature names
            
        Returns:
            Dictionary containing evaluation results
        """
        print("Evaluating enhanced models...")
        
        # Apply same feature engineering to test set
        X_test_enhanced, _, _ = self.apply_feature_engineering(
            self.X_train_enhanced[:len(X_test)], X_test, 
            self.y_train_enhanced[:len(X_test)], feature_names
        )
        
        results = {}
        
        # Evaluate all models
        for name, model in self.models.items():
            print(f"Evaluating {name}...")
            
            try:
                # Predictions
                y_pred = model.predict(X_test_enhanced)
                y_pred_proba = None
                
                if hasattr(model, 'predict_proba'):
                    y_pred_proba = model.predict_proba(X_test_enhanced)[:, 1]
                elif hasattr(model, 'decision_function'):
                    y_pred_proba = model.decision_function(X_test_enhanced)
                
                # Calculate metrics
                accuracy = accuracy_score(y_test, y_pred)
                precision = precision_score(y_test, y_pred, zero_division=0)
                recall = recall_score(y_test, y_pred, zero_division=0)
                f1 = f1_score(y_test, y_pred, zero_division=0)
                
                # ROC-AUC (if probability predictions available)
                roc_auc = None
                if y_pred_proba is not None:
                    try:
                        roc_auc = roc_auc_score(y_test, y_pred_proba)
                    except:
                        roc_auc = None
                
                results[name] = {
                    'accuracy': accuracy,
                    'precision': precision,
                    'recall': recall,
                    'f1_score': f1,
                    'roc_auc': roc_auc,
                    'predictions': y_pred,
                    'probabilities': y_pred_proba,
                    'confusion_matrix': confusion_matrix(y_test, y_pred)
                }
                
                print(f"{name} - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, "
                      f"Recall: {recall:.4f}, F1: {f1:.4f}")
                      
            except Exception as e:
                print(f"Error evaluating {name}: {str(e)}")
                continue
        
        # Evaluate anomaly detector
        print("Evaluating Enhanced Isolation Forest...")
        try:
            anomaly_pred = self.anomaly_detector.predict(X_test_enhanced)
            anomaly_pred_binary = np.where(anomaly_pred == -1, 1, 0)
            
            accuracy = accuracy_score(y_test, anomaly_pred_binary)
            precision = precision_score(y_test, anomaly_pred_binary, zero_division=0)
            recall = recall_score(y_test, anomaly_pred_binary, zero_division=0)
            f1 = f1_score(y_test, anomaly_pred_binary, zero_division=0)
            
            results['Enhanced Isolation Forest'] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'roc_auc': None,
                'predictions': anomaly_pred_binary,
                'probabilities': None,
                'confusion_matrix': confusion_matrix(y_test, anomaly_pred_binary)
            }
            
            print(f"Enhanced Isolation Forest - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, "
                  f"Recall: {recall:.4f}, F1: {f1:.4f}")
        except Exception as e:
            print(f"Error evaluating Isolation Forest: {str(e)}")
        
        self.results = results
        return results
    
    def train_anomaly_detector_enhanced(self, X_train):
        """
        Train enhanced anomaly detection model
        
        Args:
            X_train: Training features
        """
        print("Training Enhanced Isolation Forest...")
        
        # Use only normal traffic for unsupervised learning (if available)
        self.anomaly_detector.fit(X_train)
        
        print("Enhanced anomaly detector training completed!")
    
    def generate_enhanced_summary(self):
        """
        Generate enhanced results summary
        """
        print("\n" + "="*80)
        print("ENHANCED CYBER ATTACK DETECTION SYSTEM - RESULTS SUMMARY")
        print("="*80)
        
        # Create results DataFrame
        summary_data = []
        for name, result in self.results.items():
            summary_data.append({
                'Model': name,
                'Accuracy': f"{result['accuracy']:.4f}",
                'Precision': f"{result['precision']:.4f}",
                'Recall': f"{result['recall']:.4f}",
                'F1-Score': f"{result['f1_score']:.4f}",
                'ROC-AUC': f"{result['roc_auc']:.4f}" if result['roc_auc'] else "N/A"
            })
        
        df_summary = pd.DataFrame(summary_data)
        print(df_summary.to_string(index=False))
        
        print("\n" + "="*80)
        print("ENHANCED PERFORMANCE INSIGHTS:")
        print("="*80)
        
        # Find best performing models
        best_accuracy_model = max(self.results.items(), key=lambda x: x[1]['accuracy'])
        best_f1_model = max(self.results.items(), key=lambda x: x[1]['f1_score'])
        best_recall_model = max(self.results.items(), key=lambda x: x[1]['recall'])
        
        print(f"🎯 Best Accuracy: {best_accuracy_model[0]} ({best_accuracy_model[1]['accuracy']:.4f})")
        print(f"🏆 Best Overall Performance (F1): {best_f1_model[0]} ({best_f1_model[1]['f1_score']:.4f})")
        print(f"🛡️  Best Attack Detection (Recall): {best_recall_model[0]} ({best_recall_model[1]['recall']:.4f})")
        
        print("\n🚀 OPTIMIZATION TECHNIQUES APPLIED:")
        print("• Advanced feature engineering with interaction features")
        print("• SMOTE + Tomek links for balanced training data")
        print("• Hyperparameter tuning with GridSearchCV")
        print("• Ensemble methods for improved performance")
        print("• Enhanced model architectures")
        
        return df_summary

def main():
    """Test the enhanced models"""
    from data_loader import CyberDataLoader
    
    # Load and preprocess data
    loader = CyberDataLoader()
    df = loader.get_sample_data()
    X_train, X_test, y_train, y_test = loader.preprocess_data(df)
    
    # Initialize and train enhanced models
    detector = EnhancedCyberAttackDetector()
    detector.initialize_enhanced_models()
    detector.train_enhanced_models(X_train, y_train, loader.feature_names)
    detector.train_anomaly_detector_enhanced(detector.X_train_enhanced)
    
    # Evaluate models
    results = detector.evaluate_enhanced_models(X_test, y_test, loader.feature_names)
    
    # Generate summary
    summary = detector.generate_enhanced_summary()
    
    print("\nEnhanced model training and evaluation completed successfully!")

if __name__ == "__main__":
    main()