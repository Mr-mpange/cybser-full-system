"""
Machine Learning Models for Cyber Attack Detection
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                           f1_score, confusion_matrix, roc_auc_score, 
                           classification_report, roc_curve)
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import os

class CyberAttackDetector:
    """
    Comprehensive machine learning system for cyber attack detection
    """
    
    def __init__(self):
        self.models = {}
        self.results = {}
        self.feature_importance = {}
        
    def initialize_models(self):
        """
        Initialize all machine learning models
        """
        print("Initializing machine learning models...")
        
        # Supervised Learning Models
        self.models = {
            'Random Forest': RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            ),
            'SVM': SVC(
                kernel='rbf',
                probability=True,
                random_state=42
            ),
            'Logistic Regression': LogisticRegression(
                random_state=42,
                max_iter=1000
            ),
            'Neural Network': MLPClassifier(
                hidden_layer_sizes=(100, 50),
                max_iter=500,
                random_state=42
            )
        }
        
        # Unsupervised Model (Isolation Forest for anomaly detection)
        self.anomaly_detector = IsolationForest(
            contamination=0.1,  # Assume 10% of data is anomalous
            random_state=42
        )
        
        print("Models initialized successfully!")
        
    def train_supervised_models(self, X_train, y_train):
        """
        Train all supervised learning models
        
        Args:
            X_train: Training features
            y_train: Training labels
        """
        print("Training supervised learning models...")
        
        for name, model in self.models.items():
            print(f"Training {name}...")
            model.fit(X_train, y_train)
            
            # Store feature importance for tree-based models
            if hasattr(model, 'feature_importances_'):
                self.feature_importance[name] = model.feature_importances_
                
        print("Supervised models training completed!")
        
    def train_anomaly_detector(self, X_train):
        """
        Train unsupervised anomaly detection model
        
        Args:
            X_train: Training features (only normal traffic for unsupervised learning)
        """
        print("Training Isolation Forest for anomaly detection...")
        
        # For demonstration, we'll use all training data
        # In practice, you might want to use only normal traffic
        self.anomaly_detector.fit(X_train)
        
        print("Anomaly detector training completed!")
        
    def evaluate_models(self, X_test, y_test):
        """
        Evaluate all trained models
        
        Args:
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Dictionary containing evaluation results
        """
        print("Evaluating models...")
        
        results = {}
        
        # Evaluate supervised models
        for name, model in self.models.items():
            print(f"Evaluating {name}...")
            
            # Predictions
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            
            # ROC-AUC (if probability predictions available)
            roc_auc = roc_auc_score(y_test, y_pred_proba) if y_pred_proba is not None else None
            
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
        
        # Evaluate anomaly detector
        print("Evaluating Isolation Forest...")
        anomaly_pred = self.anomaly_detector.predict(X_test)
        # Convert anomaly predictions: -1 (anomaly) -> 1 (attack), 1 (normal) -> 0 (normal)
        anomaly_pred_binary = np.where(anomaly_pred == -1, 1, 0)
        
        accuracy = accuracy_score(y_test, anomaly_pred_binary)
        precision = precision_score(y_test, anomaly_pred_binary)
        recall = recall_score(y_test, anomaly_pred_binary)
        f1 = f1_score(y_test, anomaly_pred_binary)
        
        results['Isolation Forest'] = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'roc_auc': None,
            'predictions': anomaly_pred_binary,
            'probabilities': None,
            'confusion_matrix': confusion_matrix(y_test, anomaly_pred_binary)
        }
        
        print(f"Isolation Forest - Accuracy: {accuracy:.4f}, Precision: {precision:.4f}, "
              f"Recall: {recall:.4f}, F1: {f1:.4f}")
        
        self.results = results
        return results
        
    def plot_confusion_matrices(self, save_path='results'):
        """
        Plot confusion matrices for all models
        """
        if not os.path.exists(save_path):
            os.makedirs(save_path)
            
        n_models = len(self.results)
        fig, axes = plt.subplots(2, 3, figsize=(15, 10))
        axes = axes.ravel()
        
        for i, (name, result) in enumerate(self.results.items()):
            if i < len(axes):
                cm = result['confusion_matrix']
                sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=axes[i])
                axes[i].set_title(f'{name}\nAccuracy: {result["accuracy"]:.3f}')
                axes[i].set_xlabel('Predicted')
                axes[i].set_ylabel('Actual')
        
        # Hide unused subplots
        for i in range(len(self.results), len(axes)):
            axes[i].set_visible(False)
            
        plt.tight_layout()
        plt.savefig(f'{save_path}/confusion_matrices.png', dpi=300, bbox_inches='tight')
        plt.close()  # Close figure instead of showing
        
    def plot_roc_curves(self, y_test, save_path='results'):
        """
        Plot ROC curves for models with probability predictions
        """
        if not os.path.exists(save_path):
            os.makedirs(save_path)
            
        plt.figure(figsize=(10, 8))
        
        for name, result in self.results.items():
            if result['probabilities'] is not None:
                fpr, tpr, _ = roc_curve(y_test, result['probabilities'])
                plt.plot(fpr, tpr, label=f'{name} (AUC = {result["roc_auc"]:.3f})')
        
        plt.plot([0, 1], [0, 1], 'k--', label='Random Classifier')
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title('ROC Curves - Cyber Attack Detection')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.savefig(f'{save_path}/roc_curves.png', dpi=300, bbox_inches='tight')
        plt.close()  # Close figure instead of showing
        
    def plot_feature_importance(self, feature_names, save_path='results', top_n=20):
        """
        Plot feature importance for tree-based models
        """
        if not os.path.exists(save_path):
            os.makedirs(save_path)
            
        if not self.feature_importance:
            print("No feature importance data available.")
            return
            
        fig, axes = plt.subplots(1, len(self.feature_importance), figsize=(15, 8))
        if len(self.feature_importance) == 1:
            axes = [axes]
            
        for i, (name, importance) in enumerate(self.feature_importance.items()):
            # Get top N features
            indices = np.argsort(importance)[::-1][:top_n]
            top_features = [feature_names[i] for i in indices]
            top_importance = importance[indices]
            
            axes[i].barh(range(len(top_features)), top_importance)
            axes[i].set_yticks(range(len(top_features)))
            axes[i].set_yticklabels(top_features)
            axes[i].set_xlabel('Importance')
            axes[i].set_title(f'{name} - Top {top_n} Features')
            axes[i].invert_yaxis()
        
        plt.tight_layout()
        plt.savefig(f'{save_path}/feature_importance.png', dpi=300, bbox_inches='tight')
        plt.close()  # Close figure instead of showing
        
    def generate_results_summary(self):
        """
        Generate a comprehensive results summary
        """
        print("\n" + "="*80)
        print("CYBER ATTACK DETECTION SYSTEM - RESULTS SUMMARY")
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
        print("KEY INSIGHTS:")
        print("="*80)
        
        # Find best performing model
        best_f1_model = max(self.results.items(), key=lambda x: x[1]['f1_score'])
        best_recall_model = max(self.results.items(), key=lambda x: x[1]['recall'])
        
        print(f"• Best Overall Performance (F1-Score): {best_f1_model[0]} ({best_f1_model[1]['f1_score']:.4f})")
        print(f"• Best Attack Detection (Recall): {best_recall_model[0]} ({best_recall_model[1]['recall']:.4f})")
        
        print("\n• Why Recall is Critical in Cybersecurity:")
        print("  - High recall ensures we catch most actual attacks (minimize false negatives)")
        print("  - Missing a real attack (false negative) is more costly than a false alarm")
        print("  - Better to investigate a false positive than miss a real threat")
        
        return df_summary
        
    def save_models(self, save_path='models'):
        """
        Save trained models to disk
        """
        if not os.path.exists(save_path):
            os.makedirs(save_path)
            
        # Save supervised models
        for name, model in self.models.items():
            filename = f"{save_path}/{name.lower().replace(' ', '_')}_model.pkl"
            joblib.dump(model, filename)
            print(f"Saved {name} model to {filename}")
            
        # Save anomaly detector
        filename = f"{save_path}/isolation_forest_model.pkl"
        joblib.dump(self.anomaly_detector, filename)
        print(f"Saved Isolation Forest model to {filename}")
        
    def load_models(self, load_path='models'):
        """
        Load trained models from disk
        """
        model_files = {
            'Random Forest': 'random_forest_model.pkl',
            'SVM': 'svm_model.pkl',
            'Logistic Regression': 'logistic_regression_model.pkl',
            'Neural Network': 'neural_network_model.pkl'
        }
        
        for name, filename in model_files.items():
            filepath = f"{load_path}/{filename}"
            if os.path.exists(filepath):
                self.models[name] = joblib.load(filepath)
                print(f"Loaded {name} model from {filepath}")
                
        # Load anomaly detector
        filepath = f"{load_path}/isolation_forest_model.pkl"
        if os.path.exists(filepath):
            self.anomaly_detector = joblib.load(filepath)
            print(f"Loaded Isolation Forest model from {filepath}")

def main():
    """Test the models"""
    from data_loader import CyberDataLoader
    
    # Load and preprocess data
    loader = CyberDataLoader()
    df = loader.get_sample_data()
    X_train, X_test, y_train, y_test = loader.preprocess_data(df)
    
    # Initialize and train models
    detector = CyberAttackDetector()
    detector.initialize_models()
    detector.train_supervised_models(X_train, y_train)
    detector.train_anomaly_detector(X_train)
    
    # Evaluate models
    results = detector.evaluate_models(X_test, y_test)
    
    # Generate visualizations and summary
    detector.plot_confusion_matrices()
    detector.plot_roc_curves(y_test)
    detector.plot_feature_importance(loader.feature_names)
    summary = detector.generate_results_summary()
    
    # Save models
    detector.save_models()
    
    print("\nModel training and evaluation completed successfully!")

if __name__ == "__main__":
    main()