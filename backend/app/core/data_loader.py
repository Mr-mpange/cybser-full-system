"""
Data Loading and Preprocessing Module for Cyber Attack Detection System
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings('ignore')

class CyberDataLoader:
    """
    Handles loading and preprocessing of cybersecurity datasets
    Supports CIC-IDS2017, UNSW-NB15, and NSL-KDD datasets
    """
    
    def __init__(self, dataset_type='CIC-IDS2017'):
        self.dataset_type = dataset_type
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names = None
        
    def load_cic_ids2017(self, file_path):
        """
        Load CIC-IDS2017 dataset
        
        Dataset Features:
        - 78 features including flow duration, packet statistics, flags
        - Labels: BENIGN, DoS, DDoS, PortScan, Bot, Infiltration, Web Attack, Brute Force
        """
        print("Loading CIC-IDS2017 dataset...")
        
        # Read CSV file
        df = pd.read_csv(file_path)
        
        # Clean column names (remove spaces and special characters)
        df.columns = df.columns.str.strip().str.replace(' ', '_')
        
        # Handle infinite values
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        
        # Fill NaN values with median for numeric columns
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        df[numeric_columns] = df[numeric_columns].fillna(df[numeric_columns].median())
        
        print(f"Dataset shape: {df.shape}")
        print(f"Features: {df.columns.tolist()}")
        
        return df
    
    def preprocess_data(self, df, target_column='Label'):
        """
        Preprocess the dataset for machine learning
        
        Args:
            df: Input dataframe
            target_column: Name of the target column
            
        Returns:
            X_train, X_test, y_train, y_test: Preprocessed data splits
        """
        print("Preprocessing data...")
        
        # Separate features and target
        if target_column not in df.columns:
            # Try common label column names
            possible_labels = ['Label', 'label', 'Attack', 'attack', 'class', 'Class']
            target_column = None
            for col in possible_labels:
                if col in df.columns:
                    target_column = col
                    break
            
            if target_column is None:
                raise ValueError("Target column not found. Please specify the correct column name.")
        
        # Create binary classification (Normal vs Attack)
        y = df[target_column].copy()
        
        # Convert to binary: BENIGN/Normal = 0, Everything else = 1
        y_binary = np.where(y.str.upper().str.contains('BENIGN|NORMAL'), 0, 1)
        
        # Get feature columns (exclude target)
        feature_columns = [col for col in df.columns if col != target_column]
        X = df[feature_columns].copy()
        
        # Store feature names
        self.feature_names = feature_columns
        
        # Handle categorical features if any
        categorical_columns = X.select_dtypes(include=['object']).columns
        if len(categorical_columns) > 0:
            print(f"Encoding categorical features: {categorical_columns.tolist()}")
            for col in categorical_columns:
                X[col] = self.label_encoder.fit_transform(X[col].astype(str))
        
        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
        )
        
        # Scale the features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        print(f"Training set shape: {X_train_scaled.shape}")
        print(f"Test set shape: {X_test_scaled.shape}")
        print(f"Class distribution - Normal: {np.sum(y_train == 0)}, Attack: {np.sum(y_train == 1)}")
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
    def get_sample_data(self):
        """
        Generate sample cybersecurity data for demonstration
        This simulates network traffic features
        """
        print("Generating sample cybersecurity data...")
        
        np.random.seed(42)
        n_samples = 10000
        
        # Simulate network traffic features
        data = {
            'flow_duration': np.random.exponential(1000, n_samples),
            'total_fwd_packets': np.random.poisson(50, n_samples),
            'total_bwd_packets': np.random.poisson(30, n_samples),
            'total_length_fwd_packets': np.random.exponential(2000, n_samples),
            'total_length_bwd_packets': np.random.exponential(1500, n_samples),
            'fwd_packet_length_max': np.random.exponential(500, n_samples),
            'fwd_packet_length_min': np.random.exponential(50, n_samples),
            'fwd_packet_length_mean': np.random.exponential(200, n_samples),
            'bwd_packet_length_max': np.random.exponential(400, n_samples),
            'bwd_packet_length_min': np.random.exponential(40, n_samples),
            'flow_bytes_per_sec': np.random.exponential(10000, n_samples),
            'flow_packets_per_sec': np.random.exponential(100, n_samples),
            'flow_iat_mean': np.random.exponential(1000, n_samples),
            'flow_iat_std': np.random.exponential(500, n_samples),
            'flow_iat_max': np.random.exponential(2000, n_samples),
            'flow_iat_min': np.random.exponential(10, n_samples),
            'fwd_iat_total': np.random.exponential(5000, n_samples),
            'fwd_iat_mean': np.random.exponential(800, n_samples),
            'bwd_iat_total': np.random.exponential(4000, n_samples),
            'bwd_iat_mean': np.random.exponential(600, n_samples),
        }
        
        df = pd.DataFrame(data)
        
        # Create labels (80% normal, 20% attack)
        labels = np.random.choice(['BENIGN', 'DoS', 'DDoS', 'PortScan', 'Bot'], 
                                 n_samples, p=[0.8, 0.05, 0.05, 0.05, 0.05])
        df['Label'] = labels
        
        # Add some attack patterns
        attack_mask = df['Label'] != 'BENIGN'
        
        # DoS attacks: high packet rate, low duration
        dos_mask = df['Label'] == 'DoS'
        df.loc[dos_mask, 'flow_packets_per_sec'] *= 10
        df.loc[dos_mask, 'flow_duration'] /= 5
        
        # DDoS attacks: very high packet rate
        ddos_mask = df['Label'] == 'DDoS'
        df.loc[ddos_mask, 'flow_packets_per_sec'] *= 20
        df.loc[ddos_mask, 'total_fwd_packets'] *= 5
        
        # Port scan: many small packets
        portscan_mask = df['Label'] == 'PortScan'
        df.loc[portscan_mask, 'fwd_packet_length_mean'] /= 10
        df.loc[portscan_mask, 'total_fwd_packets'] *= 3
        
        print(f"Sample data generated: {df.shape}")
        print(f"Label distribution:\n{df['Label'].value_counts()}")
        
        return df

def main():
    """Test the data loader"""
    loader = CyberDataLoader()
    
    # Generate sample data
    df = loader.get_sample_data()
    
    # Preprocess data
    X_train, X_test, y_train, y_test = loader.preprocess_data(df)
    
    print("\nData loading and preprocessing completed successfully!")
    print(f"Feature names: {loader.feature_names[:10]}...")  # Show first 10 features

if __name__ == "__main__":
    main()