"""
Prediction Service for IntelliGuard
Handles ML predictions and file processing
"""

import os
import pandas as pd
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime

from ..models.data_models import NetworkTrafficData, PredictionResult
from ..models.ml_models import ml_models
from ..utils.logger import get_logger

logger = get_logger(__name__)


class PredictionService:
    """Service for handling ML predictions"""
    
    def __init__(self):
        self.prediction_history = []
        self.processing_queue = asyncio.Queue()
    
    async def process_uploaded_file(self, file_path: str, file_hash: str) -> Dict[str, Any]:
        """
        Process uploaded CSV file for batch prediction
        """
        try:
            logger.info(f"Processing uploaded file: {file_path}")
            
            # Read CSV file
            df = pd.read_csv(file_path)
            
            # Validate required columns
            required_columns = [
                'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
                'total_length_fwd_packets', 'total_length_bwd_packets',
                'fwd_packet_length_max', 'fwd_packet_length_min', 'fwd_packet_length_mean',
                'bwd_packet_length_max', 'bwd_packet_length_min',
                'flow_bytes_per_sec', 'flow_packets_per_sec',
                'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
                'fwd_iat_total', 'fwd_iat_mean', 'bwd_iat_total', 'bwd_iat_mean'
            ]
            
            missing_columns = [col for col in required_columns if col not in df.columns]
            if missing_columns:
                raise ValueError(f"Missing required columns: {missing_columns}")
            
            # Convert to NetworkTrafficData objects
            traffic_data = []
            for _, row in df.iterrows():
                try:
                    data = NetworkTrafficData(**row.to_dict())
                    traffic_data.append(data)
                except Exception as e:
                    logger.warning(f"Skipping invalid row: {str(e)}")
                    continue
            
            if not traffic_data:
                raise ValueError("No valid traffic data found in file")
            
            # Process in batches to avoid memory issues
            batch_size = 100
            all_results = []
            
            for i in range(0, len(traffic_data), batch_size):
                batch = traffic_data[i:i + batch_size]
                batch_results = ml_models.predict_attack(batch, 'Optimized XGBoost')
                all_results.extend(batch_results)
                
                # Add small delay to prevent overwhelming the system
                await asyncio.sleep(0.1)
            
            # Save results
            results_summary = {
                'file_hash': file_hash,
                'total_samples': len(traffic_data),
                'predictions': all_results,
                'processing_time': datetime.utcnow(),
                'threats_detected': sum(1 for r in all_results if r['attack_type'].value != 'Normal')
            }
            
            # Store in history
            self.prediction_history.append(results_summary)
            
            # Clean up file
            try:
                os.remove(file_path)
            except Exception as e:
                logger.warning(f"Failed to clean up file {file_path}: {str(e)}")
            
            logger.info(f"File processing completed: {len(all_results)} predictions made")
            
            return results_summary
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")
            raise
    
    def get_prediction_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent prediction history"""
        return self.prediction_history[-limit:]
    
    def get_prediction_stats(self) -> Dict[str, Any]:
        """Get prediction statistics"""
        if not self.prediction_history:
            return {
                'total_predictions': 0,
                'total_threats': 0,
                'accuracy': 0.0,
                'last_prediction': None
            }
        
        total_predictions = sum(h['total_samples'] for h in self.prediction_history)
        total_threats = sum(h['threats_detected'] for h in self.prediction_history)
        
        return {
            'total_predictions': total_predictions,
            'total_threats': total_threats,
            'threat_rate': total_threats / total_predictions if total_predictions > 0 else 0,
            'last_prediction': self.prediction_history[-1]['processing_time'] if self.prediction_history else None
        }