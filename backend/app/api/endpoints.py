"""
IntelliGuard API Endpoints
"""

from typing import List
from fastapi import APIRouter, HTTPException
from ..models.data_models import NetworkTrafficData, PredictionResponse
from ..models.ml_models import ml_models

router = APIRouter()


@router.post("/predict/single", response_model=PredictionResponse)
async def predict_single_attack(request: dict):
    """
    Analyze single network traffic sample for cyber attacks
    """
    try:
        # Extract network_data from request
        network_data = request.get('network_data', {})
        
        # Convert to list format for ML model
        data_list = [network_data]
        
        # Get prediction
        results = ml_models.predict_attack(data_list)
        
        if not results:
            raise HTTPException(status_code=500, detail="Prediction failed")
        
        result = results[0]
        
        return PredictionResponse(
            attack_type=result['attack_type'],
            confidence_score=result['confidence_score'],
            severity_level=result['severity_level'],
            anomaly_score=result['anomaly_score'],
            is_zero_day=result['is_zero_day'],
            model_used=result['model_used'],
            timestamp=result['timestamp']
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")


@router.post("/predict/batch")
async def predict_batch_attacks(network_data_list: List[NetworkTrafficData]):
    """
    Analyze multiple network traffic samples in batch
    """
    try:
        # Convert to list format for ML model
        data_list = [data.dict() for data in network_data_list]
        
        # Get predictions
        results = ml_models.predict_attack(data_list)
        
        return {
            "predictions": results,
            "total_samples": len(results),
            "summary": {
                "threats_detected": sum(1 for r in results if r['attack_type'] != 'normal'),
                "normal_traffic": sum(1 for r in results if r['attack_type'] == 'normal')
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch prediction error: {str(e)}")


@router.get("/models")
async def get_model_info():
    """Get information about available ML models"""
    return {
        "status": ml_models.get_system_status(),
        "performance": ml_models.get_model_performance()
    }