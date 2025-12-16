"""
Data models for IntelliGuard API
"""

from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class ErrorResponse(BaseModel):
    """Error response model"""
    error: str
    detail: str
    timestamp: Optional[float] = None
    path: Optional[str] = None


class NetworkTrafficData(BaseModel):
    """Network traffic data input model"""
    flow_duration: float
    total_fwd_packets: int
    total_bwd_packets: int
    flow_bytes_per_sec: float
    flow_packets_per_sec: float
    flow_iat_mean: float
    flow_iat_std: float
    fwd_packet_length_mean: float
    bwd_packet_length_mean: float


class PredictionResponse(BaseModel):
    """Prediction response model"""
    attack_type: str
    confidence_score: float
    severity_level: str
    anomaly_score: float
    is_zero_day: bool
    model_used: str
    timestamp: datetime
    sample_index: Optional[int] = None