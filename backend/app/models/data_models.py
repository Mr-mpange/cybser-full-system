"""
Pydantic data models for IntelliGuard API
"""

from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, validator


class AttackType(str, Enum):
    """Attack type enumeration"""
    NORMAL = "Normal"
    DOS = "DoS"
    DDOS = "DDoS"
    PORT_SCAN = "PortScan"
    BOT = "Bot"
    INFILTRATION = "Infiltration"
    BRUTE_FORCE = "BruteForce"
    WEB_ATTACK = "WebAttack"
    ZERO_DAY = "ZeroDay"


class SeverityLevel(str, Enum):
    """Threat severity levels"""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class NetworkTrafficData(BaseModel):
    """Network traffic data input model"""
    flow_duration: float = Field(..., description="Flow duration in seconds")
    total_fwd_packets: int = Field(..., description="Total forward packets")
    total_bwd_packets: int = Field(..., description="Total backward packets")
    total_length_fwd_packets: float = Field(..., description="Total length of forward packets")
    total_length_bwd_packets: float = Field(..., description="Total length of backward packets")
    fwd_packet_length_max: float = Field(..., description="Maximum forward packet length")
    fwd_packet_length_min: float = Field(..., description="Minimum forward packet length")
    fwd_packet_length_mean: float = Field(..., description="Mean forward packet length")
    bwd_packet_length_max: float = Field(..., description="Maximum backward packet length")
    bwd_packet_length_min: float = Field(..., description="Minimum backward packet length")
    flow_bytes_per_sec: float = Field(..., description="Flow bytes per second")
    flow_packets_per_sec: float = Field(..., description="Flow packets per second")
    flow_iat_mean: float = Field(..., description="Flow inter-arrival time mean")
    flow_iat_std: float = Field(..., description="Flow inter-arrival time standard deviation")
    flow_iat_max: float = Field(..., description="Flow inter-arrival time maximum")
    flow_iat_min: float = Field(..., description="Flow inter-arrival time minimum")
    fwd_iat_total: float = Field(..., description="Forward inter-arrival time total")
    fwd_iat_mean: float = Field(..., description="Forward inter-arrival time mean")
    bwd_iat_total: float = Field(..., description="Backward inter-arrival time total")
    bwd_iat_mean: float = Field(..., description="Backward inter-arrival time mean")
    
    @validator('*', pre=True)
    def convert_to_float(cls, v):
        """Convert numeric values to float"""
        if isinstance(v, (int, float, str)):
            try:
                return float(v)
            except (ValueError, TypeError):
                return 0.0
        return v


class PredictionRequest(BaseModel):
    """Prediction request model"""
    traffic_data: Union[NetworkTrafficData, List[NetworkTrafficData]]
    model_type: Optional[str] = Field(default="ensemble", description="Model type to use")
    include_anomaly_detection: bool = Field(default=True, description="Include zero-day anomaly detection")


class PredictionResult(BaseModel):
    """Single prediction result"""
    attack_type: AttackType
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Prediction confidence")
    severity_level: SeverityLevel
    anomaly_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="Anomaly detection score")
    is_zero_day: bool = Field(default=False, description="Indicates potential zero-day attack")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    model_version: str = Field(default="v1.0", description="Model version used")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class PredictionResponse(BaseModel):
    """Prediction response model"""
    results: List[PredictionResult]
    total_samples: int
    processing_time: float = Field(..., description="Processing time in seconds")
    system_status: str = Field(default="healthy", description="System health status")
    threat_summary: Dict[str, int] = Field(default_factory=dict, description="Summary of detected threats")


class AlertConfig(BaseModel):
    """Alert configuration model"""
    email_enabled: bool = Field(default=False)
    email_recipients: List[str] = Field(default_factory=list)
    telegram_enabled: bool = Field(default=False)
    webhook_enabled: bool = Field(default=False)
    webhook_url: Optional[str] = None
    severity_threshold: SeverityLevel = Field(default=SeverityLevel.MEDIUM)
    
    @validator('email_recipients')
    def validate_emails(cls, v):
        """Validate email addresses"""
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        for email in v:
            if not re.match(email_pattern, email):
                raise ValueError(f"Invalid email address: {email}")
        return v


class DomainMonitoring(BaseModel):
    """Domain monitoring configuration"""
    domain: str = Field(..., description="Domain to monitor")
    monitoring_enabled: bool = Field(default=True)
    check_interval: int = Field(default=300, description="Check interval in seconds")
    alert_config: AlertConfig = Field(default_factory=AlertConfig)
    
    @validator('domain')
    def validate_domain(cls, v):
        """Validate domain format"""
        import re
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, v):
            raise ValueError(f"Invalid domain format: {v}")
        return v


class SystemHealth(BaseModel):
    """System health status"""
    status: str = Field(..., description="Overall system status")
    uptime: float = Field(..., description="System uptime in seconds")
    models_loaded: bool = Field(..., description="ML models loaded status")
    last_prediction: Optional[datetime] = Field(None, description="Last prediction timestamp")
    total_predictions: int = Field(default=0, description="Total predictions made")
    threats_detected: int = Field(default=0, description="Total threats detected")
    zero_day_detected: int = Field(default=0, description="Zero-day threats detected")
    system_load: Dict[str, float] = Field(default_factory=dict, description="System resource usage")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class FileUploadResponse(BaseModel):
    """File upload response"""
    filename: str
    file_size: int
    file_hash: str
    upload_timestamp: datetime = Field(default_factory=datetime.utcnow)
    processing_status: str = Field(default="uploaded")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ErrorResponse(BaseModel):
    """Error response model"""
    error: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ThreatIntelligence(BaseModel):
    """Threat intelligence data"""
    attack_type: AttackType
    description: str
    indicators: List[str] = Field(default_factory=list)
    mitigation: List[str] = Field(default_factory=list)
    severity: SeverityLevel
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    references: List[str] = Field(default_factory=list)


class ModelPerformance(BaseModel):
    """Model performance metrics"""
    model_name: str
    accuracy: float = Field(..., ge=0.0, le=1.0)
    precision: float = Field(..., ge=0.0, le=1.0)
    recall: float = Field(..., ge=0.0, le=1.0)
    f1_score: float = Field(..., ge=0.0, le=1.0)
    roc_auc: Optional[float] = Field(None, ge=0.0, le=1.0)
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }