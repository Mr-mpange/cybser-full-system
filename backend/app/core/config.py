"""
IntelliGuard Enterprise Configuration Settings
Production-grade configuration with comprehensive security and monitoring options
"""

import os
import secrets
from typing import List, Optional, Dict, Any
from pathlib import Path

try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings
from pydantic import validator, Field


class EnterpriseSettings(BaseSettings):
    """Enterprise-grade application settings with comprehensive configuration"""
    
    # Application Core
    APP_NAME: str = "IntelliGuard Enterprise"
    APP_VERSION: str = "2.0.0"
    ENVIRONMENT: str = Field(default="production", description="Environment: development, staging, production")
    DEBUG: bool = Field(default=False, description="Enable debug mode")
    
    # API Configuration
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    
    # Security Configuration
    ALLOWED_HOSTS: List[str] = ["*"]
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000", 
        "http://localhost:8080",
        "https://intelliguard.company.com"
    ]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_MAX_AGE: int = 3600
    
    # Security Headers
    SECURITY_HEADERS_ENABLED: bool = True
    HSTS_MAX_AGE: int = 31536000  # 1 year
    CONTENT_SECURITY_POLICY: str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    
    # File Upload Configuration
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
    ALLOWED_FILE_TYPES: List[str] = [".csv", ".json", ".log", ".pcap", ".txt", ".xml"]
    UPLOAD_DIR: str = "uploads"
    TEMP_DIR: str = "temp"
    BACKUP_DIR: str = "backups"
    
    # ML Models Configuration
    MODEL_DIR: str = "ml_models/trained_models"
    MODEL_VERSION: str = "v2.0"
    MODEL_CACHE_TTL: int = 3600  # 1 hour
    ENABLE_MODEL_VERSIONING: bool = True
    AUTO_MODEL_UPDATES: bool = False
    
    # Database Configuration
    DATABASE_URL: Optional[str] = Field(default="sqlite:///./intelliguard_enterprise.db")
    DATABASE_POOL_SIZE: int = 20
    DATABASE_MAX_OVERFLOW: int = 30
    DATABASE_POOL_TIMEOUT: int = 30
    DATABASE_POOL_RECYCLE: int = 3600
    
    # Redis Configuration
    REDIS_URL: Optional[str] = Field(default="redis://localhost:6379/0")
    REDIS_PASSWORD: Optional[str] = None
    REDIS_DB: int = 0
    REDIS_MAX_CONNECTIONS: int = 50
    REDIS_SOCKET_TIMEOUT: int = 5
    
    # Email Configuration
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_TLS: bool = True
    SMTP_SSL: bool = False
    EMAIL_FROM: Optional[str] = None
    EMAIL_FROM_NAME: str = "IntelliGuard Enterprise"
    
    # Telegram Configuration
    TELEGRAM_BOT_TOKEN: Optional[str] = None
    TELEGRAM_CHAT_ID: Optional[str] = None
    TELEGRAM_PARSE_MODE: str = "HTML"
    
    # Webhook Configuration
    WEBHOOK_URL: Optional[str] = None
    WEBHOOK_SECRET: Optional[str] = None
    WEBHOOK_TIMEOUT: int = 10
    
    # Slack Configuration
    SLACK_WEBHOOK_URL: Optional[str] = None
    SLACK_CHANNEL: str = "#security-alerts"
    
    # Monitoring Configuration
    ENABLE_METRICS: bool = True
    METRICS_PORT: int = 9090
    ENABLE_HEALTH_CHECKS: bool = True
    HEALTH_CHECK_INTERVAL: int = 300  # 5 minutes
    
    # Logging Configuration
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE: Optional[str] = "logs/intelliguard.log"
    LOG_MAX_SIZE: int = 100 * 1024 * 1024  # 100MB
    LOG_BACKUP_COUNT: int = 5
    ENABLE_JSON_LOGGING: bool = True
    
    # Rate Limiting Configuration
    RATE_LIMIT_PER_MINUTE: int = 100
    RATE_LIMIT_BURST: int = 200
    RATE_LIMIT_STORAGE: str = "redis"  # redis or memory
    ENABLE_RATE_LIMITING: bool = True
    
    # Performance Configuration
    WORKER_PROCESSES: int = Field(default=4, description="Number of worker processes")
    WORKER_CONNECTIONS: int = 1000
    KEEPALIVE_TIMEOUT: int = 65
    MAX_REQUEST_SIZE: int = 100 * 1024 * 1024  # 100MB
    REQUEST_TIMEOUT: int = 300  # 5 minutes
    
    # Cache Configuration
    CACHE_TTL_DEFAULT: int = 3600  # 1 hour
    CACHE_TTL_PREDICTIONS: int = 1800  # 30 minutes
    CACHE_TTL_SYSTEM_METRICS: int = 300  # 5 minutes
    ENABLE_CACHE_COMPRESSION: bool = True
    
    # Security Monitoring
    ENABLE_INTRUSION_DETECTION: bool = True
    FAILED_LOGIN_THRESHOLD: int = 5
    FAILED_LOGIN_WINDOW: int = 300  # 5 minutes
    ENABLE_GEO_BLOCKING: bool = False
    BLOCKED_COUNTRIES: List[str] = []
    
    # ML Configuration
    ML_BATCH_SIZE: int = 1000
    ML_PREDICTION_TIMEOUT: int = 30
    ML_MODEL_WARM_UP: bool = True
    ENABLE_ENSEMBLE_PREDICTIONS: bool = True
    ANOMALY_DETECTION_THRESHOLD: float = 0.7
    
    # Alert Configuration
    ALERT_COOLDOWN_MINUTES: int = 15
    ALERT_ESCALATION_MINUTES: int = 60
    ENABLE_ALERT_AGGREGATION: bool = True
    MAX_ALERTS_PER_HOUR: int = 50
    
    # Backup Configuration
    ENABLE_AUTO_BACKUP: bool = True
    BACKUP_INTERVAL_HOURS: int = 24
    BACKUP_RETENTION_DAYS: int = 30
    BACKUP_COMPRESSION: bool = True
    
    # API Documentation
    ENABLE_DOCS: bool = Field(default=True, description="Enable API documentation")
    DOCS_URL: str = "/docs"
    REDOC_URL: str = "/redoc"
    OPENAPI_URL: str = "/openapi.json"
    
    # Third-party Integrations
    ENABLE_PROMETHEUS: bool = True
    ENABLE_GRAFANA: bool = True
    ENABLE_ELASTICSEARCH: bool = False
    ELASTICSEARCH_URL: Optional[str] = None
    
    # Compliance and Audit
    ENABLE_AUDIT_LOGGING: bool = True
    AUDIT_LOG_FILE: str = "logs/audit.log"
    ENABLE_GDPR_MODE: bool = True
    DATA_RETENTION_DAYS: int = 365
    
    @validator("CORS_ORIGINS", pre=True)
    def assemble_cors_origins(cls, v):
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)
    
    @validator("ENVIRONMENT")
    def validate_environment(cls, v):
        allowed = ["development", "staging", "production"]
        if v not in allowed:
            raise ValueError(f"Environment must be one of {allowed}")
        return v
    
    @validator("LOG_LEVEL")
    def validate_log_level(cls, v):
        allowed = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in allowed:
            raise ValueError(f"Log level must be one of {allowed}")
        return v.upper()
    
    @validator("SECRET_KEY")
    def validate_secret_key(cls, v):
        if len(v) < 32:
            raise ValueError("Secret key must be at least 32 characters long")
        return v
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment"""
        return self.ENVIRONMENT == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment"""
        return self.ENVIRONMENT == "development"
    
    @property
    def database_config(self) -> Dict[str, Any]:
        """Get database configuration"""
        return {
            "url": self.DATABASE_URL,
            "pool_size": self.DATABASE_POOL_SIZE,
            "max_overflow": self.DATABASE_MAX_OVERFLOW,
            "pool_timeout": self.DATABASE_POOL_TIMEOUT,
            "pool_recycle": self.DATABASE_POOL_RECYCLE
        }
    
    @property
    def redis_config(self) -> Dict[str, Any]:
        """Get Redis configuration"""
        return {
            "url": self.REDIS_URL,
            "password": self.REDIS_PASSWORD,
            "db": self.REDIS_DB,
            "max_connections": self.REDIS_MAX_CONNECTIONS,
            "socket_timeout": self.REDIS_SOCKET_TIMEOUT
        }
    
    @property
    def email_config(self) -> Dict[str, Any]:
        """Get email configuration"""
        return {
            "host": self.SMTP_HOST,
            "port": self.SMTP_PORT,
            "user": self.SMTP_USER,
            "password": self.SMTP_PASSWORD,
            "tls": self.SMTP_TLS,
            "ssl": self.SMTP_SSL,
            "from_email": self.EMAIL_FROM,
            "from_name": self.EMAIL_FROM_NAME
        }
    
    def create_directories(self):
        """Create required directories"""
        directories = [
            self.UPLOAD_DIR,
            self.TEMP_DIR,
            self.BACKUP_DIR,
            "logs",
            Path(self.LOG_FILE).parent if self.LOG_FILE else None,
            Path(self.AUDIT_LOG_FILE).parent
        ]
        
        for directory in directories:
            if directory:
                Path(directory).mkdir(parents=True, exist_ok=True)
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        validate_assignment = True


# Global settings instance
settings = EnterpriseSettings()

# Create required directories on import
settings.create_directories()