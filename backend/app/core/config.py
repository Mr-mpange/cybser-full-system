"""
IntelliGuard Configuration Settings
"""

import os


class Settings:
    """Simple application settings"""
    
    # Application
    APP_NAME: str = "IntelliGuard"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # API
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "your-secret-key-change-in-production"
    
    # Security
    ALLOWED_HOSTS = ["*"]
    CORS_ORIGINS = ["http://localhost:3000", "http://localhost:8080", "http://localhost:3001"]
    
    # File Upload
    MAX_FILE_SIZE: int = 50 * 1024 * 1024  # 50MB
    UPLOAD_DIR: str = "uploads"
    
    # Monitoring
    ENABLE_METRICS: bool = True
    LOG_LEVEL: str = "INFO"


# Global settings instance
settings = Settings()