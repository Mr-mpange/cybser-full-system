"""
Enterprise Validation Utilities for IntelliGuard
Comprehensive input validation and security checks
"""

import re
import ipaddress
import hashlib
from typing import Dict, Any, List, Optional
from fastapi import UploadFile
from ..models.data_models import NetworkTrafficData
from ..core.config import settings
from .logger import get_logger

logger = get_logger(__name__)


def validate_network_data(data: NetworkTrafficData) -> bool:
    """
    Validate network traffic data for completeness and security
    
    Args:
        data: NetworkTrafficData object to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        # Check required fields are present and valid
        required_fields = [
            'flow_duration', 'total_fwd_packets', 'total_bwd_packets',
            'flow_bytes_per_sec', 'flow_packets_per_sec'
        ]
        
        for field in required_fields:
            value = getattr(data, field, None)
            if value is None:
                logger.warning(f"Missing required field: {field}")
                return False
            
            # Check for reasonable ranges
            if isinstance(value, (int, float)):
                if value < 0:
                    logger.warning(f"Negative value for {field}: {value}")
                    return False
                
                # Check for extremely large values that might indicate data corruption
                if value > 1e12:  # 1 trillion - reasonable upper bound
                    logger.warning(f"Extremely large value for {field}: {value}")
                    return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error validating network data: {str(e)}")
        return False


def validate_file_upload(file: UploadFile) -> bool:
    """
    Validate uploaded file for security and format compliance
    
    Args:
        file: FastAPI UploadFile object
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        # Check file extension
        if file.filename:
            file_ext = '.' + file.filename.split('.')[-1].lower()
            if file_ext not in settings.ALLOWED_FILE_TYPES:
                logger.warning(f"Invalid file type: {file_ext}")
                return False
        
        return True
        
    except Exception as e:
        logger.error(f"Error validating file upload: {str(e)}")
        return False