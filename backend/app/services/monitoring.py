"""
Domain Monitoring Service for IntelliGuard
"""

import asyncio
import aiohttp
import time
from typing import Dict, List, Any
from datetime import datetime, timedelta

from ..models.data_models import DomainMonitoring
from ..utils.logger import get_logger

logger = get_logger(__name__)


class MonitoringService:
    """Service for monitoring domains and websites"""
    
    def __init__(self):
        self.monitored_domains = {}
        self.monitoring_tasks = {}
        self.domain_status = {}
    
    def add_domain(self, domain_config: DomainMonitoring):
        """Add domain for monitoring"""
        self.monitored_domains[domain_config.domain] = domain_config
        self.domain_status[domain_config.domain] = {
            'status': 'unknown',
            'last_check': None,
            'response_time': None,
            'error_count': 0
        }
        logger.info(f"Added domain for monitoring: {domain_config.domain}")
    
    async def start_domain_monitoring(self, domain: str):
        """Start monitoring a domain"""
        if domain not in self.monitored_domains:
            return
        
        config = self.monitored_domains[domain]
        
        # Cancel existing task if any
        if domain in self.monitoring_tasks:
            self.monitoring_tasks[domain].cancel()
        
        # Start new monitoring task
        self.monitoring_tasks[domain] = asyncio.create_task(
            self._monitor_domain_loop(domain, config)
        )
        
        logger.info(f"Started monitoring for domain: {domain}")
    
    async def _monitor_domain_loop(self, domain: str, config: DomainMonitoring):
        """Main monitoring loop for a domain"""
        while config.monitoring_enabled:
            try:
                await self._check_domain_health(domain, config)
                await asyncio.sleep(config.check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error monitoring domain {domain}: {str(e)}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _check_domain_health(self, domain: str, config: DomainMonitoring):
        """Check domain health"""
        start_time = time.time()
        
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
                
                async with session.get(url) as response:
                    response_time = time.time() - start_time
                    
                    # Update status
                    self.domain_status[domain].update({
                        'status': 'healthy' if response.status == 200 else 'warning',
                        'last_check': datetime.utcnow(),
                        'response_time': response_time,
                        'status_code': response.status,
                        'error_count': 0 if response.status == 200 else self.domain_status[domain]['error_count'] + 1
                    })
                    
                    logger.debug(f"Domain {domain} check: {response.status} ({response_time:.2f}s)")
                    
        except Exception as e:
            # Update error status
            self.domain_status[domain].update({
                'status': 'error',
                'last_check': datetime.utcnow(),
                'response_time': None,
                'error': str(e),
                'error_count': self.domain_status[domain]['error_count'] + 1
            })
            
            logger.warning(f"Domain {domain} check failed: {str(e)}")
    
    def get_monitored_domains(self) -> List[Dict[str, Any]]:
        """Get list of monitored domains with status"""
        domains = []
        
        for domain, config in self.monitored_domains.items():
            status = self.domain_status.get(domain, {})
            
            domains.append({
                'domain': domain,
                'monitoring_enabled': config.monitoring_enabled,
                'check_interval': config.check_interval,
                'status': status.get('status', 'unknown'),
                'last_check': status.get('last_check'),
                'response_time': status.get('response_time'),
                'error_count': status.get('error_count', 0)
            })
        
        return domains
    
    def stop_domain_monitoring(self, domain: str):
        """Stop monitoring a domain"""
        if domain in self.monitoring_tasks:
            self.monitoring_tasks[domain].cancel()
            del self.monitoring_tasks[domain]
        
        if domain in self.monitored_domains:
            self.monitored_domains[domain].monitoring_enabled = False
        
        logger.info(f"Stopped monitoring for domain: {domain}")
    
    def remove_domain(self, domain: str):
        """Remove domain from monitoring"""
        self.stop_domain_monitoring(domain)
        
        if domain in self.monitored_domains:
            del self.monitored_domains[domain]
        
        if domain in self.domain_status:
            del self.domain_status[domain]
        
        logger.info(f"Removed domain from monitoring: {domain}")