"""
Enterprise Monitoring Service for IntelliGuard
Real-time system monitoring, performance tracking, and health management
"""

import asyncio
import psutil
import time
import json
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import deque, defaultdict

from ..core.config import settings
from ..core.cache import cache_manager
from ..utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SystemMetrics:
    """System performance metrics"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_io: Dict[str, int]
    process_count: int
    load_average: List[float]
    temperature: Optional[float] = None


@dataclass
class ApplicationMetrics:
    """Application-specific metrics"""
    timestamp: datetime
    active_connections: int
    requests_per_second: float
    response_time_avg: float
    error_rate: float
    cache_hit_rate: float
    ml_predictions_per_minute: int
    threats_detected: int


class EnterpriseMonitoringService:
    """Enterprise-grade monitoring service with real-time metrics"""
    
    def __init__(self):
        self.is_running = False
        self.monitoring_task = None
        
        # Metrics storage (in-memory with configurable retention)
        self.system_metrics = deque(maxlen=1440)  # 24 hours at 1-minute intervals
        self.app_metrics = deque(maxlen=1440)
        self.performance_alerts = deque(maxlen=100)
        
        # Performance thresholds
        self.thresholds = {
            'cpu_warning': 70.0,
            'cpu_critical': 85.0,
            'memory_warning': 75.0,
            'memory_critical': 90.0,
            'disk_warning': 80.0,
            'disk_critical': 95.0,
            'response_time_warning': 2.0,
            'response_time_critical': 5.0,
            'error_rate_warning': 5.0,
            'error_rate_critical': 10.0
        }
        
        # Monitoring intervals
        self.system_check_interval = 30  # seconds
        self.app_check_interval = 60    # seconds
        self.health_check_interval = 300 # seconds
        
        # Performance tracking
        self.request_times = deque(maxlen=1000)
        self.error_count = 0
        self.total_requests = 0
        self.start_time = time.time()
        
    async def start(self):
        """Start monitoring service"""
        if self.is_running:
            logger.warning("Monitoring service already running")
            return
        
        logger.info("🔍 Starting Enterprise Monitoring Service")
        self.is_running = True
        
        # Start monitoring tasks
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        
        logger.info("✅ Monitoring service started successfully")
    
    async def stop(self):
        """Stop monitoring service"""
        if not self.is_running:
            return
        
        logger.info("🛑 Stopping monitoring service")
        self.is_running = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("✅ Monitoring service stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        last_system_check = 0
        last_app_check = 0
        last_health_check = 0
        
        while self.is_running:
            try:
                current_time = time.time()
                
                # System metrics collection
                if current_time - last_system_check >= self.system_check_interval:
                    await self._collect_system_metrics()
                    last_system_check = current_time
                
                # Application metrics collection
                if current_time - last_app_check >= self.app_check_interval:
                    await self._collect_app_metrics()
                    last_app_check = current_time
                
                # Health checks
                if current_time - last_health_check >= self.health_check_interval:
                    await self._perform_health_checks()
                    last_health_check = current_time
                
                await asyncio.sleep(10)  # Base loop interval
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitoring loop error: {str(e)}")
                await asyncio.sleep(30)  # Wait before retrying
    
    async def _collect_system_metrics(self):
        """Collect system performance metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory metrics
            memory = psutil.virtual_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            
            # Network I/O
            network = psutil.net_io_counters()
            network_io = {
                'bytes_sent': network.bytes_sent,
                'bytes_recv': network.bytes_recv,
                'packets_sent': network.packets_sent,
                'packets_recv': network.packets_recv
            }
            
            # Process count
            process_count = len(psutil.pids())
            
            # Load average (Unix-like systems)
            try:
                load_avg = list(psutil.getloadavg())
            except AttributeError:
                # Windows doesn't have load average
                load_avg = [cpu_percent / 100.0] * 3
            
            # Temperature (if available)
            temperature = None
            try:
                temps = psutil.sensors_temperatures()
                if temps:
                    # Get CPU temperature if available
                    for name, entries in temps.items():
                        if 'cpu' in name.lower() or 'core' in name.lower():
                            temperature = entries[0].current
                            break
            except (AttributeError, IndexError):
                pass
            
            # Create metrics object
            metrics = SystemMetrics(
                timestamp=datetime.utcnow(),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                disk_percent=disk.percent,
                network_io=network_io,
                process_count=process_count,
                load_average=load_avg,
                temperature=temperature
            )
            
            # Store metrics
            self.system_metrics.append(metrics)
            
            # Check thresholds and generate alerts
            await self._check_system_thresholds(metrics)
            
            # Cache recent metrics
            await cache_manager.set(\"system_metrics_latest\", asdict(metrics), 300)
            
        except Exception as e:
            logger.error(f\"Error collecting system metrics: {str(e)}\")
    
    async def _collect_app_metrics(self):
        \"\"\"Collect application-specific metrics\"\"\"
        try:
            # Calculate request rate
            current_time = time.time()
            uptime = current_time - self.start_time
            requests_per_second = self.total_requests / uptime if uptime > 0 else 0
            
            # Calculate average response time
            response_time_avg = sum(self.request_times) / len(self.request_times) if self.request_times else 0
            
            # Calculate error rate
            error_rate = (self.error_count / self.total_requests * 100) if self.total_requests > 0 else 0
            
            # Get cache statistics
            cache_stats = await cache_manager.get_stats()
            cache_hit_rate = cache_stats.get('hit_rate', 0)
            
            # Get active connections (approximate)
            try:
                connections = len(psutil.net_connections(kind='inet'))
            except psutil.AccessDenied:
                connections = 0
            
            # ML metrics (would be updated by ML service)
            ml_predictions_per_minute = 0  # Placeholder
            threats_detected = 0  # Placeholder
            
            # Create metrics object
            metrics = ApplicationMetrics(
                timestamp=datetime.utcnow(),
                active_connections=connections,
                requests_per_second=requests_per_second,
                response_time_avg=response_time_avg,
                error_rate=error_rate,
                cache_hit_rate=cache_hit_rate,
                ml_predictions_per_minute=ml_predictions_per_minute,
                threats_detected=threats_detected
            )
            
            # Store metrics
            self.app_metrics.append(metrics)
            
            # Check application thresholds
            await self._check_app_thresholds(metrics)
            
            # Cache recent metrics
            await cache_manager.set(\"app_metrics_latest\", asdict(metrics), 300)
            
        except Exception as e:
            logger.error(f\"Error collecting application metrics: {str(e)}\")
    
    async def _check_system_thresholds(self, metrics: SystemMetrics):
        \"\"\"Check system metrics against thresholds\"\"\"
        alerts = []
        
        # CPU threshold checks
        if metrics.cpu_percent > self.thresholds['cpu_critical']:
            alerts.append({
                'type': 'system',
                'severity': 'critical',
                'metric': 'cpu_usage',
                'value': metrics.cpu_percent,
                'threshold': self.thresholds['cpu_critical'],
                'message': f\"Critical CPU usage: {metrics.cpu_percent:.1f}%\"
            })
        elif metrics.cpu_percent > self.thresholds['cpu_warning']:
            alerts.append({
                'type': 'system',
                'severity': 'warning',
                'metric': 'cpu_usage',
                'value': metrics.cpu_percent,
                'threshold': self.thresholds['cpu_warning'],
                'message': f\"High CPU usage: {metrics.cpu_percent:.1f}%\"
            })
        
        # Memory threshold checks
        if metrics.memory_percent > self.thresholds['memory_critical']:
            alerts.append({
                'type': 'system',
                'severity': 'critical',
                'metric': 'memory_usage',
                'value': metrics.memory_percent,
                'threshold': self.thresholds['memory_critical'],
                'message': f\"Critical memory usage: {metrics.memory_percent:.1f}%\"
            })
        elif metrics.memory_percent > self.thresholds['memory_warning']:
            alerts.append({
                'type': 'system',
                'severity': 'warning',
                'metric': 'memory_usage',
                'value': metrics.memory_percent,
                'threshold': self.thresholds['memory_warning'],
                'message': f\"High memory usage: {metrics.memory_percent:.1f}%\"
            })
        
        # Disk threshold checks
        if metrics.disk_percent > self.thresholds['disk_critical']:
            alerts.append({
                'type': 'system',
                'severity': 'critical',
                'metric': 'disk_usage',
                'value': metrics.disk_percent,
                'threshold': self.thresholds['disk_critical'],
                'message': f\"Critical disk usage: {metrics.disk_percent:.1f}%\"
            })
        elif metrics.disk_percent > self.thresholds['disk_warning']:
            alerts.append({
                'type': 'system',
                'severity': 'warning',
                'metric': 'disk_usage',
                'value': metrics.disk_percent,
                'threshold': self.thresholds['disk_warning'],
                'message': f\"High disk usage: {metrics.disk_percent:.1f}%\"
            })
        
        # Store alerts
        for alert in alerts:
            alert['timestamp'] = datetime.utcnow()
            self.performance_alerts.append(alert)
    
    async def _check_app_thresholds(self, metrics: ApplicationMetrics):
        \"\"\"Check application metrics against thresholds\"\"\"
        alerts = []
        
        # Response time checks
        if metrics.response_time_avg > self.thresholds['response_time_critical']:
            alerts.append({
                'type': 'application',
                'severity': 'critical',
                'metric': 'response_time',
                'value': metrics.response_time_avg,
                'threshold': self.thresholds['response_time_critical'],
                'message': f\"Critical response time: {metrics.response_time_avg:.2f}s\"
            })
        elif metrics.response_time_avg > self.thresholds['response_time_warning']:
            alerts.append({
                'type': 'application',
                'severity': 'warning',
                'metric': 'response_time',
                'value': metrics.response_time_avg,
                'threshold': self.thresholds['response_time_warning'],
                'message': f\"High response time: {metrics.response_time_avg:.2f}s\"
            })
        
        # Error rate checks
        if metrics.error_rate > self.thresholds['error_rate_critical']:
            alerts.append({
                'type': 'application',
                'severity': 'critical',
                'metric': 'error_rate',
                'value': metrics.error_rate,
                'threshold': self.thresholds['error_rate_critical'],
                'message': f\"Critical error rate: {metrics.error_rate:.1f}%\"
            })
        elif metrics.error_rate > self.thresholds['error_rate_warning']:
            alerts.append({
                'type': 'application',
                'severity': 'warning',
                'metric': 'error_rate',
                'value': metrics.error_rate,
                'threshold': self.thresholds['error_rate_warning'],
                'message': f\"High error rate: {metrics.error_rate:.1f}%\"
            })
        
        # Store alerts
        for alert in alerts:
            alert['timestamp'] = datetime.utcnow()
            self.performance_alerts.append(alert)
    
    async def _perform_health_checks(self):
        \"\"\"Perform comprehensive health checks\"\"\"
        try:
            health_status = {
                'timestamp': datetime.utcnow(),
                'overall_status': 'healthy',
                'components': {}
            }
            
            # Database health
            try:
                from ..core.database import engine
                with engine.connect() as conn:
                    conn.execute(\"SELECT 1\")
                health_status['components']['database'] = 'healthy'
            except Exception as e:
                health_status['components']['database'] = f'unhealthy: {str(e)}'
                health_status['overall_status'] = 'degraded'
            
            # Cache health
            try:
                await cache_manager.set('health_check', 'ok', 60)
                result = await cache_manager.get('health_check')
                if result == 'ok':
                    health_status['components']['cache'] = 'healthy'
                else:
                    health_status['components']['cache'] = 'degraded'
                    health_status['overall_status'] = 'degraded'
            except Exception as e:
                health_status['components']['cache'] = f'unhealthy: {str(e)}'
                health_status['overall_status'] = 'degraded'
            
            # ML Models health
            try:
                from ..models.ml_models import ml_models
                if ml_models.is_loaded:
                    health_status['components']['ml_models'] = 'healthy'
                else:
                    health_status['components']['ml_models'] = 'degraded'
                    health_status['overall_status'] = 'degraded'
            except Exception as e:
                health_status['components']['ml_models'] = f'unhealthy: {str(e)}'
                health_status['overall_status'] = 'degraded'
            
            # Store health status
            await cache_manager.set('system_health', health_status, 600)
            
        except Exception as e:
            logger.error(f\"Health check error: {str(e)}\")
    
    def record_request(self, response_time: float, is_error: bool = False):
        \"\"\"Record request metrics\"\"\"
        self.request_times.append(response_time)
        self.total_requests += 1
        if is_error:
            self.error_count += 1
    
    async def get_system_overview(self) -> Dict[str, Any]:
        \"\"\"Get system overview with latest metrics\"\"\"
        latest_system = self.system_metrics[-1] if self.system_metrics else None
        latest_app = self.app_metrics[-1] if self.app_metrics else None
        
        return {
            'uptime_seconds': time.time() - self.start_time,
            'system_metrics': asdict(latest_system) if latest_system else None,
            'application_metrics': asdict(latest_app) if latest_app else None,
            'recent_alerts': [asdict(alert) for alert in list(self.performance_alerts)[-10:]],
            'health_status': await cache_manager.get('system_health'),
            'monitoring_status': {
                'is_running': self.is_running,
                'metrics_collected': len(self.system_metrics),
                'alerts_generated': len(self.performance_alerts)
            }
        }
    
    async def get_performance_trends(self, hours: int = 24) -> Dict[str, Any]:
        \"\"\"Get performance trends over specified time period\"\"\"
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Filter metrics by time
        recent_system = [m for m in self.system_metrics if m.timestamp > cutoff_time]
        recent_app = [m for m in self.app_metrics if m.timestamp > cutoff_time]
        
        # Calculate trends
        trends = {
            'system_trends': {
                'cpu_usage': [{'timestamp': m.timestamp.isoformat(), 'value': m.cpu_percent} for m in recent_system],
                'memory_usage': [{'timestamp': m.timestamp.isoformat(), 'value': m.memory_percent} for m in recent_system],
                'disk_usage': [{'timestamp': m.timestamp.isoformat(), 'value': m.disk_percent} for m in recent_system]
            },
            'application_trends': {
                'response_time': [{'timestamp': m.timestamp.isoformat(), 'value': m.response_time_avg} for m in recent_app],
                'error_rate': [{'timestamp': m.timestamp.isoformat(), 'value': m.error_rate} for m in recent_app],
                'requests_per_second': [{'timestamp': m.timestamp.isoformat(), 'value': m.requests_per_second} for m in recent_app]
            },
            'summary': {
                'avg_cpu': sum(m.cpu_percent for m in recent_system) / len(recent_system) if recent_system else 0,
                'avg_memory': sum(m.memory_percent for m in recent_system) / len(recent_system) if recent_system else 0,
                'avg_response_time': sum(m.response_time_avg for m in recent_app) / len(recent_app) if recent_app else 0,
                'total_requests': self.total_requests,
                'total_errors': self.error_count
            }
        }
        
        return trends
    
    async def get_alerts_summary(self) -> Dict[str, Any]:
        \"\"\"Get alerts summary\"\"\"
        recent_alerts = list(self.performance_alerts)
        
        # Group by severity
        severity_counts = defaultdict(int)
        for alert in recent_alerts:
            severity_counts[alert['severity']] += 1
        
        # Group by type
        type_counts = defaultdict(int)
        for alert in recent_alerts:
            type_counts[alert['type']] += 1
        
        return {
            'total_alerts': len(recent_alerts),
            'severity_distribution': dict(severity_counts),
            'type_distribution': dict(type_counts),
            'recent_alerts': [alert for alert in recent_alerts[-20:]]  # Last 20 alerts
        }


# Global monitoring service instance
MonitoringService = EnterpriseMonitoringService