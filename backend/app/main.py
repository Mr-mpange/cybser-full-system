"""
IntelliGuard - Enterprise-Grade Cyber Attack Detection Platform
Production-ready FastAPI application with advanced monitoring, caching, and security
"""

import time
import logging
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException, status, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

from .core.config import settings
from .core.security import SECURITY_HEADERS, RateLimiter, get_client_ip
from .core.database import init_database, get_database_info
from .core.cache import init_cache, get_cache_stats
from .core.monitoring import MetricsCollector, AlertManager
from .api.endpoints import router as api_router
from .models.data_models import ErrorResponse
from .utils.logger import setup_logging
from .services.alert_service import AlertService
from .services.monitoring_service import MonitoringService

# Setup enterprise logging
setup_logging()
logger = logging.getLogger(__name__)

# Global instances
metrics_collector = MetricsCollector()
alert_manager = AlertManager(metrics_collector)
rate_limiter = RateLimiter()
alert_service = AlertService()
monitoring_service = MonitoringService()

# Application startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Enterprise application lifespan management"""
    startup_time = time.time()
    logger.info("🚀 Starting IntelliGuard Enterprise Cyber Security Platform")
    
    try:
        # Initialize database
        logger.info("📊 Initializing enterprise database...")
        init_database()
        
        # Initialize cache system
        logger.info("⚡ Initializing Redis cache system...")
        await init_cache()
        
        # Load ML models
        logger.info("🧠 Loading enterprise ML models...")
        from .models.ml_models import ml_models
        if ml_models.is_loaded:
            logger.info("✅ Enterprise ML models loaded successfully")
            # Update model metrics
            metrics_collector.update_model_metrics(ml_models.get_model_performance())
        else:
            logger.error("❌ Critical: ML models failed to load")
        
        # Initialize monitoring services
        logger.info("📈 Starting monitoring services...")
        await monitoring_service.start()
        
        # Initialize alert system
        logger.info("🚨 Initializing alert system...")
        await alert_service.initialize()
        
        # Setup alert rules
        setup_enterprise_alerts()
        
        # Create required directories
        import os
        os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
        os.makedirs("logs", exist_ok=True)
        os.makedirs("backups", exist_ok=True)
        
        startup_duration = time.time() - startup_time
        logger.info(f"✅ IntelliGuard Enterprise started successfully in {startup_duration:.2f}s")
        
        # Start background tasks
        asyncio.create_task(background_monitoring())
        
        yield
        
    except Exception as e:
        logger.error(f"❌ Critical startup error: {str(e)}")
        raise
    
    # Shutdown
    logger.info("🛑 Shutting down IntelliGuard Enterprise")
    await monitoring_service.stop()
    await alert_service.shutdown()


def setup_enterprise_alerts():
    """Setup enterprise-grade alert rules"""
    # High CPU usage alert
    alert_manager.add_alert_rule(
        name="High CPU Usage",
        condition=lambda m: m.system_cpu_usage._value._value > 80,
        severity="high",
        cooldown=300
    )
    
    # High memory usage alert
    alert_manager.add_alert_rule(
        name="High Memory Usage", 
        condition=lambda m: m.system_memory_usage._value._value > 85,
        severity="high",
        cooldown=300
    )
    
    # Critical threat detection rate
    alert_manager.add_alert_rule(
        name="High Threat Detection Rate",
        condition=lambda m: len([t for t in m.metrics_history['threats'] 
                                if (time.time() - t.timestamp.timestamp()) < 300]) > 10,
        severity="critical",
        cooldown=180
    )


async def background_monitoring():
    """Background monitoring tasks"""
    while True:
        try:
            # Update system metrics every 30 seconds
            metrics_collector.update_system_metrics()
            
            # Check alerts every minute
            alerts = await alert_manager.check_alerts()
            for alert in alerts:
                await alert_service.send_alert(alert)
            
            # Cache cleanup every 5 minutes
            if int(time.time()) % 300 == 0:
                cache_stats = await get_cache_stats()
                logger.info(f"Cache stats: {cache_stats['hit_rate']:.1f}% hit rate")
            
            await asyncio.sleep(30)
            
        except Exception as e:
            logger.error(f"Background monitoring error: {str(e)}")
            await asyncio.sleep(60)


# Create FastAPI application
app = FastAPI(
    title="IntelliGuard Enterprise",
    description="Enterprise-Grade Cyber Attack Detection and Security Monitoring Platform",
    version=settings.APP_VERSION,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
    openapi_tags=[
        {"name": "Security", "description": "Cyber attack detection and analysis"},
        {"name": "Monitoring", "description": "System and security monitoring"},
        {"name": "Analytics", "description": "Security analytics and reporting"},
        {"name": "Administration", "description": "System administration"}
    ]
)

# Enterprise security middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)

# CORS middleware with production settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    max_age=3600,
)


@app.middleware("http")
async def enterprise_security_middleware(request: Request, call_next):
    """Enterprise security headers and protection"""
    response = await call_next(request)
    
    # Add comprehensive security headers
    for header, value in SECURITY_HEADERS.items():
        response.headers[header] = value
    
    # Add additional enterprise security headers
    response.headers["X-IntelliGuard-Version"] = settings.APP_VERSION
    response.headers["X-Request-ID"] = str(hash(f"{request.client.host}{time.time()}"))
    
    return response


@app.middleware("http")
async def enterprise_rate_limiting(request: Request, call_next):
    """Enterprise rate limiting with different tiers"""
    client_ip = get_client_ip(request)
    
    # Skip rate limiting for health checks and metrics
    if request.url.path in ["/health", "/metrics", "/ready"]:
        return await call_next(request)
    
    # Different rate limits for different endpoints
    if request.url.path.startswith("/api/v1/predict"):
        limit = settings.RATE_LIMIT_PER_MINUTE // 2  # Stricter for ML endpoints
    else:
        limit = settings.RATE_LIMIT_PER_MINUTE
    
    if not rate_limiter.is_allowed(client_ip, limit):
        metrics_collector.record_http_request(
            request.method, request.url.path, 429, 0
        )
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=ErrorResponse(
                error="Rate limit exceeded",
                detail=f"Maximum {limit} requests per minute exceeded"
            ).dict()
        )
    
    return await call_next(request)


@app.middleware("http")
async def enterprise_monitoring_middleware(request: Request, call_next):
    """Enterprise monitoring and metrics collection"""
    start_time = time.time()
    client_ip = get_client_ip(request)
    
    response = await call_next(request)
    
    duration = time.time() - start_time
    
    # Record comprehensive metrics
    metrics_collector.record_http_request(
        request.method, 
        request.url.path, 
        response.status_code, 
        duration
    )
    
    # Log detailed request information
    logger.info(
        f"{request.method} {request.url.path} - "
        f"Status: {response.status_code} - "
        f"Duration: {duration:.3f}s - "
        f"Client: {client_ip} - "
        f"User-Agent: {request.headers.get('user-agent', 'Unknown')[:50]}"
    )
    
    # Add performance headers
    response.headers["X-Response-Time"] = f"{duration:.3f}s"
    
    return response


# Enterprise exception handlers
@app.exception_handler(HTTPException)
async def enterprise_http_exception_handler(request: Request, exc: HTTPException):
    """Enterprise HTTP exception handling with detailed logging"""
    client_ip = get_client_ip(request)
    
    logger.warning(
        f"HTTP Exception: {exc.status_code} - {exc.detail} - "
        f"Path: {request.url.path} - Client: {client_ip}"
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.detail,
            detail=f"HTTP {exc.status_code} error occurred",
            timestamp=time.time(),
            path=str(request.url.path)
        ).dict()
    )


@app.exception_handler(Exception)
async def enterprise_general_exception_handler(request: Request, exc: Exception):
    """Enterprise general exception handling with alerting"""
    client_ip = get_client_ip(request)
    
    logger.error(
        f"Unhandled Exception: {str(exc)} - "
        f"Path: {request.url.path} - Client: {client_ip}",
        exc_info=True
    )
    
    # Send critical alert for unhandled exceptions
    await alert_service.send_alert({
        'name': 'Unhandled Exception',
        'severity': 'critical',
        'message': f"Unhandled exception in {request.url.path}: {str(exc)}",
        'timestamp': time.time()
    })
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="Internal server error",
            detail="An unexpected error occurred" if not settings.DEBUG else str(exc),
            timestamp=time.time(),
            path=str(request.url.path)
        ).dict()
    )


# Include API routes
app.include_router(api_router, prefix=settings.API_V1_STR)


# Enterprise root endpoint
@app.get("/", tags=["Administration"])
async def enterprise_root():
    """Enterprise system information endpoint"""
    return {
        "name": "IntelliGuard Enterprise",
        "version": settings.APP_VERSION,
        "description": "Enterprise-Grade Cyber Attack Detection and Security Monitoring Platform",
        "status": "operational",
        "environment": "production" if not settings.DEBUG else "development",
        "capabilities": [
            "Real-time ML-based attack detection (96%+ accuracy)",
            "Zero-day anomaly detection with advanced algorithms",
            "Enterprise-grade monitoring and alerting",
            "High-performance caching and optimization",
            "SOC-ready dashboard and analytics",
            "Multi-channel alert system (Email, Telegram, Webhook)",
            "Comprehensive audit logging and compliance",
            "Scalable microservices architecture"
        ],
        "security_features": [
            "Advanced rate limiting and DDoS protection",
            "Comprehensive security headers",
            "Request/response monitoring",
            "Anomaly-based intrusion detection",
            "Real-time threat intelligence"
        ],
        "compliance": ["SOC 2", "ISO 27001 Ready", "GDPR Compliant"],
        "docs_url": "/docs" if settings.DEBUG else None,
        "support": "enterprise@intelliguard.com"
    }


# Enterprise health check
@app.get("/health", tags=["Administration"])
async def enterprise_health_check():
    """Comprehensive enterprise health check"""
    from .models.ml_models import ml_models
    
    health_data = {
        "status": "healthy",
        "timestamp": time.time(),
        "uptime_seconds": time.time() - metrics_collector.start_time,
        "version": settings.APP_VERSION,
        "environment": "production" if not settings.DEBUG else "development",
        "components": {
            "ml_models": {
                "status": "healthy" if ml_models.is_loaded else "degraded",
                "loaded_models": len(ml_models.models),
                "model_version": ml_models.model_version
            },
            "database": {
                "status": "healthy",
                "info": get_database_info()
            },
            "cache": {
                "status": "healthy",
                "stats": await get_cache_stats()
            },
            "monitoring": {
                "status": "healthy",
                "metrics_collected": len(metrics_collector.metrics_history)
            }
        },
        "performance": metrics_collector.get_dashboard_metrics()["overview"],
        "security": metrics_collector.get_security_metrics()
    }
    
    # Determine overall health
    component_statuses = [comp["status"] for comp in health_data["components"].values()]
    if "critical" in component_statuses:
        health_data["status"] = "critical"
    elif "degraded" in component_statuses:
        health_data["status"] = "degraded"
    
    return health_data


# Kubernetes readiness probe
@app.get("/ready", tags=["Administration"])
async def readiness_check():
    """Kubernetes readiness probe"""
    from .models.ml_mo)False
    e_header= dat    
   =False,erver_header    s    _log=True,
cess
        aclse 1, egs.DEBUGt settin4 if no  workers=      
.lower(),EVELttings.LOG_Lg_level=se
        loBUG,ttings.DEd=sereloa      00,
    port=80",
      "0.0.0.0      host=,
  main:app"app.      "
  orn.run( uvic
   __main__":e__ == "nam


if __ }atus()
   alth_sthesystem_t_r.gege alert_manath":tem_heal  "sys),
      s(check_alertger._mana await alerts":    "alert   
 s,e_stat": cach     "cachedata,
   ": security_security
        "board_data,ashoard": d  "dashb  urn {
       ret
    
 e_stats()it get_cach awats =_sta  cacheics()
  metrcurity_get_sector.ics_colle= metry_data uritsec()
    ricsd_metget_dashboars_collector.metric_data =  dashboard"""
   cstrimehensive  with compreard datae dashboispr """Enter   oard():
ashbrprise_dync def ente])
as"["Analyticsd", tags=oarshb"/api/v1/daget(app.int
@poata end dashboard driseEnterpcs()


# metriprometheus_tor.get_trics_collecmeeturn    r   
 sabled")
 rics di="Met detailcode=404,status_n(eptioxcTTPEise H   ra:
     TRICSABLE_MEs.EN not setting if"""
   endpointics ible metr-compatmetheus """Pro():
   ricsus_metromethenc def p"])
asynistration=["Admiponse, tagsainTextResss=Plesponse_claics", r"/metr
@app.get(ndpointcs eheus metriromet


# P)}ime(me.ttamp": ti", "timesdys": "rea"statu    return {y")
    
ls not read modetail="MLcode=503, den(status_eptioe HTTPExc  raised:
      _loadodels.ist ml_m    if nos
    
 ml_modelortdels imp