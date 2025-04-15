from fastapi import FastAPI, Request, Query, HTTPException, Header, status, Depends
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from typing import List, Optional, Dict
from core.logic import (
    update_status,
    extract_monitor_tasks,
    get_domain_status,
    get_domain_details,
    get_domain_config
)
from core.state import state, state_lock, atomic_state_update
from api.models import ReportModel, DomainStatus, DomainDetails, MonitorTask
from pydantic import BaseModel, Field
import logging
from datetime import datetime, timezone

log = logging.getLogger("API")

# Security
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

app = FastAPI(
    title="PyFailoverDNS API",
    description="API for managing DNS failover configuration and monitoring",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None
)

class HealthCheckResponse(BaseModel):
    status: str
    timestamp: datetime
    components: Dict[str, str]

class ErrorResponse(BaseModel):
    detail: str

def validate_api_key(domain: str, api_key: Optional[str] = None):
    """Validate API key against domain configuration"""
    with state_lock:
        domain_cfg = get_domain_config(domain)
    
    expected_token = domain_cfg.get("agent", {}).get("token")
    
    if expected_token and api_key != expected_token:
        log.warning(f"[AUTH FAIL] Invalid token for domain {domain}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API key"
        )

@app.post("/api/v1/report",
          response_model=Dict[str, str],
          responses={
              403: {"model": ErrorResponse},
              404: {"model": ErrorResponse}
          })
async def receive_report(
    report: ReportModel,
    request: Request,
    x_api_key: str = Depends(api_key_header)
):
    """
    Receive health check reports from monitoring agents
    
    - **agent_id**: Unique identifier of the reporting agent
    - **domain**: Domain name being monitored
    - **target_ip**: IP address that was checked
    - **status**: Result of the health check (ok/fail)
    """
    try:
        # Validate domain existence
        with state_lock:
            domain_cfg = get_domain_config(report.domain)
            if not domain_cfg:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Domain not configured"
                )

        # Authentication
        validate_api_key(report.domain, x_api_key)

        # Update status with locking
        def update_callback(s):
            update_status(report)
            return {"status": "ok"}
        
        result = atomic_state_update(update_callback)
        return result

    except HTTPException as he:
        raise he
    except Exception as e:
        log.error(f"Report processing failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/api/v1/tasks",
         response_model=Dict[str, List[MonitorTask]],
         responses={
             403: {"model": ErrorResponse},
             500: {"model": ErrorResponse}
         })
async def get_tasks(
    request: Request,
    tags: str = Query(..., description="Comma-separated list of agent tags"),
    x_api_key: str = Depends(api_key_header)
):
    """
    Get monitoring tasks for agents based on their tags
    
    Returns list of monitoring jobs with parameters:
    - **check_name**: Unique job identifier
    - **target_ip**: IP to monitor
    - **port**: TCP port to check
    - **type**: Check type (tcp/http)
    """
    try:
        tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
        
        with state_lock:
            tasks = extract_monitor_tasks(tag_list)
        
        valid_tasks = []
        for task in tasks:
            try:
                validate_api_key(task["domain"], x_api_key)
                valid_tasks.append(task)
            except HTTPException:
                continue
        
        log.info(f"Returning {len(valid_tasks)} tasks for tags: {tag_list}")
        return {"tasks": valid_tasks}

    except Exception as e:
        log.error(f"Task retrieval failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/api/v1/status",
         response_model=Dict[str, List[DomainStatus]],
         responses={500: {"model": ErrorResponse}})
async def status_summary():
    """Get current status overview for all monitored domains"""
    try:
        with state_lock:
            status_data = get_domain_status()
        return {"status": status_data}
    except Exception as e:
        log.error(f"Status summary failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/api/v1/status/{domain}",
         response_model=DomainDetails,
         responses={
             404: {"model": ErrorResponse},
             500: {"model": ErrorResponse}
         })
async def status_domain(domain: str):
    """Get detailed status for specific domain"""
    try:
        with state_lock:
            config_domains = []
            for zone in state["config"].get("zones", []):
                config_domains += zone.get("domains", {}).keys()

            if domain not in config_domains:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Domain not found"
                )

            return get_domain_details(domain)
    except HTTPException as he:
        raise he
    except Exception as e:
        log.error(f"Domain status failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

@app.get("/health",
         response_model=HealthCheckResponse,
         tags=["monitoring"],
         include_in_schema=False)
async def health_check():
    """Endpoint for infrastructure health checks"""
    components = {
        "dns": "ok",
        "api": "ok",
        "database": "ok"  # Пример, можно добавить реальные проверки
    }
    
    if not state.get("config"):
        components["config"] = "error"
    
    return {
        "status": "ok" if all(v == "ok" for v in components.values()) else "degraded",
        "timestamp": datetime.now(timezone.utc),
        "components": components
    }

# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    log.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"}
    )