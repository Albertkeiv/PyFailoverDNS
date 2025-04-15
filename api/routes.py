from fastapi import FastAPI, Request, Query, HTTPException, Header, status, Depends
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from typing import List, Optional, Dict
from core.logic import (
    update_status,
    extract_monitor_tasks, # Используем обновленную функцию
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
    redoc_url=None # Можно установить "/redoc" если нужно
)

class HealthCheckResponse(BaseModel):
    status: str
    timestamp: datetime
    components: Dict[str, str]

class ErrorResponse(BaseModel):
    detail: str

def validate_api_key_for_domain(domain: str, api_key: Optional[str] = None):
    """Validate API key against a specific domain's configuration"""
    domain_cfg = get_domain_config(domain) # Использует state_lock внутри

    if not domain_cfg:
        # Эта проверка уже должна быть сделана до вызова validate_api_key_for_domain
        # но добавим на всякий случай
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain '{domain}' not configured"
        )

    expected_token = domain_cfg.get("agent", {}).get("token")

    # Если токен не задан в конфиге для домена, разрешаем доступ без ключа? (Решить по политике безопасности)
    # Текущая логика: если токен задан, он должен совпадать. Если не задан, ключ не требуется.
    if expected_token and api_key != expected_token:
        log.warning(f"[AUTH FAIL] Invalid token provided for domain {domain}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key for the requested domain"
        )
    # Если expected_token пуст, проверка проходит (доступ разрешен без ключа)
    # Если нужен ключ всегда, добавить проверку: if not expected_token: raise ...

@app.post("/api/v1/report",
        response_model=Dict[str, str],
        responses={
            403: {"model": ErrorResponse},
            404: {"model": ErrorResponse},
            500: {"model": ErrorResponse} # Добавим 500
        })
async def receive_report(
    report: ReportModel,
    request: Request,
    x_api_key: Optional[str] = Depends(api_key_header) # Сделаем ключ опциональным здесь
):
    """
    Receive health check reports from monitoring agents.
    Requires X-API-Key matching the domain's agent token if configured.

    - **agent_id**: Unique identifier of the reporting agent
    - **domain**: Domain name being monitored
    - **target_ip**: IP address that was checked
    - **status**: Result of the health check (ok/fail)
    """
    try:
        # Validate domain existence first
        domain_cfg = get_domain_config(report.domain) # Эта функция использует lock
        if not domain_cfg:
            log.warning(f"Report received for non-configured domain: {report.domain}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Domain not configured"
            )

        # Authentication based on the domain's config
        validate_api_key_for_domain(report.domain, x_api_key)

        # Update status with locking using atomic_state_update
        def update_callback(s):
            # Дополнительные проверки данных репорта можно добавить здесь
            if report.status not in ["ok", "fail"]:
                log.warning(f"Invalid status '{report.status}' in report from {report.agent_id}")
                # Можно вернуть ошибку или проигнорировать
                # raise ValueError("Invalid status value")
                return {"status": "error", "message": "Invalid status value"} # Или вернуть ошибку клиенту

            # Передаем весь объект report в update_status
            update_status(report) # update_status сама разберет report
            log.debug(f"Report from {report.agent_id} for {report.domain} -> {report.target_ip} processed.")
            return {"status": "ok"} # Возвращаем успех

        # Выполняем обновление состояния
        result = atomic_state_update(update_callback)
        if result.get("status") == "error":
            # Если update_callback вернул ошибку валидации
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("message", "Invalid report data")
            )
        return result

    except HTTPException as he:
        # Просто перебрасываем HTTP исключения дальше
        raise he
    except Exception as e:
        log.exception(f"Report processing failed unexpectedly for domain {report.domain} from agent {report.agent_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during report processing"
        )

@app.get("/api/v1/tasks",
        response_model=Dict[str, List[MonitorTask]],
        responses={
            403: {"model": ErrorResponse}, # Оставим 403 на случай, если ключ вообще не предоставлен, а он нужен
            500: {"model": ErrorResponse}
        })
async def get_tasks(
    request: Request,
    tags: str = Query(..., description="Comma-separated list of agent tags (e.g., 'test,dc1')"),
    x_api_key: Optional[str] = Depends(api_key_header) # Ключ может быть опциональным, если есть домены без токена
):
    """
    Get monitoring tasks for an agent based on its tags and API key.
    Returns tasks only for domains where the provided X-API-Key matches
    the domain's configured agent token and the tags match.

    Returns list of monitoring jobs with parameters:
    - **check_name**: Unique job identifier
    - **target_ip**: IP to monitor
    - **port**: TCP port to check (or null for ICMP)
    - **type**: Check type (tcp/http/icmp)
    """
    if not x_api_key:
        # Если ключ не предоставлен, а он может быть нужен для некоторых доменов,
        # extract_monitor_tasks вернет пустой список для защищенных доменов.
         # Можно добавить явную ошибку 403, если *все* домены требуют ключ.
        # Но пока оставим так - агент без ключа получит задачи только для открытых доменов.
        log.warning("Agent requested tasks without providing an API key.")
        # pass # Продолжаем выполнение, extract_monitor_tasks отфильтрует

    try:
        tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
        if not tag_list:
            log.warning("Agent requested tasks with empty or invalid tags.")
            # Можно вернуть ошибку 400 или пустой список
            return {"tasks": []}

        # Используем обновленную функцию, передавая ключ
        # extract_monitor_tasks сама использует atomic_state_update
        tasks = extract_monitor_tasks(tag_list, x_api_key)

        log.info(f"Returning {len(tasks)} tasks for agent with tags: {tag_list} (key provided: {'yes' if x_api_key else 'no'})")
        # Преобразуем словари в модели MonitorTask для валидации ответа
        validated_tasks = [MonitorTask(**task) for task in tasks]
        return {"tasks": validated_tasks}

    except Exception as e:
        log.exception(f"Task retrieval failed unexpectedly for tags: {tags}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during task retrieval"
        )

# --- Остальные эндпоинты (status, status/domain, health) ---
# Эндпоинты статуса не требуют аутентификации по умолчанию, можно добавить если нужно.

@app.get("/api/v1/status",
        response_model=Dict[str, List[DomainStatus]],
        responses={500: {"model": ErrorResponse}})
async def status_summary():
    """Get current status overview for all monitored domains"""
    try:
        # get_domain_status использует atomic_state_update внутри
        status_data = get_domain_status()
        # Валидируем каждую запись перед возвратом (если модель DomainStatus строгая)
        validated_status = [DomainStatus(**item) for item in status_data]
        return {"status": validated_status}
    except Exception as e:
        log.exception("Status summary retrieval failed unexpectedly")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error retrieving status summary"
        )

@app.get("/api/v1/status/{domain}",
        response_model=DomainDetails,
        responses={
            404: {"model": ErrorResponse},
            500: {"model": ErrorResponse}
        })
async def status_domain(domain: str):
    """Get detailed status for a specific domain"""
    try:
        # Проверка существования домена в конфиге
        domain_cfg = get_domain_config(domain) # Использует lock
        if not domain_cfg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Domain not configured or not found"
            )

        # Получение деталей (использует atomic_state_update внутри)
        details_data = get_domain_details(domain)
        # Валидация моделью перед возвратом
        validated_details = DomainDetails(**details_data)
        return validated_details
    except HTTPException as he:
        raise he
    except Exception as e:
        log.exception(f"Domain status retrieval failed unexpectedly for: {domain}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error retrieving domain status"
        )

@app.get("/health",
        response_model=HealthCheckResponse,
        tags=["monitoring"],
        include_in_schema=False) # Не включать в OpenAPI спецификацию по умолчанию
async def health_check():
    """Endpoint for infrastructure health checks (e.g., load balancer)"""
    # Базовая проверка - API работает
    components = {
        "api": "ok",
        # Можно добавить проверки доступности DNS сервера (сложнее) или других зависимостей
    }
    overall_status = "ok"

    # Проверка загрузки конфигурации
    with state_lock:
        if not state.get("config"):
            components["config"] = "error"
            overall_status = "degraded"
        else:
            components["config"] = "ok"

    # TODO: Добавить проверку состояния DNS сервера, если возможно
    # Например, проверять жив ли поток DNS сервера
    # Или проверять последние ответы/ошибки DNS
    components["dns_server"] = "unknown" # Пример

    return HealthCheckResponse(
        status=overall_status,
        timestamp=datetime.now(timezone.utc),
        components=components
    )

# Error handlers - остаются без изменений
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # Логируем полное исключение
    log.exception(f"Unhandled exception during request processing: {request.method} {request.url}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected internal server error occurred."},
    )