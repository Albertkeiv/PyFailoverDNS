from fastapi import FastAPI, Request, Query, HTTPException, Header
from typing import List
from core.logic import update_status, extract_monitor_tasks, get_domain_status, get_domain_details, get_domain_config
from api.models import ReportModel
from core.state import state
from fastapi.responses import JSONResponse
import logging

log = logging.getLogger("API")

app = FastAPI()

@app.post("/api/v1/report")
async def receive_report(
    report: ReportModel,
    request: Request,
    x_api_key: str = Header(None)
):
    domain_cfg = get_domain_config(report.domain)
    expected_token = domain_cfg.get("agent", {}).get("token")

    if expected_token and x_api_key != expected_token:
        log.warning(f"[AUTH FAIL] Invalid token for domain {report.domain}")
        raise HTTPException(status_code=403, detail="Invalid API key")

    update_status(report)
    return {"status": "ok"}

@app.get("/api/v1/tasks")
async def get_tasks(
    request: Request,
    tags: str = Query(..., description="Через запятую: 'eu-west4,gcp'")
):
    tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
    tasks = extract_monitor_tasks(tag_list)

    valid_tasks = []

    for task in tasks:
        domain_cfg = get_domain_config(task["domain"])
        expected_token = domain_cfg.get("agent", {}).get("token")

        if expected_token and request.headers.get("X-API-Key") != expected_token:
            log.warning(f"[AUTH FAIL] Invalid token for tasks of domain {task['domain']}")
            continue

        valid_tasks.append(task)

    log.warning(f"[DEBUG] Returning {len(valid_tasks)} tasks for tags: {tag_list}")
    for task in valid_tasks:
        log.warning(f"[DEBUG] Task: {task}")

    return {"tasks": valid_tasks}

@app.get("/api/v1/status")
async def status_summary():
    return JSONResponse(content={"status": get_domain_status()})

@app.get("/api/v1/status/{domain}")
async def status_domain(domain: str):
    config_domains = []
    for zone in state["config"].get("zones", []):
        config_domains += zone.get("domains", {}).keys()

    if domain not in config_domains:
        raise HTTPException(status_code=404, detail="Domain not found")

    return get_domain_details(domain)