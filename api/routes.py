from fastapi import FastAPI, Request, Query, HTTPException
from typing import List
from core.logic import update_status, extract_monitor_tasks,get_domain_status,get_domain_details
from api.models import ReportModel
from core.state import state
from fastapi.responses import JSONResponse
import logging

log = logging.getLogger("API")

app = FastAPI()

@app.post("/api/v1/report")
async def receive_report(report: ReportModel, request: Request):
    update_status(report)
    return {"status": "ok"}

@app.get("/api/v1/tasks")
async def get_tasks(tags: str = Query(..., description="Через запятую: 'eu-west4,gcp'")):
    tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
    tasks = extract_monitor_tasks(tag_list)
    log.warning(f"[DEBUG] Returning {len(tasks)} tasks for tags: {tag_list}")
    for task in tasks:
        log.warning(f"[DEBUG] Task: {task}")
        
    return {"tasks": tasks}

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