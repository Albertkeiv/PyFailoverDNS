from fastapi import FastAPI, Request
from fastapi import FastAPI, Request, Query
from typing import List
from core.logic import update_status, extract_monitor_tasks
from api.models import ReportModel
from core.state import state
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