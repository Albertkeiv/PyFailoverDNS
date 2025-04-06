from fastapi import FastAPI, Request
from api.models import ReportModel
from core.state import state
from core.logic import update_status
import logging

log = logging.getLogger("API")

app = FastAPI()

@app.post("/api/v1/report")
async def receive_report(report: ReportModel, request: Request):
    update_status(report)
    return {"status": "ok"}