from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime

class ReportModel(BaseModel):
    agent_id: str
    timestamp: datetime
    check_name: str
    domain: str
    type: str
    target_ip: str
    port: Optional[int]
    status: Literal["ok", "fail"]
    latency_ms: Optional[float]
    reason: Optional[str] = None