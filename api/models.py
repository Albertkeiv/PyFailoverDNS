from pydantic import BaseModel
from typing import Optional

class ReportModel(BaseModel):
    agent_id: str
    timestamp: str
    check_name: str
    domain: str
    type: str
    target_ip: str
    port: Optional[int]
    status: str  # "ok" / "fail"
    latency_ms: Optional[float]
    reason: Optional[str] = None