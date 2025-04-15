from pydantic import BaseModel, Field
from typing import Optional, Literal, List, Dict
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

# Добавляем новые модели
class AgentStatus(BaseModel):
    agent_id: str
    last_seen: datetime
    checked_ips: List[str]

class DomainStatus(BaseModel):
    domain: str
    live_ips: List[str]
    using_fallback: bool
    fallback_ips: List[str]
    agents: List[AgentStatus]
    last_updated: Optional[datetime]

class IPCheck(BaseModel):
    status: Literal["ok", "fail"]
    port: Optional[int]
    agents: List[Dict]

class DomainDetails(BaseModel):
    domain: str
    check_type: str
    live: bool
    fallback_ips: List[str]
    ip_checks: Dict[str, IPCheck]

class MonitorTask(BaseModel):
    check_name: str
    domain: str
    target_ip: str
    port: int
    type: str
    timeout_sec: int
    interval_sec: int

class HealthCheckResponse(BaseModel):
    status: str
    timestamp: datetime
    components: Dict[str, str]