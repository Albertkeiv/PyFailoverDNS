"""
PyFailoverDNS — отказоустойчивый DNS-сервер и система мониторинга
ОБЪЕДИНЕННЫЙ ИСПОЛНЯЕМЫЙ ФАЙЛ (готов для сборки в бинарник)
"""

import os
import sys
import argparse
import asyncio
import socket
import logging
import threading
import signal
from contextlib import closing
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
import random
import yaml
from fastapi import FastAPI, HTTPException, Depends, Query, Header,  Request
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from dnslib.server import BaseResolver, DNSServer
from dnslib import RR, A, QTYPE, RCODE
import uvicorn

###############################################################################
# ЛОГГИРОВАНИЕ
###############################################################################
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger("PyFailoverDNS")

###############################################################################
# ГЛОБАЛЬНОЕ СОСТОЯНИЕ
###############################################################################
state_lock = threading.RLock()
state = {"config": None, "checks": {}, "resolved": {}}

def init_state(config: dict):
    with state_lock:
        state["config"] = config

def update_state(callback):
    with state_lock:
        return callback(state)

###############################################################################
# МОДЕЛИ
###############################################################################
class ReportModel(BaseModel):
    agent_id: str
    timestamp: datetime
    check_name: str
    domain: str
    type: str
    target_ip: str
    port: Optional[int]
    status: str
    latency_ms: Optional[float] = None
    reason: Optional[str] = None

class MonitorTask(BaseModel):
    check_name: str
    domain: str
    target_ip: str
    port: Optional[int]
    type: str
    timeout_sec: int
    interval_sec: int

class DomainStatus(BaseModel):
    domain: str
    live_ips: List[str]
    using_fallback: bool
    fallback_ips: List[str]
    agents: List[Dict]
    last_updated: Optional[datetime] = None

class DomainDetails(BaseModel):
    domain: str
    check_type: str
    live: bool
    fallback_ips: List[str]
    ip_checks: Dict[str, dict]

###############################################################################
# ЗАГРУЗКА КОНФИГА
###############################################################################
def load_config(path: str) -> dict:
    with open(path) as f:
        config = yaml.safe_load(f)

    config.setdefault('dns', {})
    config.setdefault('api', {})
    config.setdefault('zones', [])

    for section in [('dns', 'listen_ip'), ('dns', 'listen_port'), ('api', 'listen_ip'), ('api', 'listen_port')]:
        if not config.get(section[0], {}).get(section[1]):
            raise ValueError(f"Missing config value: {section[0]}.{section[1]}")

    return config

###############################################################################
# ЛОГИКА
###############################################################################
def get_domain_config(domain: str) -> dict:
    for zone in state["config"].get("zones", []):
        if domain in zone.get("domains", {}):
            return zone["domains"][domain]
    return {}

def get_fallback_ips(domain_cfg: dict) -> List[str]:
    return domain_cfg.get("fallback", ["127.0.0.1"])

def get_alive_ips(domain: str) -> List[str]:
    checks = state.get("checks", {}).get(domain, {})
    cfg = get_domain_config(domain)
    timeout = cfg.get("server", {}).get("timeout_sec", 60)
    now = datetime.now(timezone.utc)
    alive = []
    for ip, agents in checks.items():
        for report in agents.values():
            ts = report.get("timestamp")
            if isinstance(ts, datetime) and (now - ts).total_seconds() <= timeout and report.get("status") == "ok":
                alive.append(ip)
                break
    return sorted(set(alive))

def get_dns_response(domain: str) -> Tuple[List[str], int, bool]:
    """
    Returns (ips, ttl, is_fallback):
    - ips: список A‑записей для ответа (живые или fallback)
    - ttl: оставшийся TTL в секундах
    - is_fallback: флаг, что это fallback‑адреса
    Политики: «any» (по умолчанию) и «priority».
    """
    now = datetime.now(timezone.utc)
    cfg = get_domain_config(domain)

    # Берём глобальный TTL из раздела dns.resolve_cache_ttl
    resolve_ttl = state["config"]["dns"].get("resolve_cache_ttl", 5)

    # Попытка взять из кеша
    cache = state["resolved"].get(domain)
    if cache:
        age = (now - cache["timestamp"]).total_seconds()
        if age <= cache["ttl"]:
            return cache["ips"], int(resolve_ttl - age), cache["fallback"]

    # Вычисляем «живые» и fallback IP
    alive = get_alive_ips(domain)
    fallback = get_fallback_ips(cfg)

    # Политика priority: среди живых берём только с макс. приоритетом
    if cfg.get("server", {}).get("policy") == "priority" and alive:
        priorities = {
            t["ip"]: t.get("priority", 0)
            for t in cfg.get("monitor", {}).get("targets", [])
        }
        max_pr = max(priorities.get(ip, 0) for ip in alive)
        ips = [ip for ip in alive if priorities.get(ip, 0) == max_pr]
        is_fallback = False

    # Политика any или другие: возвращаем все живые
    elif alive:
        ips = alive
        is_fallback = False

    # Нет живых — возвращаем fallback
    else:
        ips = fallback
        is_fallback = True

    # Сохраняем в кеш и возвращаем
    state["resolved"][domain] = {
        "ips": ips,
        "timestamp": now,
        "ttl": resolve_ttl,
        "fallback": is_fallback
    }
    return ips, resolve_ttl, is_fallback

def update_status(report: ReportModel):
    with state_lock:
        domain_checks = state["checks"].setdefault(report.domain, {})
        ip_checks = domain_checks.setdefault(report.target_ip, {})
        # Вместо report.dict() используем report.model_dump()
        ip_checks[report.agent_id] = report.model_dump()
        if report.domain in state["resolved"]:
            del state["resolved"][report.domain]

def generate_tasks(tags: List[str], token: Optional[str]) -> List[MonitorTask]:
    tasks = []
    for zone in state["config"].get("zones", []):
        for domain, cfg in zone.get("domains", {}).items():
            expected_token = cfg.get("agent", {}).get("token")
            if expected_token and token != expected_token:
                continue
            monitor = cfg.get("monitor", {})
            tag_match = monitor.get("monitor_tag")
            if isinstance(tag_match, str):
                tag_match = [t.strip() for t in tag_match.replace(",", " ").split()]
            if not set(tags) & set(tag_match):
                continue
            for t in monitor.get("targets", []):
                tasks.append(MonitorTask(
                    check_name=f"{domain}:{t['ip']}:{t.get('port', 'icmp')}",
                    domain=domain,
                    target_ip=t['ip'],
                    port=t.get("port"),
                    type=monitor.get("mode", "tcp"),
                    timeout_sec=cfg.get("agent", {}).get("timeout_sec", 5),
                    interval_sec=cfg.get("agent", {}).get("interval_sec", 30)
                ))
    return tasks

###############################################################################
# DNS РЕЗОЛВЕР
###############################################################################
class FailoverResolver(BaseResolver):
    def resolve(self, request, handler):
        """
        Обёрнутая в try/except версия resolver-а:
        при ошибках логируем и возвращаем SERVFAIL,
        иначе отвечаем A‑записями с рандомизированным порядком.
        """
        try:
            qname = str(request.q.qname).rstrip('.')
            qtype = QTYPE[request.q.qtype]
            reply = request.reply()

            if qtype == 'A':
                ips, ttl, _ = get_dns_response(qname)
                # формируем новую перемешанную копию, не мутируя кеш
                ips_to_send = random.sample(ips, len(ips))
                for ip in ips_to_send:
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl))

            return reply

        except Exception as e:
            log.exception(f"DNS resolver error for {request.q.qname}: {e}")
            # Возвращаем SERVFAIL
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply

###############################################################################
# API
###############################################################################
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
app = FastAPI()

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Глобальный обработчик для FastAPI:
    все непойманные исключения превратятся в 500 Internal Server Error,
    а полная трассировка попадёт в лог.
    """
    log.exception(f"Unhandled exception in API path {request.url.path}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"}
    )

@app.post("/api/v1/report")
async def report(report: ReportModel, x_api_key: Optional[str] = Depends(api_key_header)):
    cfg = get_domain_config(report.domain)
    if not cfg:
        raise HTTPException(status_code=404, detail="Unknown domain")
    if cfg.get("agent", {}).get("token") and cfg["agent"]["token"] != x_api_key:
        raise HTTPException(status_code=403, detail="Invalid token")
    update_status(report)
    return {"status": "ok"}

@app.get("/api/v1/tasks")
async def tasks(tags: str = Query(...), x_api_key: Optional[str] = Depends(api_key_header)):
    tags_list = [t.strip() for t in tags.split(",") if t.strip()]
    result = generate_tasks(tags_list, x_api_key)
    return {"tasks": result}

@app.get("/api/v1/status")
async def status():
    res = []
    now = datetime.now(timezone.utc)
    for zone in state["config"].get("zones", []):
        for domain, cfg in zone.get("domains", {}).items():
            live = get_alive_ips(domain)
            agents = []
            for ip, reports in state.get("checks", {}).get(domain, {}).items():
                for agent_id, rep in reports.items():
                    agents.append({"agent_id": agent_id, "checked_ips": [ip], "last_seen": rep["timestamp"]})
            res.append(DomainStatus(
                domain=domain,
                live_ips=live,
                using_fallback=not bool(live),
                fallback_ips=get_fallback_ips(cfg),
                agents=agents,
                last_updated=now
            ))
    return {"status": res}

@app.get("/api/v1/status/{domain}")
async def status_detail(domain: str):
    cfg = get_domain_config(domain)
    if not cfg:
        raise HTTPException(status_code=404, detail="Unknown domain")
    now = datetime.now(timezone.utc)
    checks = {}
    for ip, reports in state.get("checks", {}).get(domain, {}).items():
        checks[ip] = {agent_id: r for agent_id, r in reports.items()}
    live = get_alive_ips(domain)
    return DomainDetails(
        domain=domain,
        check_type=cfg.get("monitor", {}).get("mode", "tcp"),
        live=bool(live),
        fallback_ips=get_fallback_ips(cfg),
        ip_checks=checks
    )

###############################################################################
# ЗАПУСК
###############################################################################
def check_port(ip: str, port: int) -> bool:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind((ip, port))
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
            s.bind((ip, port))
        return True
    except:
        return False

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = load_config(args.config)
    init_state(config)

    if not check_port(config["dns"]["listen_ip"], config["dns"]["listen_port"]):
        log.error("DNS port in use")
        sys.exit(1)

    # 1) DNS-сервер
    resolver = FailoverResolver()
    dns_server = DNSServer(
        resolver,
        port=config["dns"]["listen_port"],
        address=config["dns"]["listen_ip"]
    )
    dns_thread = threading.Thread(target=dns_server.start)
    dns_thread.daemon = True
    dns_thread.start()

    # 2) Uvicorn API
    uv_config = uvicorn.Config(
        app,
        host=config["api"]["listen_ip"],
        port=config["api"]["listen_port"],
        log_level="info",
    )
    server = uvicorn.Server(uv_config)

    # Отключаем встроенные signal‑handlers Uvicorn
    server.install_signal_handlers = lambda: None

    # Наш общий обработчик завершения
    def _shutdown(signum, frame):
        log.info(f"Signal {signum} received: shutting down…")
        # говорим Uvicorn'у выйти из serve()
        server.should_exit = True
        # останавливаем DNS
        dns_server.stop()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # Запускаем API (блокирующий until server.should_exit=True)
    await server.serve()

    # Ждём, пока DNS‑поток корректно завершится
    log.info("Waiting for DNS thread to stop…")
    dns_thread.join()
    log.info("Shutdown complete.")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except Exception:
        log.exception("Fatal error in main")
        sys.exit(1)