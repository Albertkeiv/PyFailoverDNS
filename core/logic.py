from core.state import state, state_lock, atomic_state_update
from datetime import datetime, timezone
import logging
import random
import heapq
from typing import List, Tuple, Dict, Optional
import ipaddress

logger = logging.getLogger("LOGIC")

def update_status(report) -> None:
    """Обновляет статус проверок с блокировкой состояния"""
    def update_callback(s):
        domain = report.domain
        host = report.target_ip
        agent = report.agent_id

        checks = s.setdefault("checks", {}).setdefault(domain, {}).setdefault(host, {})
        checks[agent] = {
            "status": report.status,
            "timestamp": report.timestamp,
            "latency_ms": report.latency_ms
        }

        if domain in s.get("resolved", {}):
            del s["resolved"][domain]

        logger.info(f"Received status from {agent} for {domain} → {host}: {report.status}")
    
    atomic_state_update(update_callback)

def get_domain_config(domain: str) -> dict:
    """Возвращает конфигурацию домена с блокировкой чтения"""
    with state_lock:
        for zone in state.get("config", {}).get("zones", []):
            if domain in zone.get("domains", {}):
                return zone["domains"][domain]
        return {}

def get_alive_ips(domain: str) -> List[str]:
    """Возвращает список живых IP с учетом политик и приоритетов"""
    def process_callback(s):
        checks = s.get("checks", {}).get(domain, {})
        domain_cfg = get_domain_config(domain)
        timeout_sec = domain_cfg.get("server", {}).get("timeout_sec", 60)
        policy = domain_cfg.get("server", {}).get("policy", "any")
        now = datetime.now(timezone.utc)

        valid_hosts = []
        for ip, agents in checks.items():
            for agent_data in agents.values():
                ts = agent_data["timestamp"]
                if (now - ts).total_seconds() <= timeout_sec and agent_data["status"] == "ok":
                    valid_hosts.append(ip)
                    break

        if not valid_hosts:
            logger.warning(f"All checks for {domain} are expired or failed")
            return get_fallback_list(domain, domain_cfg)

        return sort_ips_by_policy(valid_hosts, domain_cfg, policy)
    
    return atomic_state_update(process_callback)

def sort_ips_by_policy(ips: List[str], domain_cfg: dict, policy: str) -> List[str]:
    """Сортирует IP согласно выбранной политике"""
    if policy == "priority":
        targets = domain_cfg.get("monitor", {}).get("targets", [])
        priorities = {t["ip"]: t.get("priority", 1000) for t in targets}
        
        # Сортировка с сохранением порядка одинаковых приоритетов
        return sorted(ips, key=lambda ip: priorities.get(ip, 1000))
    else:
        random.shuffle(ips)
        return ips

def get_fallback_list(domain: str, domain_cfg: Optional[dict] = None) -> List[str]:
    """Возвращает fallback IP список с валидацией"""
    if not domain_cfg:
        domain_cfg = get_domain_config(domain)
    
    fallback = domain_cfg.get("fallback", [])
    if not isinstance(fallback, list) or len(fallback) == 0:
        logger.error(f"Invalid fallback for {domain}, using default")
        return ["127.0.0.1"]
    
    # Валидация IP адресов
    valid_ips = []
    for ip in fallback:
        try:
            ipaddress.ip_address(ip)
            valid_ips.append(ip)
        except ValueError:
            logger.warning(f"Invalid fallback IP {ip} for domain {domain}")
    
    return valid_ips or ["127.0.0.1"]

def get_dns_response(domain: str) -> Tuple[List[str], int]:
    """Генерирует DNS ответ с учетом кеша и политик"""
    def process_callback(s):
        if domain in s.get("resolved", {}):
            cached = s["resolved"][domain]
            ttl = get_ttl_for_domain(domain)
            now = datetime.now(timezone.utc)
            
            if (now - cached["timestamp"]).total_seconds() <= ttl:
                logger.debug(f"[CACHE] {domain} → {cached['ips']}")
                return apply_rr_policy(cached["ips"], domain)

        # Кеш устарел или отсутствует
        ip_list = get_alive_ips(domain)
        ttl = get_ttl_for_domain(domain)
        
        s["resolved"][domain] = {
            "ips": ip_list,
            "timestamp": datetime.now(timezone.utc)
        }
        
        logger.info(f"[RESOLVE] {domain} → {ip_list}")
        return apply_rr_policy(ip_list, domain), ttl
    
    return atomic_state_update(process_callback)

def apply_rr_policy(ip_list: List[str], domain: str) -> List[str]:
    """Применяет round-robin балансировку"""
    if len(ip_list) <= 1:
        return ip_list
    
    with state_lock:
        rr_idx = state.setdefault("rr_counters", {}).get(domain, 0)
        state["rr_counters"][domain] = (rr_idx + 1) % len(ip_list)
    
    return ip_list[rr_idx:] + ip_list[:rr_idx]

def get_ttl_for_domain(domain: str) -> int:
    """Возвращает TTL для домена"""
    with state_lock:
        return state.get("config", {}).get("dns", {}).get("resolve_cache_ttl", 5)

def get_domain_status() -> List[dict]:
    """Генерирует статус всех доменов"""
    def process_callback(s):
        result = []
        now = datetime.now(timezone.utc)
        
        for zone in s.get("config", {}).get("zones", []):
            for domain, cfg in zone.get("domains", {}).items():
                result.append(build_domain_status(domain, cfg, now))
        
        return result
    
    return atomic_state_update(process_callback)

def build_domain_status(domain: str, cfg: dict, now: datetime) -> dict:
    """Строит статус для одного домена"""
    checks = state.get("checks", {}).get(domain, {})
    timeout = cfg.get("server", {}).get("timeout_sec", 60)
    
    status = {
        "domain": domain,
        "live_ips": [],
        "using_fallback": False,
        "fallback_ips": cfg.get("fallback", []),
        "agents": [],
        "last_updated": None
    }
    
    # Анализ проверок
    latest_ts = None
    for ip, agents in checks.items():
        for agent_id, data in agents.items():
            ts = data["timestamp"]
            if (now - ts).total_seconds() <= timeout and data["status"] == "ok":
                status["live_ips"].append(ip)
            
            update_agent_status(status["agents"], agent_id, ip, ts)
            latest_ts = max(latest_ts, ts) if latest_ts else ts
    
    status["live_ips"] = sorted(set(status["live_ips"]))
    status["using_fallback"] = len(status["live_ips"]) == 0
    status["last_updated"] = latest_ts.isoformat() if latest_ts else None
    
    return status

def update_agent_status(agents: list, agent_id: str, ip: str, ts: datetime) -> None:
    """Обновляет информацию об агентах"""
    existing = next((a for a in agents if a["agent_id"] == agent_id), None)
    if existing:
        existing["checked_ips"].append(ip)
        if ts > existing["last_seen"]:
            existing["last_seen"] = ts
    else:
        agents.append({
            "agent_id": agent_id,
            "last_seen": ts,
            "checked_ips": [ip]
        })

def get_domain_details(domain: str) -> dict:
    """Возвращает детальную информацию о домене"""
    def process_callback(s):
        cfg = get_domain_config(domain)
        checks = s.get("checks", {}).get(domain, {})
        now = datetime.now(timezone.utc)
        
        return {
            "domain": domain,
            "check_type": cfg.get("monitor", {}).get("mode", "tcp"),
            "live": any(ip_has_live_checks(ip, checks, cfg, now) for ip in checks),
            "fallback_ips": cfg.get("fallback", []),
            "ip_checks": build_ip_checks(checks, cfg, now)
        }
    
    return atomic_state_update(process_callback)

def ip_has_live_checks(ip: str, checks: dict, cfg: dict, now: datetime) -> bool:
    """Проверяет есть ли живые проверки для IP"""
    timeout = cfg.get("server", {}).get("timeout_sec", 60)
    return any(
        (now - data["timestamp"]).total_seconds() <= timeout
        and data["status"] == "ok"
        for agent_data in checks.get(ip, {}).values()
    )

def build_ip_checks(checks: dict, cfg: dict, now: datetime) -> dict:
    """Формирует информацию о проверках IP"""
    timeout = cfg.get("server", {}).get("timeout_sec", 60)
    ip_checks = {}
    
    for ip, agents in checks.items():
        reports = []
        for agent_id, data in agents.items():
            reports.append({
                "agent_id": agent_id,
                "status": data["status"],
                "timestamp": data["timestamp"].isoformat(),
                "latency_ms": data.get("latency_ms"),
                "expired": (now - data["timestamp"]).total_seconds() > timeout
            })
        
        ip_checks[ip] = {
            "status": "ok" if any(r["status"] == "ok" and not r["expired"] for r in reports) else "fail",
            "port": next((t["port"] for t in cfg.get("monitor", {}).get("targets", []) 
                        if t.get("ip") == ip), None),
            "agents": reports
        }
    
    return ip_checks

def extract_monitor_tasks(agent_tags: List[str]) -> List[dict]:
    """Генерирует задачи мониторинга на основе тегов агента"""
    def process_callback(s):
        tasks = []
        config = s.get("config", {})
        
        for zone in config.get("zones", []):
            for domain, domain_cfg in zone.get("domains", {}).items():
                if should_include_domain(domain_cfg, agent_tags):
                    tasks.extend(create_tasks_for_domain(domain, domain_cfg))
        
        return tasks
    
    return atomic_state_update(process_callback)

def should_include_domain(domain_cfg: dict, agent_tags: List[str]) -> bool:
    """Определяет должен ли домен быть включен в задачи"""
    monitor_tags = domain_cfg.get("monitor", {}).get("monitor_tag", "")
    if isinstance(monitor_tags, str):
        monitor_tags = monitor_tags.split()
    return bool(set(monitor_tags) & set(agent_tags))

def create_tasks_for_domain(domain: str, domain_cfg: dict) -> List[dict]:
    """Создает задачи мониторинга для домена"""
    tasks = []
    monitor_cfg = domain_cfg.get("monitor", {})
    
    for target in monitor_cfg.get("targets", []):
        if "ip" not in target or "port" not in target:
            continue
        
        tasks.append({
            "check_name": f"{domain}:{target['ip']}:{target['port']}",
            "domain": domain,
            "target_ip": target["ip"],
            "port": target["port"],
            "type": monitor_cfg.get("mode", "tcp"),
            "timeout_sec": domain_cfg.get("agent", {}).get("timeout_sec", 10),
            "interval_sec": domain_cfg.get("agent", {}).get("interval_sec", 30)
        })
    
    return tasks