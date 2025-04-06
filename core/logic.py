from core.state import state
from datetime import datetime, timezone
import logging

log = logging.getLogger("CACHE")

def get_ip_for_domain(domain: str) -> str:
    # Проверка кэша
    cached = state["resolved"].get(domain)
    ttl = state["config"].get("logic", {}).get("resolve_cache_ttl", 5)
    now = datetime.now(timezone.utc)

    if cached:
        age = (now - cached["timestamp"]).total_seconds()
        if age <= ttl:
            logging.debug(f"[CACHE HIT] Domain: {domain}, IP: {cached['ip']}")
            return cached["ip"]

    # Пересчёт, если кэш отсутствует или устарел
    ip = calculate_best_ip(domain)

    # Сохраняем в кэш
    state["resolved"][domain] = {
        "ip": ip,
        "timestamp": now
    }

    logging.debug(f"[CACHE SET] Domain: {domain}, IP: {ip}")
    return ip


def calculate_best_ip(domain: str) -> str:
    checks = state["checks"].get(domain, {})
    if not checks:
        logging.warning(f"No checks recorded for domain: {domain}")
        return get_fallback(domain)

    config = state["config"]
    logic_cfg = config.get("logic", {})
    timeout_sec = logic_cfg.get("timeout_sec", 60)

    now = datetime.now(timezone.utc)
    valid_hosts = []

    for ip, agents in checks.items():
        for agent_id, data in agents.items():
            ts = parse_timestamp(data["timestamp"])
            if (now - ts).total_seconds() <= timeout_sec and data["status"] == "ok":
                valid_hosts.append(ip)
                break

    if valid_hosts:
        return valid_hosts[0]

    logging.warning(f"All checks for {domain} are expired or failed")
    return get_fallback(domain)


def get_fallback(domain: str) -> str:
    fallback_ip = (
        state["config"]
        .get("zones", [])[0]
        .get("domains", {})
        .get(domain, {})
        .get("fallback_ip")
    )
    return fallback_ip or "127.0.0.1"


def parse_timestamp(ts: str) -> datetime:
    try:
        if ts.endswith("Z"):
            ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.now(timezone.utc)
    
def update_status(report):
    domain = report.domain
    host = report.target_ip
    agent = report.agent_id

    checks = state.setdefault("checks", {}).setdefault(domain, {}).setdefault(host, {})
    checks[agent] = {
        "status": report.status,
        "timestamp": report.timestamp,
        "latency_ms": report.latency_ms
    }

    # Опционально: сброс кэша, если хочешь, чтобы новые данные сразу применялись
    if domain in state.get("resolved", {}):
        del state["resolved"][domain]