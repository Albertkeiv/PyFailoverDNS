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

def get_domain_config(domain: str) -> dict:
    for zone in state["config"].get("zones", []):
        domains = zone.get("domains", {})
        if domain in domains:
            return domains[domain]
    return {}

def calculate_best_ip(domain: str) -> str:
    checks = state["checks"].get(domain, {})
    if not checks:
        logging.warning(f"No checks recorded for domain: {domain}")
        return get_fallback(domain)

    domain_cfg = get_domain_config(domain)
    timeout_sec = domain_cfg.get("timeout_sec", 60)
    ttl = domain_cfg.get("resolve_cache_ttl", 5)

    now = datetime.now(timezone.utc)
    valid_hosts = []

    for ip, agents in checks.items():
        for agent_id, data in agents.items():
            ts = data["timestamp"]  # Уже datetime, ничего парсить не нужно
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

def get_ttl_for_domain(domain: str) -> int:
    domain_cfg = get_domain_config(domain)
    return domain_cfg.get("resolve_cache_ttl", 5)

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

def extract_monitor_tasks(agent_tags: list[str]) -> list[dict]:
    """
    Возвращает список заданий на мониторинг, подходящих агенту по его тегам.
    """
    tasks = []
    config = state.get("config", {})
    zones = config.get("zones", [])

    for zone in zones:
        domains = zone.get("domains", {})
        for domain, domain_cfg in domains.items():
            monitor_tags = domain_cfg.get("monitor_tag", "")
            if isinstance(monitor_tags, str):
                monitor_tags = monitor_tags.split()
            elif not isinstance(monitor_tags, list):
                continue  # некорректный формат

            # если хотя бы один тег совпадает
            if not set(monitor_tags) & set(agent_tags):
                continue

            mode = domain_cfg.get("mode", "tcp")
            timeout = domain_cfg.get("timeout_sec", 10)
            interval = domain_cfg.get("interval_sec", 30)
            targets = domain_cfg.get("targets", [])

            for target in targets:
                ip = target.get("ip")
                port = target.get("port")
                if not ip or not port:
                    continue

                check_name = f"{domain}:{ip}:{port}"

                tasks.append({
                    "check_name": check_name,
                    "domain": domain,
                    "target_ip": ip,
                    "port": port,
                    "type": mode,
                    "timeout_sec": timeout,
                    "interval_sec": interval
                })

    return tasks