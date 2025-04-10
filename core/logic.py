from core.state import state
from datetime import datetime, timezone
import logging
import random

log = logging.getLogger("CACHE")

def get_ip_for_domain(domain: str) -> list[str]:
    cached = state["resolved"].get(domain)
    ttl = get_ttl_for_domain(domain)
    now = datetime.now(timezone.utc)

    if cached:
        age = (now - cached["timestamp"]).total_seconds()
        if age <= ttl:
            logging.debug(f"[CACHE HIT] Domain: {domain}, IPs: {cached['ips']}")
            return cached["ips"]

    ip_list = get_alive_ips(domain)

    state["resolved"][domain] = {
        "ips": ip_list,
        "timestamp": now
    }

    logging.debug(f"[CACHE SET] Domain: {domain}, IPs: {ip_list}")
    return ip_list

def get_domain_config(domain: str) -> dict:
    for zone in state["config"].get("zones", []):
        domains = zone.get("domains", {})
        if domain in domains:
            return domains[domain]
    return {}

def get_alive_ips(domain: str) -> list[str]:
    checks = state["checks"].get(domain, {})
    if not checks:
        logging.warning(f"No checks recorded for domain: {domain}")
        return get_fallback_list(domain)

    domain_cfg = get_domain_config(domain)
    timeout_sec = domain_cfg.get("server", {}).get("timeout_sec", 60)

    now = datetime.now(timezone.utc)
    valid_hosts = []

    for ip, agents in checks.items():
        for agent_id, data in agents.items():
            ts = data["timestamp"]
            if (now - ts).total_seconds() <= timeout_sec and data["status"] == "ok":
                valid_hosts.append(ip)
                break

    if valid_hosts:
        random.shuffle(valid_hosts)  # Рандомизируем порядок IP
        return valid_hosts

    logging.warning(f"All checks for {domain} are expired or failed")
    return get_fallback_list(domain)

def get_fallback_list(domain: str) -> list[str]:
    cfg = get_domain_config(domain)
    fallback_list = cfg.get("fallback", [])
    if isinstance(fallback_list, list) and fallback_list:
        return fallback_list
    return ["127.0.0.1"]

def calculate_best_ip(domain: str) -> str:
    checks = state["checks"].get(domain, {})
    if not checks:
        logging.warning(f"No checks recorded for domain: {domain}")
        return get_fallback(domain)

    domain_cfg = get_domain_config(domain)
    timeout_sec = domain_cfg.get("server", {}).get("timeout_sec", 60)

    now = datetime.now(timezone.utc)
    valid_hosts = []

    for ip, agents in checks.items():
        for agent_id, data in agents.items():
            ts = data["timestamp"]
            if (now - ts).total_seconds() <= timeout_sec and data["status"] == "ok":
                valid_hosts.append(ip)
                break

    if valid_hosts:
        return valid_hosts[0]

    logging.warning(f"All checks for {domain} are expired or failed")
    return get_fallback(domain)


def get_fallback(domain: str) -> str:
    cfg = get_domain_config(domain)
    fallback_list = cfg.get("fallback", [])
    if isinstance(fallback_list, list) and fallback_list:
        return fallback_list[0]
    return "127.0.0.1"

def get_ttl_for_domain(domain: str) -> int:
    return state["config"].get("dns", {}).get("resolve_cache_ttl", 5)

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

    log.info(f"Received status from {agent} for {domain} → {host}: {report.status}")

    # Опционально: сброс кэша, если хочешь, чтобы новые данные сразу применялись
    if domain in state.get("resolved", {}):
        del state["resolved"][domain]

def get_domain_status() -> list[dict]:
    from datetime import timezone

    now = datetime.now(timezone.utc)
    result = []

    for zone in state["config"].get("zones", []):
        for domain, cfg in zone.get("domains", {}).items():
            fallback = cfg.get("fallback", [])
            timeout = cfg.get("server", {}).get("timeout_sec", 60)

            checks = state.get("checks", {}).get(domain, {})
            live_ips = []
            agent_map = {}

            latest_ts = None

            for ip, agents in checks.items():
                for agent_id, data in agents.items():
                    ts = data["timestamp"]
                    if agent_id not in agent_map:
                        agent_map[agent_id] = {
                            "agent_id": agent_id,
                            "last_seen": ts,
                            "checked_ips": set([ip])
                        }
                    else:
                        agent_map[agent_id]["checked_ips"].add(ip)
                        if ts > agent_map[agent_id]["last_seen"]:
                            agent_map[agent_id]["last_seen"] = ts

                    if (now - ts).total_seconds() <= timeout and data["status"] == "ok":
                        live_ips.append(ip)

                    if latest_ts is None or ts > latest_ts:
                        latest_ts = ts

            agent_list = []
            for info in agent_map.values():
                agent_list.append({
                    "agent_id": info["agent_id"],
                    "last_seen": info["last_seen"].isoformat(),
                    "checked_ips": sorted(info["checked_ips"])
                })

            result.append({
                "domain": domain,
                "live_ips": sorted(set(live_ips)),
                "using_fallback": len(live_ips) == 0,
                "fallback_ips": fallback,
                "agents": agent_list,
                "last_updated": latest_ts.isoformat() if latest_ts else None
            })

    return result

def get_domain_details(domain: str) -> dict:
    cfg = get_domain_config(domain)
    targets = cfg.get("monitor", {}).get("targets", [])
    ip_to_port = {target["ip"]: target["port"] for target in targets if "ip" in target and "port" in target}
    fallback = cfg.get("fallback", [])
    timeout = cfg.get("server", {}).get("timeout_sec", 60)
    monitor_mode = cfg.get("monitor", {}).get("mode", "tcp")

    now = datetime.now(timezone.utc)
    checks = state.get("checks", {}).get(domain, {})

    ip_status = {}

    for ip, agents in checks.items():
        agent_reports = []

        ip_ok = False
        for agent_id, data in agents.items():
            ts = data["timestamp"]
            age = (now - ts).total_seconds()
            alive = age <= timeout

            agent_reports.append({
                "agent_id": agent_id,
                "status": data["status"],
                "timestamp": ts.isoformat(),
                "latency_ms": data.get("latency_ms"),
                "expired": not alive
            })

            if alive and data["status"] == "ok":
                ip_ok = True

        ip_status[ip] = {
            "status": "ok" if ip_ok else "fail",
            "port": ip_to_port.get(ip),
            "agents": agent_reports
        }

    # Проверим, есть ли хоть один ok
    has_live_ip = any(ipinfo["status"] == "ok" for ipinfo in ip_status.values())

    return {
    "domain": domain,
    "check_type": monitor_mode,   # ← Вот оно
    "live": has_live_ip,
    "fallback_ips": fallback,
    "ip_checks": ip_status
}

def extract_monitor_tasks(agent_tags: list[str]) -> list[dict]:
    tasks = []
    config = state.get("config", {})
    zones = config.get("zones", [])

    for zone in zones:
        domains = zone.get("domains", {})
        for domain, domain_cfg in domains.items():
            monitor_cfg = domain_cfg.get("monitor", {})
            agent_cfg = domain_cfg.get("agent", {})

            monitor_tags = monitor_cfg.get("monitor_tag", "")
            if isinstance(monitor_tags, str):
                monitor_tags = monitor_tags.split()
            elif not isinstance(monitor_tags, list):
                continue

            if not set(monitor_tags) & set(agent_tags):
                continue

            mode = monitor_cfg.get("mode", "tcp")
            timeout = agent_cfg.get("timeout_sec", 10)
            interval = agent_cfg.get("interval_sec", 30)
            targets = monitor_cfg.get("targets", [])

            log.warning(f"[DEBUG] Domain: {domain}")
            log.warning(f"[DEBUG] Type of targets: {type(targets)}")
            log.warning(f"[DEBUG] Targets raw content: {targets}")
            log.warning(f"[DEBUG] Number of targets: {len(targets)}")

            for target in targets:
                ip = target.get("ip")
                port = target.get("port")
                if not ip or not port:
                    log.warning(f"[DEBUG] Skipping invalid target: {target}")
                    continue

                check_name = f"{domain}:{ip}:{port}"
                log.debug(f"[MONITOR TASK] {check_name} ({ip}:{port}) for tags={agent_tags}")

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