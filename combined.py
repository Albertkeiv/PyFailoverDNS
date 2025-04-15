"""
Combined PyFailoverDNS File
Объединённый файл для проекта PyFailoverDNS, содержащий код из:
    - main.py
    - server.py
    - resolver.py
    - config_loader.py
    - logic.py
    - state.py
    - routes.py
    - models.py
Файл разделён на логические секции для сохранения структуры и зависимостей.
"""

import os
import sys
import argparse
import asyncio
import uvicorn
import socket
import threading
import time
import logging
from contextlib import closing
from datetime import datetime, timezone, timedelta
import yaml
import ipaddress
import random
import heapq
from typing import List, Tuple, Dict, Optional

# Настройка базового логгирования
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s'
)
log = logging.getLogger("MAIN")

###############################################################################
# 1. State (из state.py)
###############################################################################
log_state = logging.getLogger("STATE")

# Рекурсивный lock для атомарного доступа к состоянию
state_lock = threading.RLock()

# Глобальное состояние приложения
state = {
    "config": None,
    "agents": {},
    "checks": {},
    "resolved": {}
}

def init_state(config):
    with state_lock:
        state["config"] = config

def atomic_state_update(callback):
    with state_lock:
        return callback(state)

###############################################################################
# 2. Config Loader (из config_loader.py)
###############################################################################
log_config = logging.getLogger("CONFIG")

class ConfigValidationError(ValueError):
    pass

def load_config(path: str) -> dict:
    """
    Загружает и валидирует конфигурационный файл YAML.
    Возвращает нормализованный конфиг в виде словаря.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, 'r') as f:
        try:
            config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigValidationError(f"Invalid YAML syntax: {e}")

    # Нормализация структуры
    config.setdefault('dns', {})
    config.setdefault('api', {})
    config.setdefault('zones', [])

    # Валидация базовой структуры
    required_fields = [
        ('dns', 'listen_ip'),
        ('dns', 'listen_port'),
        ('api', 'listen_ip'),
        ('api', 'listen_port'),
    ]

    for section, key in required_fields:
        if not config.get(section, {}).get(key):
            raise ConfigValidationError(f"Missing required config value: {section}.{key}")

    # Валидация сетевых параметров
    try:
        ipaddress.ip_address(config['dns']['listen_ip'])
        ipaddress.ip_address(config['api']['listen_ip'])
    except ValueError as e:
        raise ConfigValidationError(f"Invalid IP address: {e}")

    if not (1 <= config['dns']['listen_port'] <= 65535):
        raise ConfigValidationError("Invalid DNS port number")
    if not (1 <= config['api']['listen_port'] <= 65535):
        raise ConfigValidationError("Invalid API port number")

    # Валидация зон и доменов
    if not isinstance(config['zones'], list):
        raise ConfigValidationError("Zones must be a list")

    seen_domains = set()
    for zone in config['zones']:
        if not isinstance(zone, dict):
            raise ConfigValidationError("Zone must be a dictionary")
        domains = zone.get('domains', {})
        if not isinstance(domains, dict):
            raise ConfigValidationError("Domains must be a dictionary")
        for domain, domain_cfg in domains.items():
            if domain in seen_domains:
                raise ConfigValidationError(f"Duplicate domain: {domain}")
            seen_domains.add(domain)
            validate_domain_config(domain, domain_cfg)

    # Установка значений по умолчанию
    config['dns'].setdefault('resolve_cache_ttl', 5)
    config['api'].setdefault('enabled', True)

    log_config.info(f"Loaded valid config from {path}")
    return config

def validate_domain_config(domain: str, domain_cfg: dict):
    """Валидация конфигурации отдельного домена"""
    required_sections = ['server', 'monitor', 'fallback']
    for section in required_sections:
        if section not in domain_cfg:
            raise ConfigValidationError(f"Domain {domain} missing required section: {section}")

    # Валидация серверных настроек
    server_cfg = domain_cfg['server']
    valid_policies = ['any', 'priority', 'quorum', 'all']
    if server_cfg.get('policy', 'any') not in valid_policies:
        log_config.warning(f"Policy {server_cfg['policy']} for domain {domain} is not fully supported yet.")
        if server_cfg.get('policy', 'any') not in ['any', 'priority']:
            raise ConfigValidationError(
                f"Invalid or unsupported server policy for {domain}: {server_cfg['policy']}. Supported: any, priority"
            )

    # Валидация мониторинга
    monitor_cfg = domain_cfg['monitor']
    valid_modes = ['tcp', 'http', 'icmp']
    if monitor_cfg.get('mode', 'tcp') not in valid_modes:
        log_config.warning(f"Monitor mode {monitor_cfg['mode']} for domain {domain} might not be supported by agents yet.")
    targets = monitor_cfg.get('targets', [])
    if not isinstance(targets, list) or len(targets) == 0:
        raise ConfigValidationError(f"Domain {domain} must have at least one monitoring target")
    for target in targets:
        if 'ip' not in target:
            raise ConfigValidationError(f"Invalid target configuration in {domain} (missing ip): {target}")
        if monitor_cfg.get('mode', 'tcp') != 'icmp' and 'port' not in target:
            raise ConfigValidationError(f"Invalid target configuration in {domain} (missing port for non-ICMP check): {target}")
        try:
            ipaddress.ip_address(target['ip'])
        except ValueError:
            raise ConfigValidationError(f"Invalid target IP in {domain}: {target['ip']}")

    # Валидация fallback IP
    fallback = domain_cfg['fallback']
    if not isinstance(fallback, list):
        raise ConfigValidationError(f"Fallback for domain {domain} must be a list")
    for ip in fallback:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ConfigValidationError(f"Invalid fallback IP in {domain}: {ip}")

    # Валидация агента (если указан)
    agent_cfg = domain_cfg.get('agent', {})
    if agent_cfg.get('token') and len(agent_cfg['token']) < 8:
        raise ConfigValidationError(f"Agent token for {domain} must be at least 8 characters")

###############################################################################
# 3. Models (из models.py)
###############################################################################
from pydantic import BaseModel, Field
from typing import Literal

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

###############################################################################
# 4. Logic (из logic.py)
###############################################################################
log_logic = logging.getLogger("LOGIC")

def get_domain_config(domain: str) -> dict:
    """Возвращает конфигурацию домена с атомарным доступом к state"""
    def process_callback(s):
        config = s.get("config", {})
        for zone in config.get("zones", []):
            if domain in zone.get("domains", {}):
                return zone["domains"][domain].copy()
        return {}
    return atomic_state_update(process_callback)

def get_ttl_for_domain(domain: str) -> int:
    """Возвращает TTL для домена из конфигурации или state"""
    def process_callback(s):
        domain_cfg = get_domain_config(domain)
        ttl = domain_cfg.get("server", {}).get("resolve_cache_ttl") or s.get("config", {}).get("dns", {}).get("resolve_cache_ttl", 5)
        return ttl
    return atomic_state_update(process_callback)

def sort_ips_by_policy(ips: List[str], domain_cfg: dict, policy: str) -> List[str]:
    """Сортирует IP согласно заданной политике"""
    if not ips:
        return []
    if policy == "priority":
        targets = domain_cfg.get("monitor", {}).get("targets", [])
        priorities = {t["ip"]: t.get("priority", 1000) for t in targets if "ip" in t}
        return sorted(ips, key=lambda ip: priorities.get(ip, 1000))
    elif policy == "any":
        shuffled_ips = list(ips)
        random.shuffle(shuffled_ips)
        return shuffled_ips
    else:
        log_logic.warning(f"Unsupported policy '{policy}' requested, returning shuffled list.")
        shuffled_ips = list(ips)
        random.shuffle(shuffled_ips)
        return shuffled_ips

def get_fallback_list(domain: str, domain_cfg: Optional[dict] = None) -> List[str]:
    """Возвращает fallback IP список с валидацией"""
    def process_callback(s):
        effective_domain_cfg = domain_cfg
        if not effective_domain_cfg:
            _cfg = get_domain_config(domain)
            if not _cfg:
                log_logic.error(f"Cannot get domain config for {domain} to determine fallback IPs.")
                return ["127.0.0.1"]
            effective_domain_cfg = _cfg
        fallback = effective_domain_cfg.get("fallback", [])
        if not isinstance(fallback, list):
            log_logic.error(f"Invalid fallback configuration for {domain} (not a list), using default.")
            return ["127.0.0.1"]
        if not fallback:
            log_logic.warning(f"Fallback list is empty for domain {domain}. No fallback IPs available.")
            return []
        valid_ips = []
        for ip in fallback:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                log_logic.warning(f"Invalid fallback IP format '{ip}' for domain {domain}")
        if not valid_ips and fallback:
            log_logic.error(f"All configured fallback IPs for {domain} are invalid. Returning default.")
            return ["127.0.0.1"]
        elif not valid_ips and not fallback:
            return []
        return valid_ips
    return atomic_state_update(process_callback)

def apply_rr_policy(ip_list: List[str], domain: str, current_state: dict) -> List[str]:
    """Применяет round-robin балансировку к списку IP"""
    if len(ip_list) <= 1:
        return ip_list
    rr_counters = current_state.setdefault("rr_counters", {})
    rr_idx = rr_counters.get(domain, 0)
    rr_counters[domain] = (rr_idx + 1) % len(ip_list)
    return ip_list[rr_idx:] + ip_list[:rr_idx]

def get_alive_ips(domain: str) -> List[str]:
    """Возвращает список живых IP с учетом политик и fallback"""
    def process_callback(s):
        domain_cfg = get_domain_config(domain)
        if not domain_cfg:
            log_logic.warning(f"get_alive_ips called for non-configured domain: {domain}")
            return []
        checks = s.get("checks", {}).get(domain, {})
        timeout_sec = domain_cfg.get("server", {}).get("timeout_sec", 60)
        policy = domain_cfg.get("server", {}).get("policy", "any")
        now = datetime.now(timezone.utc)
        valid_hosts = []
        configured_targets = {t['ip'] for t in domain_cfg.get("monitor", {}).get("targets", []) if 'ip' in t}
        for ip, agents in checks.items():
            if ip not in configured_targets:
                continue
            for agent_id, agent_data in agents.items():
                ts = agent_data.get("timestamp")
                status = agent_data.get("status")
                if not isinstance(ts, datetime):
                    log_logic.warning(f"Invalid timestamp type for agent {agent_id} check on {ip}: {type(ts)}")
                    continue
                time_diff = now - ts
                if time_diff.total_seconds() >= 0 and time_diff.total_seconds() <= timeout_sec and status == "ok":
                    valid_hosts.append(ip)
                    break
        unique_valid_hosts = sorted(list(set(valid_hosts)))
        if not unique_valid_hosts:
            log_logic.warning(f"No live IPs found for {domain} within timeout {timeout_sec}s. Using fallback.")
            return get_fallback_list(domain, domain_cfg)
        else:
            log_logic.info(f"Live IPs found for {domain}: {unique_valid_hosts}. Applying policy '{policy}'.")
            return sort_ips_by_policy(unique_valid_hosts, domain_cfg, policy)
    return atomic_state_update(process_callback)

def get_dns_response(domain: str) -> Tuple[List[str], int]:
    """Генерирует DNS ответ (список IP и TTL) с учетом кеша и политик"""
    def process_callback(s):
        domain_cfg = get_domain_config(domain)
        if not domain_cfg:
            log_logic.debug(f"DNS query for non-configured domain: {domain}")
            default_ttl = s.get("config", {}).get("dns", {}).get("resolve_cache_ttl", 5)
            return [], default_ttl
        cache_key = domain
        resolved_cache = s.setdefault("resolved", {})
        now = datetime.now(timezone.utc)
        base_ttl = get_ttl_for_domain(domain)
        if cache_key in resolved_cache:
            cached_entry = resolved_cache[cache_key]
            cache_timestamp = cached_entry.get("timestamp")
            cached_ttl = cached_entry.get("ttl", base_ttl)
            if isinstance(cache_timestamp, datetime):
                cache_age = (now - cache_timestamp).total_seconds()
                if cache_age >= 0 and cache_age <= cached_ttl:
                    remaining_ttl = max(0, int(cached_ttl - cache_age))
                    log_logic.debug(f"[CACHE HIT] {domain} -> {cached_entry['ips']} (TTL remaining: {remaining_ttl}s)")
                    return apply_rr_policy(cached_entry['ips'], domain, s), remaining_ttl
                else:
                    log_logic.debug(f"[CACHE EXPIRED] {domain} (Age: {cache_age:.1f}s > TTL: {cached_ttl}s)")
            else:
                log_logic.warning(f"Invalid timestamp in cache for {domain}. Ignoring cache entry.")
                del s["resolved"][cache_key]
        log_logic.debug(f"[CACHE MISS] Resolving {domain}")
        ip_list = get_alive_ips(domain)
        live_ips_exist = False
        checks = s.get("checks", {}).get(domain, {})
        timeout_sec = domain_cfg.get("server", {}).get("timeout_sec", 60)
        for ip, agents in checks.items():
            for agent_data in agents.values():
                ts = agent_data.get("timestamp")
                if isinstance(ts, datetime):
                    time_diff = now - ts
                    if time_diff.total_seconds() >= 0 and time_diff.total_seconds() <= timeout_sec and agent_data.get("status") == "ok":
                        live_ips_exist = True
                        break
            if live_ips_exist:
                break
        is_fallback = not live_ips_exist and bool(ip_list)
        final_ttl = domain_cfg.get("fallback_ttl", base_ttl) if is_fallback else base_ttl
        resolved_cache[cache_key] = {
            "ips": ip_list,
            "timestamp": now,
            "ttl": final_ttl,
            "is_fallback": is_fallback
        }
        log_logic.info(f"[RESOLVE] {domain} -> {ip_list} (TTL: {final_ttl}, Fallback: {is_fallback})")
        return apply_rr_policy(ip_list, domain, s), final_ttl
    return atomic_state_update(process_callback)

def update_status(report) -> None:
    """Обновляет статус проверок на основе отчета от агента"""
    def update_callback(s):
        domain = report.domain
        host = report.target_ip
        agent = report.agent_id
        domain_cfg = get_domain_config(domain)
        if not domain_cfg:
            log_logic.warning(f"Received status report from agent {agent} for non-configured domain {domain}. Ignoring.")
            return
        configured_targets = {t['ip'] for t in domain_cfg.get("monitor", {}).get("targets", []) if 'ip' in t}
        if host not in configured_targets:
            log_logic.warning(f"Received status report from agent {agent} for domain {domain} target IP {host} which is not configured in targets. Ignoring.")
            return
        domain_checks = s.setdefault("checks", {}).setdefault(domain, {})
        host_checks = domain_checks.setdefault(host, {})
        host_checks[agent] = {
            "status": report.status,
            "timestamp": report.timestamp,
            "latency_ms": report.latency_ms,
            "port": report.port,
            "reason": report.reason
        }
        if domain in s.get("resolved", {}):
            log_logic.debug(f"Clearing DNS cache for {domain} due to new report from {agent}")
            del s["resolved"][domain]
        log_logic.info(f"Status updated by {agent} for {domain} -> {host}:{report.port} = {report.status}")
    atomic_state_update(update_callback)

def _update_agent_status_summary(agents_summary: dict, agent_id: str, ip: str, ts: datetime) -> None:
    if agent_id not in agents_summary:
        agents_summary[agent_id] = {
            "agent_id": agent_id,
            "last_seen": ts,
            "checked_ips": set([ip])
        }
    else:
        agents_summary[agent_id]["checked_ips"].add(ip)
        if ts > agents_summary[agent_id]["last_seen"]:
            agents_summary[agent_id]["last_seen"] = ts

def _build_domain_status(domain: str, cfg: dict, checks: dict, now: datetime) -> dict:
    timeout = cfg.get("server", {}).get("timeout_sec", 60)
    live_ips = set()
    agents_summary = {}
    latest_ts = None
    domain_checks = checks.get(domain, {})
    configured_targets = {t['ip'] for t in cfg.get("monitor", {}).get("targets", []) if 'ip' in t}
    for ip, agents_reports in domain_checks.items():
        if ip not in configured_targets:
            continue
        ip_is_live = False
        for agent_id, data in agents_reports.items():
            ts = data.get("timestamp")
            if isinstance(ts, datetime):
                _update_agent_status_summary(agents_summary, agent_id, ip, ts)
                latest_ts = max(latest_ts, ts) if latest_ts else ts
                time_diff = now - ts
                if not ip_is_live and time_diff.total_seconds() >= 0 and time_diff.total_seconds() <= timeout and data.get("status") == "ok":
                    live_ips.add(ip)
                    ip_is_live = True
    status = {
        "domain": domain,
        "live_ips": sorted(list(live_ips)),
        "using_fallback": not bool(live_ips),
        "fallback_ips": cfg.get("fallback", []),
        "agents": [],
        "last_updated": latest_ts.isoformat() if latest_ts else None
    }
    agent_list = []
    for agent_id, summary in agents_summary.items():
        agent_list.append({
            "agent_id": agent_id,
            "last_seen": summary["last_seen"],
            "checked_ips": sorted(list(summary["checked_ips"]))
        })
    status["agents"] = sorted(agent_list, key=lambda a: a["agent_id"])
    return status

def get_domain_status() -> List[dict]:
    """Генерирует статус всех доменов для API"""
    def process_callback(s):
        result = []
        now = datetime.now(timezone.utc)
        config = s.get("config", {})
        checks = s.get("checks", {})
        for zone in config.get("zones", []):
            for domain, cfg in zone.get("domains", {}).items():
                result.append(_build_domain_status(domain, cfg, checks, now))
        return sorted(result, key=lambda d: d["domain"])
    return atomic_state_update(process_callback)

def _ip_has_live_checks(ip: str, ip_agents_reports: dict, timeout: int, now: datetime) -> bool:
    for agent_data in ip_agents_reports.values():
        ts = agent_data.get("timestamp")
        if isinstance(ts, datetime):
            time_diff = now - ts
            if time_diff.total_seconds() >= 0 and time_diff.total_seconds() <= timeout and agent_data.get("status") == "ok":
                return True
    return False

def _build_ip_checks_details(checks: dict, cfg: dict, now: datetime) -> dict:
    timeout = cfg.get("server", {}).get("timeout_sec", 60)
    ip_checks_details = {}
    domain_checks = checks.get(cfg["_domain_name_for_context_"], {})
    targets_map = {t['ip']: t for t in cfg.get("monitor", {}).get("targets", []) if 'ip' in t}
    for ip, agents_reports in domain_checks.items():
        if ip not in targets_map:
            continue
        reports_list = []
        ip_is_live = False
        for agent_id, data in agents_reports.items():
            ts = data.get("timestamp")
            is_expired = True
            if isinstance(ts, datetime):
                time_diff = now - ts
                is_expired = not (time_diff.total_seconds() >= 0 and time_diff.total_seconds() <= timeout)
                if not is_expired and data.get("status") == "ok":
                    ip_is_live = True
            reports_list.append({
                "agent_id": agent_id,
                "status": data.get("status", "unknown"),
                "timestamp": ts.isoformat() if isinstance(ts, datetime) else None,
                "latency_ms": data.get("latency_ms"),
                "expired": is_expired
            })
        ip_checks_details[ip] = {
            "status": "ok" if ip_is_live else "fail",
            "port": targets_map[ip].get("port"),
            "agents": sorted(reports_list, key=lambda r: r["agent_id"])
        }
    for target_ip, target_cfg in targets_map.items():
        if target_ip not in ip_checks_details:
            ip_checks_details[target_ip] = {
                "status": "unknown",
                "port": target_cfg.get("port"),
                "agents": []
            }
    return ip_checks_details

def get_domain_details(domain: str) -> dict:
    """Возвращает детальную информацию о домене для API"""
    def process_callback(s):
        cfg = get_domain_config(domain)
        if not cfg:
            raise KeyError(f"Domain '{domain}' not found in configuration")
        checks = s.get("checks", {})
        now = datetime.now(timezone.utc)
        timeout = cfg.get("server", {}).get("timeout_sec", 60)
        domain_is_live = False
        domain_checks = checks.get(domain, {})
        for ip, agents_reports in domain_checks.items():
            if _ip_has_live_checks(ip, agents_reports, timeout, now):
                domain_is_live = True
                break
        cfg["_domain_name_for_context_"] = domain
        ip_checks_data = _build_ip_checks_details(checks, cfg, now)
        return {
            "domain": domain,
            "check_type": cfg.get("monitor", {}).get("mode", "tcp"),
            "live": domain_is_live,
            "fallback_ips": cfg.get("fallback", []),
            "ip_checks": ip_checks_data
        }
    return atomic_state_update(process_callback)

def _should_include_domain_for_task(domain_cfg: dict, agent_tags: List[str]) -> bool:
    monitor_cfg = domain_cfg.get("monitor", {})
    required_tag = monitor_cfg.get("monitor_tag")
    if not required_tag:
        return False
    required_tags_list = []
    if isinstance(required_tag, str):
        required_tags_list = [tag.strip() for tag in required_tag.replace(",", " ").split() if tag.strip()]
    elif isinstance(required_tag, list):
        required_tags_list = [str(tag).strip() for tag in required_tag if str(tag).strip()]
    if not required_tags_list:
        return False
    return bool(set(required_tags_list) & set(agent_tags))

def _create_tasks_for_domain(domain: str, domain_cfg: dict) -> List[dict]:
    tasks = []
    monitor_cfg = domain_cfg.get("monitor", {})
    agent_cfg = domain_cfg.get("agent", {})
    check_mode = monitor_cfg.get("mode", "tcp")
    for target in monitor_cfg.get("targets", []):
        target_ip = target.get("ip")
        target_port = target.get("port") if check_mode != 'icmp' else None
        if not target_ip:
            log_logic.warning(f"Skipping task creation for domain {domain} due to missing target IP in {target}")
            continue
        tasks.append({
            "check_name": f"{domain}:{target_ip}:{target_port or 'icmp'}",
            "domain": domain,
            "target_ip": target_ip,
            "port": target_port,
            "type": check_mode,
            "timeout_sec": agent_cfg.get("timeout_sec", 5),
            "interval_sec": agent_cfg.get("interval_sec", 30)
        })
    return tasks

def extract_monitor_tasks(agent_tags: List[str], agent_api_key: Optional[str]) -> List[dict]:
    """Генерирует задачи мониторинга для доменов, на которые у агента есть права"""
    def process_callback(s):
        tasks = []
        config = s.get("config", {})
        if not agent_tags:
            log_logic.warning("Agent requested tasks with no tags.")
            return []
        for zone in config.get("zones", []):
            for domain, domain_cfg in zone.get("domains", {}).items():
                expected_token = domain_cfg.get("agent", {}).get("token")
                token_match = (not expected_token) or (agent_api_key == expected_token)
                if not token_match:
                    continue
                if _should_include_domain_for_task(domain_cfg, agent_tags):
                    tasks.extend(_create_tasks_for_domain(domain, domain_cfg))
        log_logic.info(f"Extracted {len(tasks)} tasks for agent tags: {agent_tags} (Key provided: {'yes' if agent_api_key else 'no'})")
        return sorted(tasks, key=lambda t: t["check_name"])
    return atomic_state_update(process_callback)

###############################################################################
# 5. Resolver (из resolver.py)
###############################################################################
from dnslib.server import BaseResolver, DNSServer
from dnslib import RR, A, QTYPE

log_dns = logging.getLogger("DNS")

class FailoverResolver(BaseResolver):
    def __init__(self, config: dict, state: dict, lock: threading.RLock):
        self.config = config
        self.state = state
        self.state_lock = lock
        self._validate_config()

    def _validate_config(self) -> None:
        if not self.config.get('dns'):
            raise ValueError("Missing DNS configuration section")
        if 'resolve_cache_ttl' not in self.config.get('dns', {}):
            self.config.setdefault('dns', {}).setdefault('resolve_cache_ttl', 5)
            log_dns.warning("resolve_cache_ttl not found in DNS config, using default 5s")

    def resolve(self, request, handler) -> RR:
        qname = str(request.q.qname).rstrip('.')
        qtype = QTYPE[request.q.qtype]
        reply = request.reply()
        try:
            domain_cfg = get_domain_config(qname)
            if not domain_cfg:
                log_dns.debug(f"Domain not configured or handled by this server: {qname}")
                return reply
            if qtype == "A":
                self._process_a_record(qname, reply, domain_cfg)
            else:
                log_dns.warning(f"Unsupported query type: {qtype} for domain {qname}")
        except Exception as e:
            log_dns.exception(f"Failed to process query for {qname}: {e}")
            return reply
        return reply

    def _process_a_record(self, qname: str, reply: RR, domain_cfg: dict) -> None:
        try:
            ip_list, ttl = get_dns_response(qname)
        except Exception as e:
            log_dns.exception(f"Error resolving domain {qname} via core logic: {e}")
            ip_list = []
            ttl = self.config.get('dns', {}).get('resolve_cache_ttl', 5)
        is_fallback = False
        if not ip_list:
            log_dns.warning(f"No IPs (live or fallback) available for domain {qname}")
            return
        valid_ips = self._validate_ips_format(ip_list, qname)
        if not valid_ips:
            log_dns.error(f"IP list for {qname} received from logic contains invalid formats: {ip_list}. Not returning records.")
            return
        effective_ttl = ttl
        for ip in valid_ips:
            reply.add_answer(
                RR(
                    qname,
                    QTYPE.A,
                    rdata=A(ip),
                    ttl=effective_ttl
                )
            )
        log_dns.info(f"Resolved {qname} -> {valid_ips} (TTL: {effective_ttl})")

    def _validate_ips_format(self, ips: List[str], domain: str) -> List[str]:
        valid_ips = []
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                log_dns.warning(f"Invalid IP format '{ip}' provided for domain {domain}")
        return valid_ips

###############################################################################
# 6. DNS Server (из server.py)
###############################################################################
class ThreadedDNSServer:
    def __init__(self, config: dict):
        self.config = config
        self.server = None
        self.thread = None
        self._stop_event = threading.Event()

    def start(self):
        try:
            resolver = FailoverResolver(
                config=self.config,
                state=state,
                lock=state_lock
            )
            dns_cfg = self.config['dns']
            listen_ip = dns_cfg['listen_ip']
            listen_port = dns_cfg['listen_port']
            log_dns.info(f"Attempting to create DNSServer on {listen_ip}:{listen_port}")
            self.server = DNSServer(
                resolver,
                port=listen_port,
                address=listen_ip,
            )
            log_dns.info("DNSServer object created successfully.")
        except Exception as e:
            log_dns.exception("Failed to initialize DNSServer components")
            self.server = None
            return
        if self.server:
            log_dns.debug("Starting DNS server thread...")
            self.thread = threading.Thread(target=self._run_server, name="DNSServerThread", daemon=False)
            self.thread.start()
            log_dns.info(f"DNS server thread '{self.thread.name}' started.")
        else:
            log_dns.error("DNS Server object was not created. Thread not started.")

    def _run_server(self):
        if not self.server:
            log_dns.error("DNS server instance is None, cannot run server thread.")
            return
        listen_ip = self.config['dns']['listen_ip']
        listen_port = self.config['dns']['listen_port']
        log_dns.info(f"DNS Server thread: Preparing to call server.start() on {listen_ip}:{listen_port}...")
        try:
            log_dns.debug("DNS Server thread: Calling server.start() now...")
            self.server.start()
            log_dns.warning("DNS Server thread: server.start() returned unexpectedly (should only happen after stop()).")
        except OSError as e:
            log_dns.exception(f"DNS Server thread: OSError during server.start() or listening on {listen_ip}:{listen_port}")
        except Exception as e:
            log_dns.exception("DNS Server thread: An unexpected error occurred during server execution")
        finally:
            log_dns.info("DNS Server thread: Reached finally block.")
            if self.server and self.server.is_running():
                log_dns.warning("DNS Server thread: Server was still running in finally block, stopping it now.")
                try:
                    self.server.stop()
                except Exception as stop_err:
                    log_dns.exception("DNS Server thread: Error while trying to stop server in finally block.")
            log_dns.info(f"DNS Server thread finished for {listen_ip}:{listen_port}.")

    def stop(self):
        listen_ip = self.config['dns']['listen_ip']
        listen_port = self.config['dns']['listen_port']
        log_dns.info(f"Stop requested for DNS server on {listen_ip}:{listen_port}")
        if self.server and self.server.is_running():
            log_dns.info("DNS server is running, attempting to stop...")
            try:
                self.server.stop()
                log_dns.info("DNSServer stop() method called.")
            except Exception as e:
                log_dns.exception("Exception occurred while calling server.stop()")
        elif self.server:
            log_dns.info("DNS server object exists but is not running.")
        else:
            log_dns.info("DNS server object does not exist.")
        if self.thread and self.thread.is_alive():
            log_dns.info(f"Waiting for DNS server thread '{self.thread.name}' to join...")
            self.thread.join(timeout=5.0)
            if self.thread.is_alive():
                log_dns.warning(f"DNS server thread '{self.thread.name}' did not stop after 5 seconds.")
            else:
                log_dns.info(f"DNS server thread '{self.thread.name}' joined successfully.")
        elif self.thread:
            log_dns.info(f"DNS server thread '{self.thread.name}' was already finished.")
        log_dns.info(f"DNS server stop sequence completed for {listen_ip}:{listen_port}.")

def start_dns_server(config: dict) -> ThreadedDNSServer:
    server = ThreadedDNSServer(config)
    server.start()
    return server

###############################################################################
# 7. API Routes (из routes.py)
###############################################################################
from fastapi import FastAPI, Request, Query, HTTPException, Header, status, Depends
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader

log_api = logging.getLogger("API")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

app = FastAPI(
    title="PyFailoverDNS API",
    description="API for managing DNS failover configuration and monitoring",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None
)

class HealthCheckResponseModel(BaseModel):
    status: str
    timestamp: datetime
    components: Dict[str, str]

class ErrorResponse(BaseModel):
    detail: str

def validate_api_key_for_domain(domain: str, api_key: Optional[str] = None):
    domain_cfg = get_domain_config(domain)
    if not domain_cfg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Domain '{domain}' not configured"
        )
    expected_token = domain_cfg.get("agent", {}).get("token")
    if expected_token and api_key != expected_token:
        log_api.warning(f"[AUTH FAIL] Invalid token provided for domain {domain}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key for the requested domain"
        )

@app.post("/api/v1/report",
          response_model=Dict[str, str],
          responses={
              403: {"model": ErrorResponse},
              404: {"model": ErrorResponse},
              500: {"model": ErrorResponse}
          })
async def receive_report(
    report: ReportModel,
    request: Request,
    x_api_key: Optional[str] = Depends(api_key_header)
):
    try:
        domain_cfg = get_domain_config(report.domain)
        if not domain_cfg:
            log_api.warning(f"Report received for non-configured domain: {report.domain}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Domain not configured"
            )
        validate_api_key_for_domain(report.domain, x_api_key)
        def update_callback(s):
            if report.status not in ["ok", "fail"]:
                log_api.warning(f"Invalid status '{report.status}' in report from {report.agent_id}")
                return {"status": "error", "message": "Invalid status value"}
            update_status(report)
            log_api.debug(f"Report from {report.agent_id} for {report.domain} -> {report.target_ip} processed.")
            return {"status": "ok"}
        result = atomic_state_update(update_callback)
        if result.get("status") == "error":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.get("message", "Invalid report data")
            )
        return result
    except HTTPException as he:
        raise he
    except Exception as e:
        log_api.exception(f"Report processing failed unexpectedly for domain {report.domain} from agent {report.agent_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during report processing"
        )

@app.get("/api/v1/tasks",
         response_model=Dict[str, List[MonitorTask]],
         responses={
             403: {"model": ErrorResponse},
             500: {"model": ErrorResponse}
         })
async def get_tasks(
    request: Request,
    tags: str = Query(..., description="Comma-separated list of agent tags (e.g., 'test,dc1')"),
    x_api_key: Optional[str] = Depends(api_key_header)
):
    if not x_api_key:
        log_api.warning("Agent requested tasks without providing an API key.")
    try:
        tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
        if not tag_list:
            log_api.warning("Agent requested tasks with empty or invalid tags.")
            return {"tasks": []}
        tasks = extract_monitor_tasks(tag_list, x_api_key)
        log_api.info(f"Returning {len(tasks)} tasks for agent with tags: {tag_list} (key provided: {'yes' if x_api_key else 'no'})")
        validated_tasks = [MonitorTask(**task) for task in tasks]
        return {"tasks": validated_tasks}
    except Exception as e:
        log_api.exception(f"Task retrieval failed unexpectedly for tags: {tags}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during task retrieval"
        )

@app.get("/api/v1/status",
         response_model=Dict[str, List[DomainStatus]],
         responses={500: {"model": ErrorResponse}})
async def status_summary():
    try:
        status_data = get_domain_status()
        validated_status = [DomainStatus(**item) for item in status_data]
        return {"status": validated_status}
    except Exception as e:
        log_api.exception("Status summary retrieval failed unexpectedly")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error retrieving status summary"
        )

@app.get("/api/v1/status/{domain}",
         response_model=DomainDetails,
         responses={
             404: {"model": ErrorResponse},
             500: {"model": ErrorResponse}
         })
async def status_domain(domain: str):
    try:
        domain_cfg = get_domain_config(domain)
        if not domain_cfg:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Domain not configured or not found"
            )
        details_data = get_domain_details(domain)
        validated_details = DomainDetails(**details_data)
        return validated_details
    except HTTPException as he:
        raise he
    except Exception as e:
        log_api.exception(f"Domain status retrieval failed unexpectedly for: {domain}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error retrieving domain status"
        )

@app.get("/health",
         response_model=HealthCheckResponseModel,
         tags=["monitoring"],
         include_in_schema=False)
async def health_check():
    components = {
        "api": "ok",
    }
    overall_status = "ok"
    with state_lock:
        if not state.get("config"):
            components["config"] = "error"
            overall_status = "degraded"
        else:
            components["config"] = "ok"
    components["dns_server"] = "unknown"
    return HealthCheckResponseModel(
        status=overall_status,
        timestamp=datetime.now(timezone.utc),
        components=components
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    log_api.exception(f"Unhandled exception during request processing: {request.method} {request.url}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected internal server error occurred."},
    )

###############################################################################
# 8. Main (из main.py)
###############################################################################
def check_port(ip: str, port: int) -> bool:
    """Проверяет, свободен ли TCP/UDP порт"""
    tcp_free = False
    udp_free = False
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind((ip, port))
            tcp_free = True
    except socket.error:
        log.warning(f"TCP port {ip}:{port} seems to be in use.")
        tcp_free = False
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as s:
            s.bind((ip, port))
            udp_free = True
    except socket.error:
        log.warning(f"UDP port {ip}:{port} seems to be in use.")
        udp_free = False
    return tcp_free and udp_free

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True, help='Path to config.yaml')
    args = parser.parse_args()
    if not os.path.isfile(args.config):
        logging.error(f"Config file not found: {args.config}")
        sys.exit(1)
    dns_server_instance = None
    try:
        log.info(f"Loading configuration from: {args.config}")
        config = load_config(args.config)
        init_state(config)
        log.info("Configuration loaded and state initialized.")
        dns_cfg = config["dns"]
        dns_ip = dns_cfg["listen_ip"]
        dns_port = dns_cfg["listen_port"]
        log.info(f"Checking if DNS port {dns_ip}:{dns_port} is free...")
        if not check_port(dns_ip, dns_port):
            log.error(f"DNS port {dns_ip}:{dns_port} is already in use or cannot be bound. Exiting.")
            sys.exit(1)
        log.info(f"DNS port {dns_ip}:{dns_port} appears to be free.")
        log.info("Starting DNS server...")
        dns_server_instance = start_dns_server(config)
        await asyncio.sleep(1)
        log.info("DNS server start initiated.")
        api_cfg = config["api"]
        api_ip = api_cfg["listen_ip"]
        api_port = api_cfg["listen_port"]
        log.info(f"Starting API server on {api_ip}:{api_port}...")
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host=api_ip,
                port=api_port,
                log_level="debug",
                access_log=True
            )
        )
        log.info("Running Uvicorn server...")
        await server.serve()
        log.info("Uvicorn server has stopped.")
    except SystemExit as e:
        log.error(f"System exit requested with code {e.code}.")
    except Exception as e:
        log.exception("Critical error during application lifecycle")
    finally:
        log.info("Shutting down application...")
        if dns_server_instance:
            log.info("Stopping DNS server instance...")
            dns_server_instance.stop()
        else:
            log.info("No active DNS server instance to stop.")
        log.info("Application shutdown complete.")
        if 'e' in locals() and isinstance(e, SystemExit):
            sys.exit(e.code)
        elif 'e' in locals() and isinstance(e, Exception):
            sys.exit(1)
        else:
            sys.exit(0)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("KeyboardInterrupt received (likely handled in main).")
    except Exception as e:
        logging.exception(f"Unexpected error at the top level: {e}")