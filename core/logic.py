from core.state import state, state_lock, atomic_state_update
from datetime import datetime, timezone, timedelta
import logging
import random
import heapq
from typing import List, Tuple, Dict, Optional
import ipaddress

logger = logging.getLogger("LOGIC")

# ============================================
# 1. Вспомогательные функции и функции доступа к конфигу/состоянию
# ============================================

def get_domain_config(domain: str) -> dict:
    """Возвращает конфигурацию домена с блокировкой чтения"""
    # Эта функция может вызываться из разных мест, убедимся, что она атомарна
    def process_callback(s):
        config = s.get("config", {})
        for zone in config.get("zones", []):
            if domain in zone.get("domains", {}):
                # Возвращаем копию, чтобы избежать случайных изменений вне state_lock
                return zone["domains"][domain].copy()
        return {}
    # Используем atomic_state_update для безопасного доступа к config
    return atomic_state_update(process_callback)

def get_ttl_for_domain(domain: str) -> int:
    """Возвращает TTL для домена, читая из состояния"""
    def process_callback(s):
        domain_cfg = get_domain_config(domain) # Получаем конфиг домена
        # TTL из конфига домена имеет приоритет
        ttl = domain_cfg.get("server", {}).get("resolve_cache_ttl") or \
            s.get("config", {}).get("dns", {}).get("resolve_cache_ttl", 5)
        return ttl
    # Используем atomic_state_update, т.к. читаем config и вызываем get_domain_config
    return atomic_state_update(process_callback)


def sort_ips_by_policy(ips: List[str], domain_cfg: dict, policy: str) -> List[str]:
    """Сортирует IP согласно выбранной политике"""
    if not ips:
        return []

    if policy == "priority":
        targets = domain_cfg.get("monitor", {}).get("targets", [])
        # Создаем словарь ip -> priority, с дефолтом, если IP не найден в таргетах
        priorities = {t["ip"]: t.get("priority", 1000) for t in targets if "ip" in t}
        # Сортировка по приоритету (меньше = выше). Нестабильная сортировка может менять порядок для одинаковых приоритетов.
        # Используем стабильную сортировку sorted()
        return sorted(ips, key=lambda ip: priorities.get(ip, 1000))
    elif policy == "any": # "any" обычно означает случайный или round-robin
        # Для детерминизма в рамках одного вызова просто перемешаем
        shuffled_ips = list(ips) # Создаем копию для перемешивания
        random.shuffle(shuffled_ips)
        return shuffled_ips
    # Добавить другие политики (quorum, all), когда они будут реализованы
    else: # По умолчанию или неизвестная политика - просто возвращаем как есть или перемешиваем
        logger.warning(f"Unsupported policy '{policy}' requested, returning shuffled list.")
        shuffled_ips = list(ips)
        random.shuffle(shuffled_ips)
        return shuffled_ips


def get_fallback_list(domain: str, domain_cfg: Optional[dict] = None) -> List[str]:
    """Возвращает fallback IP список с валидацией"""
    def process_callback(s):
        effective_domain_cfg = domain_cfg
        if not effective_domain_cfg:
            _cfg = get_domain_config(domain) # Получаем конфиг внутри callback
            if not _cfg:
                logger.error(f"Cannot get domain config for {domain} to determine fallback IPs.")
                return ["127.0.0.1"]
            effective_domain_cfg = _cfg

        fallback = effective_domain_cfg.get("fallback", [])
        if not isinstance(fallback, list):
            logger.error(f"Invalid fallback configuration for {domain} (not a list), using default.")
            return ["127.0.0.1"]

        if not fallback:
            logger.warning(f"Fallback list is empty for domain {domain}. No fallback IPs available.")
            return []

        valid_ips = []
        for ip in fallback:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                logger.warning(f"Invalid fallback IP format '{ip}' for domain {domain}")

        if not valid_ips and fallback: # Если были настроены fallback, но все невалидны
            logger.error(f"All configured fallback IPs for {domain} are invalid. Returning default.")
            return ["127.0.0.1"]
        elif not valid_ips and not fallback: # Если fallback не были настроены
            return [] # Возвращаем пустой список

        return valid_ips

    # Эта функция читает конфиг через get_domain_config, который уже атомарен
    # Прямого изменения state нет, но для консистентности с get_domain_config используем atomic_state_update
    return atomic_state_update(process_callback)

def apply_rr_policy(ip_list: List[str], domain: str, current_state: dict) -> List[str]:
    """
    Применяет round-robin балансировку к списку IP.
    Модифицирует счетчик в переданном `current_state`.
    """
    if len(ip_list) <= 1:
        return ip_list

    # Доступ к счетчикам RR внутри переданного состояния (уже под блокировкой)
    rr_counters = current_state.setdefault("rr_counters", {})
    rr_idx = rr_counters.get(domain, 0)
    # Обновляем счетчик в переданном состоянии
    rr_counters[domain] = (rr_idx + 1) % len(ip_list)

    # Выполняем сдвиг списка для round-robin
    return ip_list[rr_idx:] + ip_list[:rr_idx]


# ============================================
# 2. Основная логика определения живых IP и DNS ответа
# ============================================

def get_alive_ips(domain: str) -> List[str]:
    """
    Возвращает список живых IP с учетом политик и приоритетов.
    Если живых нет, возвращает fallback IP.
    Функция атомарна.
    """
    def process_callback(s):
        domain_cfg = get_domain_config(domain) # Вызов внутри callback -> OK
        if not domain_cfg:
            logger.warning(f"get_alive_ips called for non-configured domain: {domain}")
            return []

        checks = s.get("checks", {}).get(domain, {})
        timeout_sec = domain_cfg.get("server", {}).get("timeout_sec", 60)
        policy = domain_cfg.get("server", {}).get("policy", "any")
        now = datetime.now(timezone.utc)

        valid_hosts = []
        configured_targets = {t['ip'] for t in domain_cfg.get("monitor", {}).get("targets", []) if 'ip' in t}

        for ip, agents in checks.items():
            if ip not in configured_targets:
                # logger.warning(f"Check received for IP {ip} which is not in targets for domain {domain}. Ignoring.")
                continue # Игнорируем отчеты для IP не из текущей конфигурации

            for agent_id, agent_data in agents.items():
                # Проверка статуса и времени жизни отчета
                ts = agent_data.get("timestamp")
                status = agent_data.get("status")
                if not isinstance(ts, datetime):
                    logger.warning(f"Invalid timestamp type for agent {agent_id} check on {ip}: {type(ts)}")
                    continue

                # Корректное сравнение времени с учетом таймзон
                time_diff = now - ts
                if time_diff >= timedelta(seconds=0) and time_diff.total_seconds() <= timeout_sec and status == "ok":
                    valid_hosts.append(ip)
                    # logger.debug(f"IP {ip} is alive for {domain} based on report from {agent_id} (age: {time_diff.total_seconds():.1f}s)")
                    break # Достаточно одного OK отчета от любого агента для этого IP

        # Убираем дубликаты, если один IP был добавлен несколько раз (хотя break должен предотвращать)
        unique_valid_hosts = sorted(list(set(valid_hosts)))

        if not unique_valid_hosts:
            logger.warning(f"No live IPs found for {domain} within timeout {timeout_sec}s. Using fallback.")
            # Вызов get_fallback_list внутри callback -> OK (он тоже использует atomic_state_update/работает со state)
            return get_fallback_list(domain, domain_cfg)
        else:
            logger.info(f"Live IPs found for {domain}: {unique_valid_hosts}. Applying policy '{policy}'.")
            # Вызов sort_ips_by_policy внутри callback -> OK (он определен выше)
            return sort_ips_by_policy(unique_valid_hosts, domain_cfg, policy)

    return atomic_state_update(process_callback)


def get_dns_response(domain: str) -> Tuple[List[str], int]:
    """
    Генерирует DNS ответ (список IP и TTL) с учетом кеша и политик.
    Функция атомарна.
    """
    def process_callback(s):
        domain_cfg = get_domain_config(domain) # Вызов внутри callback -> OK
        if not domain_cfg:
            logger.debug(f"DNS query for non-configured domain: {domain}")
            default_ttl = s.get("config", {}).get("dns", {}).get("resolve_cache_ttl", 5)
            return [], default_ttl # Возвращаем пустой список и TTL по умолчанию

        cache_key = domain
        resolved_cache = s.setdefault("resolved", {})
        now = datetime.now(timezone.utc)
        # TTL берем из функции get_ttl_for_domain, которая читает из state
        base_ttl = get_ttl_for_domain(domain) # Вызов внутри callback -> OK

        # 1. Проверка кеша
        if cache_key in resolved_cache:
            cached_entry = resolved_cache[cache_key]
            cache_timestamp = cached_entry.get("timestamp")
            cached_ttl = cached_entry.get("ttl", base_ttl) # Используем TTL из кеша

            if isinstance(cache_timestamp, datetime):
                cache_age = (now - cache_timestamp).total_seconds()
                if cache_age >= 0 and cache_age <= cached_ttl:
                    remaining_ttl = max(0, int(cached_ttl - cache_age))
                    logger.debug(f"[CACHE HIT] {domain} -> {cached_entry['ips']} (TTL remaining: {remaining_ttl}s)")
                    # Применяем RR к кешированному результату перед возвратом
                    # Вызов apply_rr_policy -> OK (определен выше, работает с 's')
                    return apply_rr_policy(cached_entry['ips'], domain, s), remaining_ttl
                else:
                    logger.debug(f"[CACHE EXPIRED] {domain} (Age: {cache_age:.1f}s > TTL: {cached_ttl}s)")
            else:
                logger.warning(f"Invalid timestamp in cache for {domain}. Ignoring cache entry.")
                del resolved_cache[cache_key] # Удаляем некорректную запись


        # 2. Кеш устарел или отсутствует - получаем живые IP (включая fallback логику)
        logger.debug(f"[CACHE MISS] Resolving {domain}")
        # Вызов get_alive_ips -> OK (определен выше, атомарен)
        ip_list = get_alive_ips(domain)

        # Определяем, были ли использованы fallback адреса
        # Перепроверяем живые IP в текущем состоянии, так как get_alive_ips вернул результат,
        # который мог быть fallback'ом
        live_ips_exist = False
        checks = s.get("checks", {}).get(domain, {})
        timeout_sec = domain_cfg.get("server", {}).get("timeout_sec", 60)
        for ip, agents in checks.items():
            for agent_data in agents.values():
                ts = agent_data.get("timestamp")
                if isinstance(ts, datetime):
                    time_diff = now - ts
                    if time_diff >= timedelta(seconds=0) and time_diff.total_seconds() <= timeout_sec and agent_data.get("status") == "ok":
                            live_ips_exist = True
                            break
            if live_ips_exist:
                break

        is_fallback = not live_ips_exist and bool(ip_list)

        # Определяем TTL для записи в кеш
        final_ttl = domain_cfg.get("fallback_ttl", base_ttl) if is_fallback else base_ttl

        # 3. Обновляем кеш
        resolved_cache[cache_key] = {
            "ips": ip_list,
            "timestamp": now,
            "ttl": final_ttl,
            "is_fallback": is_fallback
        }

        logger.info(f"[RESOLVE] {domain} -> {ip_list} (TTL: {final_ttl}, Fallback: {is_fallback})")
        # Применяем RR к свежему результату перед возвратом
        # Вызов apply_rr_policy -> OK
        return apply_rr_policy(ip_list, domain, s), final_ttl

    return atomic_state_update(process_callback)


# ============================================
# 3. Функции обновления состояния от агентов
# ============================================

def update_status(report) -> None:
    """Обновляет статус проверок на основе отчета от агента. Функция атомарна."""
    def update_callback(s):
        domain = report.domain
        host = report.target_ip
        agent = report.agent_id

        # Проверка существования домена в конфиге перед обновлением
        domain_cfg = get_domain_config(domain) # Вызов внутри callback -> OK
        if not domain_cfg:
            logger.warning(f"Received status report from agent {agent} for non-configured domain {domain}. Ignoring.")
            return # Не обновляем статус для неконфигурированных доменов

        # Проверка, что IP есть в таргетах этого домена
        configured_targets = {t['ip'] for t in domain_cfg.get("monitor", {}).get("targets", []) if 'ip' in t}
        if host not in configured_targets:
            logger.warning(f"Received status report from agent {agent} for domain {domain} target IP {host} which is not configured in targets. Ignoring.")
            return # Игнорируем отчеты для IP не из текущей конфигурации

        # Получаем словарь проверок для домена и хоста
        domain_checks = s.setdefault("checks", {}).setdefault(domain, {})
        host_checks = domain_checks.setdefault(host, {})

        # Обновляем данные для конкретного агента
        host_checks[agent] = {
            "status": report.status,
            "timestamp": report.timestamp,
            "latency_ms": report.latency_ms,
            "port": report.port, # Добавим порт из отчета
            "reason": report.reason # И причину ошибки, если есть
        }

        # Очистка кеша DNS для этого домена при получении нового статуса
        if domain in s.get("resolved", {}):
            logger.debug(f"Clearing DNS cache for {domain} due to new report from {agent}")
            del s["resolved"][domain]

        logger.info(f"Status updated by {agent} for {domain} -> {host}:{report.port} = {report.status}")

    atomic_state_update(update_callback)


# ============================================
# 4. Функции для API (статус, детали, задачи)
# ============================================

# --- Вспомогательные функции для API статуса ---

def _update_agent_status_summary(agents_summary: dict, agent_id: str, ip: str, ts: datetime) -> None:
    """Обновляет информацию об агентах в словаре для статусных API."""
    if agent_id not in agents_summary:
        agents_summary[agent_id] = {
            "agent_id": agent_id,
            "last_seen": ts,
            "checked_ips": set([ip]) # Используем set для уникальности
        }
    else:
        agents_summary[agent_id]["checked_ips"].add(ip)
        if ts > agents_summary[agent_id]["last_seen"]:
            agents_summary[agent_id]["last_seen"] = ts

def _build_domain_status(domain: str, cfg: dict, checks: dict, now: datetime) -> dict:
    """Строит статус для одного домена (для /api/v1/status)."""
    timeout = cfg.get("server", {}).get("timeout_sec", 60)
    live_ips = set()
    agents_summary = {} # Словарь agent_id -> {last_seen, checked_ips}
    latest_ts = None

    domain_checks = checks.get(domain, {})
    configured_targets = {t['ip'] for t in cfg.get("monitor", {}).get("targets", []) if 'ip' in t}

    for ip, agents_reports in domain_checks.items():
        if ip not in configured_targets:
            continue # Игнорируем статус для неконфигурированных IP

        ip_is_live = False
        for agent_id, data in agents_reports.items():
            ts = data.get("timestamp")
            if isinstance(ts, datetime):
                # Обновляем общую информацию об агенте
                _update_agent_status_summary(agents_summary, agent_id, ip, ts)
                latest_ts = max(latest_ts, ts) if latest_ts else ts

                # Проверяем живость IP
                time_diff = now - ts
                if not ip_is_live and time_diff >= timedelta(seconds=0) and time_diff.total_seconds() <= timeout and data.get("status") == "ok":
                    live_ips.add(ip)
                    ip_is_live = True # Этот IP жив, можно не проверять другие отчеты для него

    status = {
        "domain": domain,
        "live_ips": sorted(list(live_ips)),
        "using_fallback": not live_ips, # Используем fallback, если нет живых IP
        "fallback_ips": cfg.get("fallback", []),
        "agents": [], # Будет заполнено ниже
        "last_updated": latest_ts.isoformat() if latest_ts else None
    }

    # Преобразуем agents_summary в список для ответа API
    agent_list = []
    for agent_id, summary in agents_summary.items():
        agent_list.append({
            "agent_id": agent_id,
            "last_seen": summary["last_seen"],#.isoformat(), # Модель Pydantic ожидает datetime
            "checked_ips": sorted(list(summary["checked_ips"]))
        })
    # Сортируем агентов по ID для стабильности
    status["agents"] = sorted(agent_list, key=lambda a: a["agent_id"])

    return status


# --- Функции для эндпоинтов API ---

def get_domain_status() -> List[dict]:
    """Генерирует статус всех доменов для API. Функция атомарна."""
    def process_callback(s):
        result = []
        now = datetime.now(timezone.utc)
        config = s.get("config", {})
        checks = s.get("checks", {})

        for zone in config.get("zones", []):
            for domain, cfg in zone.get("domains", {}).items():
                # Вызов _build_domain_status внутри callback -> OK
                result.append(_build_domain_status(domain, cfg, checks, now))

        # Сортируем домены по имени для стабильности
        return sorted(result, key=lambda d: d["domain"])

    return atomic_state_update(process_callback)


def _ip_has_live_checks(ip: str, ip_agents_reports: dict, timeout: int, now: datetime) -> bool:
    """Проверяет, есть ли живые проверки для IP в переданных отчетах."""
    for agent_data in ip_agents_reports.values():
        ts = agent_data.get("timestamp")
        if isinstance(ts, datetime):
            time_diff = now - ts
            if time_diff >= timedelta(seconds=0) and time_diff.total_seconds() <= timeout and agent_data.get("status") == "ok":
                return True
    return False

def _build_ip_checks_details(checks: dict, cfg: dict, now: datetime) -> dict:
    """Формирует детальную информацию о проверках IP для /api/v1/status/{domain}."""
    timeout = cfg.get("server", {}).get("timeout_sec", 60)
    ip_checks_details = {}
    domain_checks = checks.get(cfg["_domain_name_for_context_"], {}) # Используем переданное имя домена
    targets_map = {t['ip']: t for t in cfg.get("monitor", {}).get("targets", []) if 'ip' in t}


    for ip, agents_reports in domain_checks.items():
        if ip not in targets_map:
            continue # Игнорируем IP не из конфига

        reports_list = []
        ip_is_live = False
        for agent_id, data in agents_reports.items():
            ts = data.get("timestamp")
            is_expired = True
            if isinstance(ts, datetime):
                time_diff = now - ts
                is_expired = not (time_diff >= timedelta(seconds=0) and time_diff.total_seconds() <= timeout)
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
            "port": targets_map[ip].get("port"), # Берем порт из конфига таргета
            "agents": sorted(reports_list, key=lambda r: r["agent_id"]) # Сортируем агентов
        }

    # Добавляем информацию для IP из конфига, по которым еще не было отчетов
    for target_ip, target_cfg in targets_map.items():
        if target_ip not in ip_checks_details:
            ip_checks_details[target_ip] = {
                "status": "unknown", # Или "fail" по умолчанию?
                "port": target_cfg.get("port"),
                "agents": []
            }


    return ip_checks_details


def get_domain_details(domain: str) -> dict:
    """Возвращает детальную информацию о домене для API. Функция атомарна."""
    def process_callback(s):
        cfg = get_domain_config(domain) # Вызов внутри callback -> OK
        if not cfg:
            # Эта проверка дублируется в API роуте, но безопаснее иметь ее и здесь
            raise KeyError(f"Domain '{domain}' not found in configuration")

        checks = s.get("checks", {})
        now = datetime.now(timezone.utc)
        timeout = cfg.get("server", {}).get("timeout_sec", 60)

        # Проверяем общую живость домена (есть ли хоть один живой IP)
        domain_is_live = False
        domain_checks = checks.get(domain, {})
        for ip, agents_reports in domain_checks.items():
            # Вызов _ip_has_live_checks внутри callback -> OK
            if _ip_has_live_checks(ip, agents_reports, timeout, now):
                domain_is_live = True
                break

        # Добавляем имя домена в конфиг для контекста в _build_ip_checks_details
        cfg["_domain_name_for_context_"] = domain
        ip_checks_data = _build_ip_checks_details(checks, cfg, now) # Вызов внутри callback -> OK

        return {
            "domain": domain,
            "check_type": cfg.get("monitor", {}).get("mode", "tcp"),
            "live": domain_is_live,
            "fallback_ips": cfg.get("fallback", []),
            "ip_checks": ip_checks_data
        }

    return atomic_state_update(process_callback)


# --- Функции для API задач ---

def _should_include_domain_for_task(domain_cfg: dict, agent_tags: List[str]) -> bool:
    """Определяет, должен ли домен быть включен в задачи по тегам."""
    monitor_cfg = domain_cfg.get("monitor", {})
    required_tag = monitor_cfg.get("monitor_tag") # Ожидаем один тег или None

    if not required_tag:
        # Если тег не указан в конфиге домена, задачи для него не выдаются по тегам?
        # Или выдаются всем агентам? Уточнить логику.
        # Текущая реализация README подразумевает фильтрацию по тегу.
        # Если тег не задан, ни один агент по тегу его не получит.
        return False

    # monitor_tag может быть списком или строкой через пробел/запятую - нормализуем к списку
    required_tags_list = []
    if isinstance(required_tag, str):
        required_tags_list = [tag.strip() for tag in required_tag.replace(",", " ").split() if tag.strip()]
    elif isinstance(required_tag, list):
        required_tags_list = [str(tag).strip() for tag in required_tag if str(tag).strip()]

    if not required_tags_list: # Если теги были, но пустые после очистки
        return False

    # Проверяем пересечение тегов агента и тегов домена
    return bool(set(required_tags_list) & set(agent_tags))

def _create_tasks_for_domain(domain: str, domain_cfg: dict) -> List[dict]:
    """Создает задачи мониторинга для одного домена."""
    tasks = []
    monitor_cfg = domain_cfg.get("monitor", {})
    agent_cfg = domain_cfg.get("agent", {})
    check_mode = monitor_cfg.get("mode", "tcp")

    for target in monitor_cfg.get("targets", []):
        target_ip = target.get("ip")
        # Порт может быть не нужен для ICMP
        target_port = target.get("port") if check_mode != 'icmp' else None

        if not target_ip:
            logger.warning(f"Skipping task creation for domain {domain} due to missing target IP in {target}")
            continue
        # Добавим проверку валидности IP тут? Или положимся на config_loader?
        # try:
        #     ipaddress.ip_address(target_ip)
        # except ValueError:
        #     logger.warning(f"Skipping task for domain {domain} due to invalid target IP: {target_ip}")
        #     continue

        tasks.append({
            # Имя чека должно быть уникальным
            "check_name": f"{domain}:{target_ip}:{target_port or 'icmp'}",
            "domain": domain,
            "target_ip": target_ip,
            "port": target_port, # Будет None для ICMP
            "type": check_mode,
            "timeout_sec": agent_cfg.get("timeout_sec", 5), # Таймаут на выполнение одного чека
            "interval_sec": agent_cfg.get("interval_sec", 30) # Интервал между чеками
        })

    return tasks

def extract_monitor_tasks(agent_tags: List[str], agent_api_key: Optional[str]) -> List[dict]:
    """
    Генерирует задачи мониторинга для доменов, на которые у агента
    есть права (совпадает токен) и совпадают теги. Функция атомарна.
    """
    def process_callback(s):
        tasks = []
        config = s.get("config", {})

        # Если нет тегов у агента, не выдаем задач (требуем хотя бы один тег)
        if not agent_tags:
            logger.warning("Agent requested tasks with no tags.")
            return []

        for zone in config.get("zones", []):
            for domain, domain_cfg in zone.get("domains", {}).items():
                # 1. Проверка токена доступа к домену
                expected_token = domain_cfg.get("agent", {}).get("token")
                # Если токен для домена не задан, любой агент (даже без ключа) может получить задачу?
                # Или если токен не задан, никто не может?
                # Текущая логика: Если токен задан, он должен совпасть. Если не задан, доступ разрешен (даже без ключа).
                token_match = (not expected_token) or (agent_api_key == expected_token)

                if not token_match:
                    # logger.debug(f"Agent key mismatch or missing for domain {domain}. Skipping tasks.")
                    continue # Ключ не совпадает (и он требовался), пропускаем домен

                # 2. Проверка совпадения тегов (если токен совпал или не требовался)
                # Вызов _should_include_domain_for_task внутри callback -> OK
                if _should_include_domain_for_task(domain_cfg, agent_tags):
                    # Вызов _create_tasks_for_domain внутри callback -> OK
                    tasks.extend(_create_tasks_for_domain(domain, domain_cfg))

        logger.info(f"Extracted {len(tasks)} tasks for agent tags: {agent_tags} (Key provided: {'yes' if agent_api_key else 'no'})")
        # Сортируем задачи по имени для стабильности
        return sorted(tasks, key=lambda t: t["check_name"])

    return atomic_state_update(process_callback)