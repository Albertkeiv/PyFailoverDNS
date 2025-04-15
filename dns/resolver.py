from dnslib.server import BaseResolver
from dnslib import RR, A, QTYPE
from core.logic import get_dns_response, get_fallback_list, get_domain_config # Импортируем недостающие
from core.state import state, state_lock # Импортируем глобальные переменные
import logging
from typing import List, Tuple
import ipaddress
import threading # Импортируем threading

logger = logging.getLogger("DNS")

class FailoverResolver(BaseResolver):
    def __init__(self, config: dict, state: dict, lock: threading.RLock): # Добавляем state и lock
        self.config = config
        self.state = state # Сохраняем state
        self.state_lock = lock # Сохраняем lock
        self._validate_config() # Валидация базовых вещей остается

    def _validate_config(self) -> None:
        """Проверяем обязательные параметры конфигурации DNS"""
        # Упростим валидацию, основная логика в config_loader
        if not self.config.get('dns'):
            raise ValueError("Missing DNS configuration section")
        if 'resolve_cache_ttl' not in self.config.get('dns', {}):
            # Установим значение по умолчанию, если не найдено, т.к. config_loader уже должен был это сделать
            self.config.setdefault('dns', {}).setdefault('resolve_cache_ttl', 5)
            logger.warning("resolve_cache_ttl not found in DNS config, using default 5s")
            # raise ValueError("Missing resolve_cache_ttl in DNS config") - Не падать, а использовать дефолт

    def resolve(self, request, handler) -> RR:
        """Основной метод обработки DNS-запросов"""
        qname = str(request.q.qname).rstrip('.')
        qtype = QTYPE[request.q.qtype]
        reply = request.reply()

        try:
            # Проверяем, есть ли такой домен в нашей конфигурации
            domain_cfg = get_domain_config(qname) # Используем функцию из logic
            if not domain_cfg:
                logger.debug(f"Domain not configured or handled by this server: {qname}")
                # Не отвечаем на запросы для неконфигурированных доменов
                # Можно настроить пересылку на другие серверы, если нужно
                return reply # Возвращаем пустой ответ (NXDOMAIN неявно)

            if qtype == "A":
                self._process_a_record(qname, reply, domain_cfg) # Передаем domain_cfg
            else:
                logger.warning(f"Unsupported query type: {qtype} for domain {qname}")
        except Exception as e:
            logger.exception(f"Failed to process query for {qname}: {e}") # Используем logger.exception для traceback
            return reply # Возвращаем пустой ответ при ошибке

        return reply

    def _process_a_record(self, qname: str, reply: RR, domain_cfg: dict) -> None: # Принимаем domain_cfg
        """Обрабатывает A-запросы с учетом failover логики"""
        try:
            # get_dns_response теперь использует state и lock напрямую через atomic_state_update
            ip_list, ttl = get_dns_response(qname)
        except Exception as e: # Ловим более общие ошибки на всякий случай
            logger.exception(f"Error resolving domain {qname} via core logic: {e}")
            ip_list = [] # Возвращаем пустой список в случае ошибки
            ttl = self.config.get('dns', {}).get('resolve_cache_ttl', 5) # Используем TTL по умолчанию


        # Валидация IP адресов происходит внутри get_dns_response -> get_alive_ips -> get_fallback_list
        # Если get_dns_response вернул пустой список, значит, нет живых IP и нет fallback'ов (или они некорректны)
        # В этом случае не добавляем A записи

        # Проверим, вернулся ли fallback из-за отсутствия живых IP
        # Это можно определить, сравнив ip_list с fallback_list, но проще добавить флаг в get_dns_response,
        # но пока оставим так - если ip_list не пуст, значит что-то вернулось (либо живые, либо fallback)
        is_fallback = False # TODO: Улучшить определение использования fallback

        if not ip_list:
            logger.warning(f"No IPs (live or fallback) available for domain {qname}")
            # Можно установить SOA или NXDOMAIN, но пока просто не добавляем записи
            # ttl = domain_cfg.get("fallback_ttl", 30) # Можно использовать fallback_ttl для негативного кэширования
            return # Не добавлять записи, если список пуст

        valid_ips = self._validate_ips_format(ip_list, qname) # Дополнительная проверка формата

        if not valid_ips:
            logger.error(f"IP list for {qname} received from logic contains invalid formats: {ip_list}. Not returning records.")
            return

        effective_ttl = ttl
        # Если использовался fallback, можно применить fallback_ttl, если он задан
        # if is_fallback and "fallback_ttl" in domain_cfg:
        #     effective_ttl = domain_cfg["fallback_ttl"]

        for ip in valid_ips:
            reply.add_answer(
                RR(
                    qname,
                    QTYPE.A,
                    rdata=A(ip),
                    ttl=effective_ttl # Используем определенный TTL
                )
            )
        logger.info(f"Resolved {qname} -> {valid_ips} (TTL: {effective_ttl})")

    def _validate_ips_format(self, ips: List[str], domain: str) -> List[str]:
        """Фильтрует и валидирует только формат IP-адресов"""
        valid_ips = []
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                logger.warning(f"Invalid IP format '{ip}' provided for domain {domain}")
        return valid_ips

    # _get_default_fallback убран, т.к. логика fallback теперь полностью в core.logic