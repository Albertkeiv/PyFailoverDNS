from dnslib.server import BaseResolver
from dnslib import RR, A, QTYPE
from core.logic import get_dns_response
from core.state import state, state_lock
import logging
from typing import List, Tuple
import ipaddress

logger = logging.getLogger("DNS")

class FailoverResolver(BaseResolver):
    def __init__(self, config: dict):
        self.config = config
        self._validate_config()

    def _validate_config(self) -> None:
        """Проверяем обязательные параметры конфигурации"""
        if not self.config.get('dns'):
            raise ValueError("Missing DNS configuration")
        if not self.config['dns'].get('resolve_cache_ttl'):
            raise ValueError("Missing resolve_cache_ttl in DNS config")

    def resolve(self, request, handler) -> RR:
        """Основной метод обработки DNS-запросов"""
        qname = str(request.q.qname).rstrip('.')
        qtype = QTYPE[request.q.qtype]
        reply = request.reply()

        try:
            if qtype == "A":
                self._process_a_record(qname, reply)
            else:
                logger.warning(f"Unsupported query type: {qtype}")
        except Exception as e:
            logger.error(f"Failed to process query: {e}")
            return reply

        return reply

    def _process_a_record(self, qname: str, reply: RR) -> None:
        """Обрабатывает A-запросы с учетом failover логики"""
        with state_lock:
            try:
                ip_list, ttl = get_dns_response(qname)
            except KeyError:
                logger.error(f"Domain not found: {qname}")
                return

        valid_ips = self._validate_ips(ip_list, qname)
        
        for ip in valid_ips:
            reply.add_answer(
                RR(
                    qname,
                    QTYPE.A,
                    rdata=A(ip),
                    ttl=ttl
                )
            )
        logger.info(f"Resolved {qname} → {valid_ips} (TTL: {ttl})")

    def _validate_ips(self, ips: List[str], domain: str) -> List[str]:
        """Фильтрует и валидирует IP-адреса"""
        valid_ips = []
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                logger.warning(f"Invalid IP {ip} for domain {domain}")
        return valid_ips or self._get_default_fallback(domain)

    def _get_default_fallback(self, domain: str) -> List[str]:
        """Возвращает дефолтный fallback при отсутствии валидных IP"""
        logger.error(f"All IPs invalid for {domain}, using default fallback")
        return ["127.0.0.1"]