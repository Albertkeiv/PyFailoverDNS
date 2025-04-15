import os
import yaml
import ipaddress
from typing import Dict, Any
from datetime import datetime
import logging

log = logging.getLogger("CONFIG")

class ConfigValidationError(ValueError):
    pass

def load_config(path: str) -> dict:
    """
    Загружает и валидирует конфигурационный файл YAML
    Возвращает нормализованный конфиг словарем
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, 'r') as f:
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
            raise ConfigValidationError(
                f"Missing required config value: {section}.{key}"
            )

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
            # Проверка уникальности доменов
            if domain in seen_domains:
                raise ConfigValidationError(f"Duplicate domain: {domain}")
            seen_domains.add(domain)

            # Валидация конфигурации домена
            validate_domain_config(domain, domain_cfg)

    # Проверка совместимости потоков DNS и API
    dns_threads = config['dns'].get('threads', 1)
    api_enabled = config['api'].get('enabled', True)
    
    if dns_threads > 1 and api_enabled:
        raise ConfigValidationError(
            "Multi-threaded DNS server requires API to be disabled "
            "(set api.enabled: false)"
        )

    # Установка значений по умолчанию
    config['dns'].setdefault('resolve_cache_ttl', 5)
    config['dns'].setdefault('threads', 1)
    config['api'].setdefault('enabled', True)

    log.info(f"Loaded valid config from {config_path}")
    return config

def validate_domain_config(domain: str, domain_cfg: dict):
    """Валидация конфигурации отдельного домена"""
    required_sections = ['server', 'monitor', 'fallback']
    
    for section in required_sections:
        if section not in domain_cfg:
            raise ConfigValidationError(
                f"Domain {domain} missing required section: {section}"
            )

    # Валидация серверных настроек
    server_cfg = domain_cfg['server']
    if server_cfg.get('policy', 'any') not in ['any', 'priority']:
        raise ConfigValidationError(
            f"Invalid server policy for {domain}: {server_cfg['policy']}"
        )

    # Валидация мониторинга
    monitor_cfg = domain_cfg['monitor']
    if monitor_cfg.get('mode', 'tcp') not in ['tcp', 'http', 'icmp']:
        raise ConfigValidationError(
            f"Invalid monitor mode for {domain}: {monitor_cfg['mode']}"
        )

    # Проверка целей мониторинга
    targets = monitor_cfg.get('targets', [])
    if not isinstance(targets, list) or len(targets) == 0:
        raise ConfigValidationError(
            f"Domain {domain} must have at least one monitoring target"
        )

    for target in targets:
        if 'ip' not in target or 'port' not in target:
            raise ConfigValidationError(
                f"Invalid target configuration in {domain}: {target}"
            )

    # Валидация fallback IP
    fallback = domain_cfg['fallback']
    if not isinstance(fallback, list) or len(fallback) == 0:
        raise ConfigValidationError(
            f"Domain {domain} must have non-empty fallback list"
        )

    for ip in fallback:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ConfigValidationError(
                f"Invalid fallback IP in {domain}: {ip}"
            )

    # Валидация агента
    agent_cfg = domain_cfg.get('agent', {})
    if agent_cfg.get('token') and len(agent_cfg['token']) < 8:
        raise ConfigValidationError(
            f"Agent token for {domain} must be at least 8 characters"
        )