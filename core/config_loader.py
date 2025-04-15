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

    # Удалена проверка совместимости потоков DNS и API, т.к. DNS сервер однопоточный
    # dns_threads = config['dns'].get('threads', 1)
    # api_enabled = config['api'].get('enabled', True)
    #
    # if dns_threads > 1 and api_enabled:
    #     raise ConfigValidationError(
    #         "Multi-threaded DNS server requires API to be disabled "
    #         "(set api.enabled: false)"
    #     )

    # Установка значений по умолчанию
    config['dns'].setdefault('resolve_cache_ttl', 5)
    # config['dns'].setdefault('threads', 1) # Этот параметр не используется
    config['api'].setdefault('enabled', True) # Параметр 'enabled' не используется в main.py, но оставим для ясности

    log.info(f"Loaded valid config from {path}") # Исправлено: config_path -> path
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
    # Добавим 'all' и 'quorum' как возможные, но пока не реализованные
    valid_policies = ['any', 'priority', 'quorum', 'all']
    if server_cfg.get('policy', 'any') not in valid_policies:
        log.warning(f"Policy {server_cfg['policy']} for domain {domain} is not fully supported yet.")
        # Пока не будем падать, разрешим использовать 'any' или 'priority'
        if server_cfg.get('policy', 'any') not in ['any', 'priority']:
            raise ConfigValidationError(
            f"Invalid or unsupported server policy for {domain}: {server_cfg['policy']}. Supported: any, priority"
        )


    # Валидация мониторинга
    monitor_cfg = domain_cfg['monitor']
    # Добавим http, icmp как возможные, но пока не реализованные агентом
    valid_modes = ['tcp', 'http', 'icmp']
    if monitor_cfg.get('mode', 'tcp') not in valid_modes:
        log.warning(f"Monitor mode {monitor_cfg['mode']} for domain {domain} might not be supported by agents yet.")
        # Пока не будем падать, но предупредим
        # raise ConfigValidationError(
        #    f"Invalid monitor mode for {domain}: {monitor_cfg['mode']}"
        # )

    # Проверка целей мониторинга
    targets = monitor_cfg.get('targets', [])
    if not isinstance(targets, list) or len(targets) == 0:
        raise ConfigValidationError(
            f"Domain {domain} must have at least one monitoring target"
        )

    for target in targets:
        # Порт не обязателен для ICMP
        if 'ip' not in target:
            raise ConfigValidationError(
                f"Invalid target configuration in {domain} (missing ip): {target}"
            )
        if monitor_cfg.get('mode', 'tcp') != 'icmp' and 'port' not in target:
            raise ConfigValidationError(
                f"Invalid target configuration in {domain} (missing port for non-ICMP check): {target}"
            )
        # Проверка IP адреса в таргете
        try:
            ipaddress.ip_address(target['ip'])
        except ValueError:
            raise ConfigValidationError(
                f"Invalid target IP in {domain}: {target['ip']}"
            )


    # Валидация fallback IP
    fallback = domain_cfg['fallback']
    if not isinstance(fallback, list): # Пустой список разрешен, если не хотим fallback
        raise ConfigValidationError(
            f"Fallback for domain {domain} must be a list"
        )
    # Убираем проверку на len > 0, пустой fallback может быть легитимным
    # if len(fallback) == 0:
    #     raise ConfigValidationError(
    #         f"Domain {domain} must have non-empty fallback list"
    #     )

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