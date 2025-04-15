import asyncio
import uvicorn
from api.routes import app as api_app
from dns.server import start_dns_server
from core.config_loader import load_config
from core.state import init_state, state
import logging
import argparse
import os
import sys

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s'
)

def validate_config(config: dict):
    required_fields = [
        ("dns", "listen_ip"),
        ("dns", "listen_port"),
        ("api", "listen_ip"),
        ("api", "listen_port"),
    ]
    for section, key in required_fields:
        if section not in config or key not in config[section]:
            raise ValueError(f"Missing required config value: '{section}.{key}'")

    zones = config.get("zones")
    if not zones or not isinstance(zones, list):
        raise ValueError("Missing or invalid 'zones' block in config.yaml")

    valid_domain_found = False
    for zone in zones:
        domains = zone.get("domains")
        if domains and isinstance(domains, dict):
            valid_domain_found = True
            break

    if not valid_domain_found:
        raise ValueError("No valid 'domains' found inside any 'zones' in config.yaml")


async def main():
    parser = argparse.ArgumentParser(description="PyFailoverDNS — отказоустойчивый DNS с логикой failover")
    parser.add_argument('--config', required=True, help='Путь к конфигурационному файлу YAML')
    args = parser.parse_args()

    if not os.path.exists(args.config):
        print(f"[FATAL] Конфигурационный файл не найден: {args.config}", file=sys.stderr)
        sys.exit(1)

    config = load_config(args.config)

    try:
        validate_config(config)
    except ValueError as e:
        print(f"[FATAL] Ошибка конфигурации: {e}", file=sys.stderr)
        sys.exit(1)

    init_state(config)
    dns_server = start_dns_server(config)

    api_cfg = config["api"]
    uvicorn_config = uvicorn.Config(api_app, host=api_cfg["listen_ip"], port=api_cfg["listen_port"], log_level="debug")
    server = uvicorn.Server(uvicorn_config)
    await server.serve()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Завершение по Ctrl+C")