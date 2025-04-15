import os
import sys
import argparse
import asyncio
import uvicorn
from api.routes import app as api_app
from dns.server import start_dns_server
from core.config_loader import load_config
from core.state import init_state
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s'
)

async def main():
    # Парсинг аргументов командной строки
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True, help='Path to config.yaml')
    args = parser.parse_args()

    # Проверка существования файла
    if not os.path.isfile(args.config):
        logging.error(f"Config file not found: {args.config}")
        sys.exit(1)

    try:
        # Загрузка конфигурации
        config = load_config(args.config)  # Используем args.config
        init_state(config)
        
        # Запуск DNS сервера
        dns_server = start_dns_server(config)
        
        # Запуск API сервера
        api_cfg = config["api"]
        server = uvicorn.Server(
            uvicorn.Config(
                api_app,
                host=api_cfg["listen_ip"],
                port=api_cfg["listen_port"],
                log_level="debug"
            )
        )
        
        await server.serve()
    except Exception as e:
        logging.exception("Critical error during startup")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Shutdown by Ctrl+C")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")