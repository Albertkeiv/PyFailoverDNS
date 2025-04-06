import asyncio
import uvicorn
from api.routes import app as api_app
from dns.server import start_dns_server
from core.config_loader import load_config
from core.state import init_state, state
import logging
import argparse

CONFIG_PATH = "config.yaml"

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s'
)

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config.yaml', help='Путь к конфигурационному файлу')
    args = parser.parse_args()

    config = load_config(args.config)
    init_state(config)

    # Запускаем DNS-сервер в отдельной задаче
    start_dns_server(config)

    # Запускаем API-сервер
    api_cfg = config["api"]
    uvicorn_config = uvicorn.Config(api_app, host=api_cfg["listen_ip"], port=api_cfg["listen_port"], log_level="debug")
    server = uvicorn.Server(uvicorn_config)
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())