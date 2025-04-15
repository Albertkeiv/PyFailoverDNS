import os
import sys
import argparse
import asyncio
import uvicorn
import socket # Импортируем socket
from contextlib import closing # Для безопасного закрытия сокета
from api.routes import app as api_app
from dns.server import start_dns_server
from core.config_loader import load_config
from core.state import init_state
import logging

logging.basicConfig(
    level=logging.DEBUG, # Убедись, что уровень DEBUG
    format='%(asctime)s [%(name)s] [%(levelname)s] %(message)s'
)
log = logging.getLogger("MAIN") # Используем логгер для main

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
        logging.error(f"Config file not found: {args.config}") # Используем стандартный logging до настройки логгера MAIN
        sys.exit(1)

    dns_server_instance = None # Для корректной остановки

    try:
        log.info(f"Loading configuration from: {args.config}")
        config = load_config(args.config)
        init_state(config)
        log.info("Configuration loaded and state initialized.")

        # --- Проверка порта DNS ---
        dns_cfg = config["dns"]
        dns_ip = dns_cfg["listen_ip"]
        dns_port = dns_cfg["listen_port"]
        log.info(f"Checking if DNS port {dns_ip}:{dns_port} is free...")
        if not check_port(dns_ip, dns_port):
            log.error(f"DNS port {dns_ip}:{dns_port} is already in use or cannot be bound. Exiting.")
            sys.exit(1)
        log.info(f"DNS port {dns_ip}:{dns_port} appears to be free.")
        # --- Конец проверки порта DNS ---

        # Запуск DNS сервера
        log.info("Starting DNS server...")
        dns_server_instance = start_dns_server(config) # Сохраняем экземпляр
        # Небольшая пауза, чтобы дать потоку DNS шанс запуститься и возможно выдать ошибку
        await asyncio.sleep(1)
        log.info("DNS server start initiated.")

        # Запуск API сервера
        api_cfg = config["api"]
        api_ip = api_cfg["listen_ip"]
        api_port = api_cfg["listen_port"]
        log.info(f"Starting API server on {api_ip}:{api_port}...")

        server = uvicorn.Server(
            uvicorn.Config(
                api_app,
                host=api_ip,
                port=api_port,
                log_level="debug", # Логирование uvicorn
                access_log=True # Включаем логи доступа API
            )
        )

        # Запуск uvicorn и ожидание его завершения
        log.info("Running Uvicorn server...")
        await server.serve()
        # Эта строка выполнится только после остановки Uvicorn (например, по Ctrl+C)
        log.info("Uvicorn server has stopped.")

    except SystemExit as e:
        # Перехватываем sys.exit(), чтобы выполнить очистку
        log.error(f"System exit requested with code {e.code}.")
        # sys.exit(e.code) # Можно выйти здесь или после очистки
    except Exception as e:
        log.exception("Critical error during application lifecycle")
        # sys.exit(1) # Выход после очистки
    finally:
        log.info("Shutting down application...")
        # Останавливаем DNS сервер при выходе
        if dns_server_instance:
            log.info("Stopping DNS server instance...")
            dns_server_instance.stop()
        else:
            log.info("No active DNS server instance to stop.")
        log.info("Application shutdown complete.")
        # Выходим с кодом ошибки, если он был
        if 'e' in locals() and isinstance(e, SystemExit):
            sys.exit(e.code)
        elif 'e' in locals() and isinstance(e, Exception):
            sys.exit(1)
        else:
            sys.exit(0) # Нормальный выход

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # Обработка Ctrl+C происходит внутри main() -> finally теперь
        log.info("KeyboardInterrupt received (likely handled in main).")
    except Exception as e:
        # Ловим ошибки, которые могли произойти вне main() или до/после asyncio.run()
        logging.exception(f"Unexpected error at the top level: {e}")