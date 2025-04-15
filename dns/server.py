from dnslib.server import DNSServer
from dns.resolver import FailoverResolver
from core.state import state, state_lock
from core.config_loader import load_config
import logging
import threading

logger = logging.getLogger("DNS")

class ThreadedDNSServer:
    def __init__(self, config_path: str):
        self.config = load_config(config_path)
        self.server = None
        self.thread = None

    def start(self):
        """Запускает DNS сервер в отдельном потоке"""
        resolver = FailoverResolver(
            config=self.config,
            state=state,
            lock=state_lock
        )

        self.server = DNSServer(
            resolver,
            port=self.config['dns']['listen_port'],
            address=self.config['dns']['listen_ip'],
            tcp=True,
            logger=logger
        )

        self.thread = threading.Thread(target=self.server.start)
        self.thread.daemon = True
        self.thread.start()
        logger.info(f"DNS server started on {self.config['dns']['listen_ip']}:{self.config['dns']['listen_port']}")

    def stop(self):
        """Останавливает DNS сервер"""
        if self.server:
            self.server.stop()
            self.thread.join()
            logger.info("DNS server stopped")

def start_dns_server(config_path: str) -> ThreadedDNSServer:
    """Фабричная функция для создания и запуска сервера"""
    server = ThreadedDNSServer(config_path)
    server.start()
    return server