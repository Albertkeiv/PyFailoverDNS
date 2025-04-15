from dnslib.server import DNSServer
from dns.resolver import FailoverResolver
from core.state import state, state_lock
import logging
import threading
import time # Добавим time для возможной задержки

logger = logging.getLogger("DNS")

logger.setLevel(logging.DEBUG)

class ThreadedDNSServer:
    def __init__(self, config: dict):
        self.config = config
        self.server = None
        self.thread = None
        self._stop_event = threading.Event() # Добавим событие для управления остановкой

    def start(self):
        """Запускает DNS сервер в отдельном потоке"""
        try:
            resolver = FailoverResolver(
                config=self.config,
                state=state,
                lock=state_lock
            )

            dns_cfg = self.config['dns']
            listen_ip = dns_cfg['listen_ip']
            listen_port = dns_cfg['listen_port']

            logger.info(f"Attempting to create DNSServer on {listen_ip}:{listen_port}")
            self.server = DNSServer(
                resolver,
                port=listen_port,
                address=listen_ip,
            )
            logger.info("DNSServer object created successfully.")

        except Exception as e:
            # Логируем ошибку создания резолвера или сервера
            logger.exception("Failed to initialize DNSServer components")
            self.server = None # Убедимся, что сервер не будет запущен
            return # Не запускаем поток, если инициализация не удалась

        # Запускаем поток только если сервер успешно создан
        if self.server:
            logger.debug("Starting DNS server thread...")
            # Установим daemon=False временно для диагностики!
            # Если основная программа завершится, этот поток не даст ей закрыться,
            # что поможет понять, проблема в этом потоке или в основной программе.
            self.thread = threading.Thread(target=self._run_server, name="DNSServerThread", daemon=False)
            # self.thread.daemon = True # Вернуть обратно после диагностики
            self.thread.start()
            logger.info(f"DNS server thread '{self.thread.name}' started.")
        else:
            logger.error("DNS Server object was not created. Thread not started.")


    def _run_server(self):
        """Метод для запуска в потоке с обработкой ошибок и циклом"""
        if not self.server:
            logger.error("DNS server instance is None, cannot run server thread.")
            return

        listen_ip = self.config['dns']['listen_ip']
        listen_port = self.config['dns']['listen_port']
        logger.info(f"DNS Server thread: Preparing to call server.start() on {listen_ip}:{listen_port}...")
        try:
            # ---> Лог ПЕРЕД вызовом <---
            logger.debug("DNS Server thread: Calling server.start() now...")

            self.server.start() # Этот вызов должен БЛОКИРОВАТЬ здесь

            # ---> Лог ПОСЛЕ вызова <---
            # Если мы видим это сообщение БЕЗ вызова stop(), значит start() не заблокировал поток!
            logger.warning("DNS Server thread: server.start() returned unexpectedly (should only happen after stop()).")

        except OSError as e:
            logger.exception(f"DNS Server thread: OSError during server.start() or listening on {listen_ip}:{listen_port}")
        except Exception as e:
            logger.exception("DNS Server thread: An unexpected error occurred during server execution (inside server.start()?)")
        finally:
            logger.info("DNS Server thread: Reached finally block.")
            if self.server and self.server.is_running():
                logger.warning("DNS Server thread: Server was still running in finally block, stopping it now.")
                try:
                    self.server.stop()
                except Exception as stop_err:
                    logger.exception("DNS Server thread: Error while trying to stop server in finally block.")
            logger.info(f"DNS Server thread finished for {listen_ip}:{listen_port}.")


    def stop(self):
        """Останавливает DNS сервер"""
        listen_ip = self.config['dns']['listen_ip']
        listen_port = self.config['dns']['listen_port']
        logger.info(f"Stop requested for DNS server on {listen_ip}:{listen_port}")

        if self.server and self.server.is_running():
            logger.info("DNS server is running, attempting to stop...")
            try:
                self.server.stop()
                logger.info("DNSServer stop() method called.")
            except Exception as e:
                logger.exception("Exception occurred while calling server.stop()")
        elif self.server:
            logger.info("DNS server object exists but is not running.")
        else:
            logger.info("DNS server object does not exist.")

        # Ждем завершения потока
        if self.thread and self.thread.is_alive():
            logger.info(f"Waiting for DNS server thread '{self.thread.name}' to join...")
            self.thread.join(timeout=5.0) # Ждем до 5 секунд
            if self.thread.is_alive():
                logger.warning(f"DNS server thread '{self.thread.name}' did not stop after 5 seconds.")
            else:
                logger.info(f"DNS server thread '{self.thread.name}' joined successfully.")
        elif self.thread:
            logger.info(f"DNS server thread '{self.thread.name}' was already finished.")

        logger.info(f"DNS server stop sequence completed for {listen_ip}:{listen_port}.")


# Функция-обертка остается прежней
def start_dns_server(config: dict) -> ThreadedDNSServer:
    server = ThreadedDNSServer(config)
    server.start()
    return server