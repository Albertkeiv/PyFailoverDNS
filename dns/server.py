from dnslib.server import DNSServer
from dns.resolver import FailoverResolver

def start_dns_server(config):
    resolver = FailoverResolver(config)
    server = DNSServer(resolver, port=config["dns"]["listen_port"], address=config["dns"]["listen_ip"])
    server.start_thread()
    return server