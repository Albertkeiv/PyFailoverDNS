from dnslib.server import BaseResolver
from dnslib import RR, A, QTYPE
from core.logic import get_dns_response
import logging

log = logging.getLogger("DNS")

class FailoverResolver(BaseResolver):
    def __init__(self, config):
        self.config = config

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]
        reply = request.reply()

        if qtype == "A":
            ip_list, ttl = get_dns_response(qname)
            for ip in ip_list:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl))
            log.debug(f"Resolved {qname} → {ip_list} (TTL={ttl})")

        return reply