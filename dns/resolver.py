from dnslib.server import BaseResolver
from dnslib import RR, A, QTYPE
from core.logic import get_ip_for_domain
from core.state import state
import time
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
            ip = get_ip_for_domain(qname)
            if ip:
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=10))

        return reply