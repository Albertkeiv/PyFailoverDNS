from dnslib.server import BaseResolver
from dnslib import RR, A, QTYPE
from core.logic import get_ip_for_domain, get_ttl_for_domain
import logging

log = logging.getLogger("DNS")

_rr_counters = {}

class FailoverResolver(BaseResolver):
    def __init__(self, config):
        self.config = config

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]

        reply = request.reply()

        if qtype == "A":
            ip_list = get_ip_for_domain(qname)
            ttl = get_ttl_for_domain(qname)

            if ip_list:
                idx = _rr_counters.setdefault(qname, 0)
                rotated = ip_list[idx:] + ip_list[:idx]
                _rr_counters[qname] = (idx + 1) % len(ip_list)

                for ip in rotated:
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl))
                    log.debug(f"Resolved {qname} → {ip} (TTL={ttl}) [round-robin]")

        return reply



