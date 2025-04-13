from dnslib.server import BaseResolver
from dnslib import RR, A, QTYPE
from core.logic import (
    get_ip_for_domain,
    get_ttl_for_domain,
    get_domain_config,
    using_fallback,
    is_priority_mode
)
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

            domain_cfg = get_domain_config(qname)
            policy = domain_cfg.get("server", {}).get("policy", "any")
            is_fallback = using_fallback(ip_list, qname)
            priority_mode = is_priority_mode(domain_cfg)

            if ip_list:
                if policy == "priority" and priority_mode and not is_fallback:
                    ip = ip_list[0]
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl))
                    log.debug(f"Resolved {qname} → {ip} (TTL={ttl}) [priority mode]")
                else:
                    idx = _rr_counters.setdefault(qname, 0)
                    rotated = ip_list[idx:] + ip_list[:idx]
                    _rr_counters[qname] = (idx + 1) % len(ip_list)
                    for ip in rotated:
                        reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl))
                    log.debug(f"Resolved {qname} → {rotated} (TTL={ttl}) [round-robin or fallback]")

        return reply