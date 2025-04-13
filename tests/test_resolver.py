import pytest
from dnslib import DNSRecord
from dns.resolver import FailoverResolver
from core.state import state
from datetime import datetime, timezone


def make_dns_request(domain: str):
    return DNSRecord.question(domain, qtype="A")


@pytest.fixture
def priority_domain():
    domain = list(state["config"]["zones"][0]["domains"].keys())[0]
    cfg = state["config"]["zones"][0]["domains"][domain]

    # Переключаем на политику priority и добавляем приоритеты явно
    cfg["server"]["policy"] = "priority"
    cfg["monitor"]["targets"] = [
        {"ip": "9.9.9.9", "port": 80, "priority": 5},
        {"ip": "8.8.8.8", "port": 80, "priority": 1},
        {"ip": "7.7.7.7", "port": 80, "priority": 3},
    ]
    return domain, cfg["monitor"]["targets"]


def test_priority_policy_returns_single_best(priority_domain):
    domain, targets = priority_domain
    now = datetime.now(timezone.utc)

    state["resolved"] = {}  # Сброс кэша
    state["checks"][domain] = {
        t["ip"]: {
            "agent1": {
                "status": "ok",
                "timestamp": now,
                "latency_ms": 12.3
            }
        } for t in targets
    }

    resolver = FailoverResolver(config={})
    request = make_dns_request(domain)
    response = resolver.resolve(request, None)

    # Должен быть только один IP — с наивысшим приоритетом
    assert len(response.rr) == 1
    assert str(response.rr[0].rdata) == "8.8.8.8"


def test_priority_policy_fallback(priority_domain):
    domain, targets = priority_domain
    cfg = state["config"]["zones"][0]["domains"][domain]
    cfg["fallback"] = ["127.0.0.1"]
    fallback = cfg["fallback"]

    past = datetime.now(timezone.utc)
    state["resolved"] = {}
    state["checks"][domain] = {
        t["ip"]: {
            "agent1": {
                "status": "fail",
                "timestamp": past,
                "latency_ms": None
            }
        } for t in targets
    }

    resolver = FailoverResolver(config={})
    request = make_dns_request(domain)
    response = resolver.resolve(request, None)

    assert len(response.rr) == len(fallback)
    for rr in response.rr:
        assert str(rr.rdata) in fallback