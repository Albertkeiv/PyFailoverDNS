import pytest
from core import logic
from core.state import state
from datetime import datetime, timedelta, timezone
from api.models import ReportModel

@pytest.fixture
def domain_info():
    domain = list(state["config"]["zones"][0]["domains"].keys())[0]
    cfg = state["config"]["zones"][0]["domains"][domain]
    targets = cfg["monitor"]["targets"]
    fallback = cfg.get("fallback", [])
    return domain, targets, fallback

def test_update_status_and_get_ip(domain_info):
    domain, targets, _ = domain_info
    now = datetime.now(timezone.utc)

    report = ReportModel(
        agent_id="agent1",
        timestamp=now,
        check_name=f"{domain}:{targets[0]['ip']}:{targets[0]['port']}",
        domain=domain,
        type="tcp",
        target_ip=targets[0]["ip"],
        port=targets[0]["port"],
        status="ok",
        latency_ms=10.5
    )

    logic.update_status(report)
    ips = logic.get_ip_for_domain(domain)
    assert targets[0]["ip"] in ips

def test_get_ip_cache_hit(domain_info):
    domain, targets, _ = domain_info
    now = datetime.now(timezone.utc)
    state["resolved"][domain] = {
        "ips": [targets[0]["ip"]],
        "timestamp": now
    }
    ips = logic.get_ip_for_domain(domain)
    assert ips == [targets[0]["ip"]]

def test_calculate_best_ip_ok(domain_info):
    domain, targets, _ = domain_info
    now = datetime.now(timezone.utc)
    state["checks"][domain] = {
        targets[0]["ip"]: {
            "agent1": {
                "status": "ok",
                "timestamp": now,
                "latency_ms": 23.4
            }
        }
    }

    best_ip = logic.calculate_best_ip(domain)
    assert best_ip == targets[0]["ip"]

def test_calculate_best_ip_fallback(domain_info):
    domain, targets, fallback = domain_info
    past = datetime.now(timezone.utc) - timedelta(seconds=300)
    state["checks"][domain] = {
        targets[0]["ip"]: {
            "agent1": {
                "status": "ok",
                "timestamp": past,
                "latency_ms": 23.4
            }
        }
    }

    best_ip = logic.calculate_best_ip(domain)
    assert best_ip == fallback[0]

def test_get_fallback_list(domain_info):
    domain, _, fallback = domain_info
    fb = logic.get_fallback_list(domain)
    assert fb == fallback

def test_extract_monitor_tasks(domain_info):
    tasks = logic.extract_monitor_tasks(["test"])
    assert tasks
    task = tasks[0]
    assert "domain" in task
    assert "target_ip" in task
    assert "port" in task
    assert "type" in task

def test_expired_check_does_not_count(domain_info):
    domain, targets, fallback = domain_info
    past = datetime.now(timezone.utc) - timedelta(seconds=300)
    state["checks"][domain] = {
        targets[0]["ip"]: {
            "agent1": {
                "status": "ok",
                "timestamp": past,
                "latency_ms": 15
            }
        }
    }

    ips = logic.get_alive_ips(domain)
    assert ips == fallback

def test_failed_status_does_not_count(domain_info):
    domain, targets, fallback = domain_info
    now = datetime.now(timezone.utc)
    state["checks"][domain] = {
        targets[0]["ip"]: {
            "agent1": {
                "status": "fail",
                "timestamp": now,
                "latency_ms": None
            }
        }
    }

    ips = logic.get_alive_ips(domain)
    assert ips == fallback

def test_weird_status_fallbacks(domain_info):
    domain, targets, fallback = domain_info
    now = datetime.now(timezone.utc)
    state["checks"][domain] = {
        targets[0]["ip"]: {
            "agentX": {
                "status": "banana",
                "timestamp": now,
                "latency_ms": None
            }
        }
    }

    ip = logic.calculate_best_ip(domain)
    assert ip == fallback[0]

def test_no_fallback_returns_localhost(domain_info):
    domain, _, _ = domain_info
    state["config"]["zones"][0]["domains"][domain]["fallback"] = []
    state["checks"] = {}

    ip = logic.calculate_best_ip(domain)
    assert ip == "127.0.0.1"