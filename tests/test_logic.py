import pytest
from core import logic
from core.state import state
from datetime import datetime, timedelta, timezone

@pytest.fixture(autouse=True)
def setup_state():
    state["config"] = {
        "dns": {"resolve_cache_ttl": 5},
        "zones": [{
            "name": "failover",
            "domains": {
                "webmail.failover": {
                    "fallback": ["10.10.10.254"],
                    "server": {"timeout_sec": 60},
                    "monitor": {
                        "mode": "tcp",
                        "monitor_tag": "test",
                        "targets": [{"ip": "1.1.1.1", "port": 80}]
                    },
                    "agent": {
                        "timeout_sec": 10,
                        "interval_sec": 30
                    }
                }
            }
        }]
    }
    state["checks"] = {}
    state["resolved"] = {}

def test_update_status_and_get_ip():
    from api.models import ReportModel
    report = ReportModel(
        agent_id="agent1",
        timestamp=datetime.now(timezone.utc),
        check_name="webmail.failover:1.2.3.4:80",
        domain="webmail.failover",
        type="tcp",
        target_ip="1.2.3.4",
        port=80,
        status="ok",
        latency_ms=10.5
    )
    logic.update_status(report)

    ips = logic.get_ip_for_domain("webmail.failover")
    assert ips == ["1.2.3.4"]

def test_get_ip_cache_hit():
    now = datetime.now(timezone.utc)
    state["resolved"]["webmail.failover"] = {
        "ips": ["1.2.3.4"],
        "timestamp": now
    }
    ips = logic.get_ip_for_domain("webmail.failover")
    assert ips == ["1.2.3.4"]

def test_calculate_best_ip_ok():
    now = datetime.now(timezone.utc)
    state["checks"] = {
        "webmail.failover": {
            "1.1.1.1": {
                "agent1": {
                    "status": "ok",
                    "timestamp": now,
                    "latency_ms": 23.4
                }
            }
        }
    }
    best_ip = logic.calculate_best_ip("webmail.failover")
    assert best_ip == "1.1.1.1"

def test_calculate_best_ip_fallback():
    past = datetime.now(timezone.utc) - timedelta(seconds=120)
    state["checks"] = {
        "webmail.failover": {
            "1.1.1.1": {
                "agent1": {
                    "status": "ok",
                    "timestamp": past,
                    "latency_ms": 23.4
                }
            }
        }
    }
    best_ip = logic.calculate_best_ip("webmail.failover")
    assert best_ip == "10.10.10.254"

def test_get_fallback_list():
    fb = logic.get_fallback_list("webmail.failover")
    assert fb == ["10.10.10.254"]

def test_extract_monitor_tasks():
    tasks = logic.extract_monitor_tasks(["test"])
    assert len(tasks) == 1
    task = tasks[0]
    assert task["domain"] == "webmail.failover"
    assert task["target_ip"] == "1.1.1.1"
    assert task["port"] == 80
    assert task["type"] == "tcp"

def test_expired_check_does_not_count():
    past = datetime.now(timezone.utc) - timedelta(seconds=300)
    state["checks"] = {
        "webmail.failover": {
            "1.2.3.4": {
                "agent1": {
                    "status": "ok",
                    "timestamp": past,
                    "latency_ms": 15
                }
            }
        }
    }

    ips = logic.get_alive_ips("webmail.failover")
    assert ips == ["10.10.10.254"]  # fallback

def test_failed_status_does_not_count():
    now = datetime.now(timezone.utc)
    state["checks"] = {
        "webmail.failover": {
            "1.2.3.4": {
                "agent1": {
                    "status": "fail",
                    "timestamp": now,
                    "latency_ms": None
                }
            }
        }
    }

    ips = logic.get_alive_ips("webmail.failover")
    assert ips == ["10.10.10.254"]  # fallback

def test_weird_status_fallbacks():
    now = datetime.now(timezone.utc)
    state["checks"] = {
        "webmail.failover": {
            "1.2.3.4": {
                "agentX": {
                    "status": "banana",
                    "timestamp": now,
                    "latency_ms": None
                }
            }
        }
    }

    ip = logic.calculate_best_ip("webmail.failover")
    assert ip == "10.10.10.254"

def test_no_fallback_returns_localhost():
    state["config"]["zones"][0]["domains"]["webmail.failover"]["fallback"] = []

    state["checks"] = {}  # Пусто
    ip = logic.calculate_best_ip("webmail.failover")
    assert ip == "127.0.0.1"