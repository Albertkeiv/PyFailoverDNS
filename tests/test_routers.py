import pytest
from fastapi.testclient import TestClient
from api.routes import app
from core.state import state
from datetime import datetime, timezone

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_state():
    state["config"] = {
        "zones": [{
            "name": "failover",
            "domains": {
                "webmail.failover": {
                    "fallback": ["1.1.1.1"],
                    "server": {"timeout_sec": 60}
                }
            }
        }]
    }
    state["checks"] = {}

def test_post_report():
    payload = {
        "agent_id": "agent1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "check_name": "webmail.failover:1.2.3.4:80",
        "domain": "webmail.failover",
        "type": "tcp",
        "target_ip": "1.2.3.4",
        "port": 80,
        "status": "ok",
        "latency_ms": 12.3
    }
    response = client.post("/api/v1/report", json=payload)
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_get_tasks_no_tags():
    response = client.get("/api/v1/tasks")
    assert response.status_code == 422  # Required query param

def test_get_tasks_with_tags():
    def mock_extract_monitor_tasks(tags):
        return [{
            "domain": "webmail.failover",
            "check_name": "webmail.failover:127.0.0.1:80",
            "target_ip": "127.0.0.1",
            "port": 80,
            "type": "tcp",
            "timeout_sec": 10,
            "interval_sec": 30
        }]
    
    import api.routes
    original = api.routes.extract_monitor_tasks
    api.routes.extract_monitor_tasks = mock_extract_monitor_tasks

    response = client.get("/api/v1/tasks?tags=test")
    assert response.status_code == 200
    data = response.json()
    assert "tasks" in data
    assert data["tasks"][0]["domain"] == "webmail.failover"

    api.routes.extract_monitor_tasks = original  # восстановить

def test_get_status_summary():
    response = client.get("/api/v1/status")
    assert response.status_code == 200
    assert "status" in response.json()

def test_get_status_domain_not_found():
    response = client.get("/api/v1/status/nonexistent.failover")
    assert response.status_code == 404

def test_get_status_domain_found():
    domain = "webmail.failover"
    state["checks"][domain] = {
        "1.2.3.4": {
            "agent1": {
                "status": "ok",
                "timestamp": datetime.now(timezone.utc),
                "latency_ms": 20
            }
        }
    }

    response = client.get(f"/api/v1/status/{domain}")
    assert response.status_code == 200
    json = response.json()
    assert json["domain"] == domain
    assert "ip_checks" in json