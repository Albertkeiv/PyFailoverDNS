import pytest
from fastapi.testclient import TestClient
from api.routes import app
from core.state import state
from datetime import datetime, timezone

client = TestClient(app)

@pytest.fixture
def domain_info():
    domain = list(state["config"]["zones"][0]["domains"].keys())[0]
    cfg = state["config"]["zones"][0]["domains"][domain]
    fallback = cfg.get("fallback", [])
    return domain, fallback

def test_post_report(domain_info):
    domain, _ = domain_info
    target = state["config"]["zones"][0]["domains"][domain]["monitor"]["targets"][0]

    payload = {
        "agent_id": "agent1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "check_name": f"{domain}:{target['ip']}:{target['port']}",
        "domain": domain,
        "type": "tcp",
        "target_ip": target["ip"],
        "port": target["port"],
        "status": "ok",
        "latency_ms": 12.3
    }

    token = state["config"]["zones"][0]["domains"][domain]["agent"]["token"]

    response = client.post("/api/v1/report", json=payload, headers={"X-API-Key": token})
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_get_tasks_no_tags():
    response = client.get("/api/v1/tasks")
    assert response.status_code == 422  # Required query param

def test_get_tasks_with_tags(domain_info):
    domain, _ = domain_info
    token = state["config"]["zones"][0]["domains"][domain]["agent"]["token"]

    response = client.get("/api/v1/tasks?tags=test", headers={"X-API-Key": token})
    assert response.status_code == 200
    data = response.json()
    assert "tasks" in data
    assert any(task["domain"] == domain for task in data["tasks"])

def test_get_status_summary():
    response = client.get("/api/v1/status")
    assert response.status_code == 200
    assert "status" in response.json()

def test_get_status_domain_not_found():
    response = client.get("/api/v1/status/nonexistent.failover")
    assert response.status_code == 404

def test_get_status_domain_found(domain_info):
    domain, _ = domain_info
    target = state["config"]["zones"][0]["domains"][domain]["monitor"]["targets"][0]

    state["checks"][domain] = {
        target["ip"]: {
            "agent1": {
                "status": "ok",
                "timestamp": datetime.now(timezone.utc),
                "latency_ms": 20
            }
        }
    }

    response = client.get(f"/api/v1/status/{domain}")
    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == domain
    assert "ip_checks" in data

def test_post_report_invalid_token(domain_info):
    domain, _ = domain_info
    target = state["config"]["zones"][0]["domains"][domain]["monitor"]["targets"][0]

    payload = {
        "agent_id": "agent1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "check_name": f"{domain}:{target['ip']}:{target['port']}",
        "domain": domain,
        "type": "tcp",
        "target_ip": target["ip"],
        "port": target["port"],
        "status": "ok",
        "latency_ms": 12.3
    }

    response = client.post("/api/v1/report", json=payload, headers={"X-API-Key": "WRONG"})
    assert response.status_code == 403