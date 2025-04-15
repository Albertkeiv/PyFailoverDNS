import pytest
from fastapi.testclient import TestClient
from api.routes import app
from core.state import state, state_lock, atomic_state_update
from datetime import datetime, timezone
import json

client = TestClient(app)

@pytest.fixture
def domain_info():
    with state_lock:
        domain = list(state["config"]["zones"][0]["domains"].keys())[0]
        cfg = state["config"]["zones"][0]["domains"][domain]
        fallback = cfg.get("fallback", [])
        return domain, fallback

def test_post_report(domain_info):
    domain, _ = domain_info
    with state_lock:
        target = state["config"]["zones"][0]["domains"][domain]["monitor"]["targets"][0]
        token = state["config"]["zones"][0]["domains"][domain]["agent"]["token"]

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

    response = client.post(
        "/api/v1/report",
        json=payload,
        headers={"X-API-Key": token}
    )
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_get_tasks_no_tags():
    response = client.get("/api/v1/tasks")
    assert response.status_code == 422  # Missing required query param

def test_get_tasks_with_tags(domain_info):
    domain, _ = domain_info
    with state_lock:
        token = state["config"]["zones"][0]["domains"][domain]["agent"]["token"]

    response = client.get(
        "/api/v1/tasks?tags=test",
        headers={"X-API-Key": token}
    )
    assert response.status_code == 200
    data = response.json()
    assert "tasks" in data
    assert isinstance(data["tasks"], list)
    assert any(task["domain"] == domain for task in data["tasks"])

def test_get_status_summary():
    response = client.get("/api/v1/status")
    assert response.status_code == 200
    assert "status" in response.json()
    assert isinstance(response.json()["status"], list)

def test_get_status_domain_not_found():
    response = client.get("/api/v1/status/nonexistent.failover")
    assert response.status_code == 404
    assert json.loads(response.content) == {"detail": "Domain not found"}

def test_get_status_domain_found(domain_info):
    domain, _ = domain_info
    with state_lock:
        target = state["config"]["zones"][0]["domains"][domain]["monitor"]["targets"][0]
        
        def update_state(s):
            s["checks"][domain] = {
                target["ip"]: {
                    "agent1": {
                        "status": "ok",
                        "timestamp": datetime.now(timezone.utc),
                        "latency_ms": 20
                    }
                }
            }
        atomic_state_update(update_state)

    response = client.get(f"/api/v1/status/{domain}")
    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == domain
    assert "ip_checks" in data
    assert target["ip"] in data["ip_checks"]

def test_post_report_invalid_token(domain_info):
    domain, _ = domain_info
    with state_lock:
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

    response = client.post(
        "/api/v1/report", 
        json=payload, 
        headers={"X-API-Key": "WRONG"}
    )
    assert response.status_code == 403
    assert json.loads(response.content) == {"detail": "Invalid API key"}

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "timestamp" in data
    assert "components" in data