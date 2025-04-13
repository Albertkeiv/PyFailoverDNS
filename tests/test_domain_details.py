from core.logic import get_domain_status, get_domain_details
from core.state import state
from datetime import datetime, timezone

def test_get_domain_status_not_empty():
    results = get_domain_status()
    assert isinstance(results, list)
    assert len(results) > 0
    for item in results:
        assert "domain" in item
        assert "agents" in item

def test_get_domain_details_keys():
    domain = list(state["config"]["zones"][0]["domains"].keys())[0]
    result = get_domain_details(domain)
    assert "domain" in result
    assert "ip_checks" in result
    assert isinstance(result["ip_checks"], dict)