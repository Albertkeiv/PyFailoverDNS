from api.models import ReportModel
from datetime import datetime, timezone

def test_report_model_valid():
    report = ReportModel(
        agent_id="agent1",
        timestamp=datetime.now(timezone.utc),
        check_name="webmail:1.2.3.4:80",
        domain="webmail.failover",
        type="tcp",
        target_ip="1.2.3.4",
        port=80,
        status="ok",
        latency_ms=23.4
    )
    assert report.agent_id == "agent1"
    assert report.status == "ok"