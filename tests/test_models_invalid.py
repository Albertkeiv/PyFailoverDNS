import pytest
from api.models import ReportModel
from datetime import datetime, timezone

def test_missing_fields_raises_error():
    with pytest.raises(Exception):
        ReportModel(
            agent_id="a1", timestamp=datetime.now(timezone.utc), domain="x", type="tcp", target_ip="1.2.3.4", status="ok"
        )

def test_invalid_status():
    with pytest.raises(Exception):
        ReportModel(
            agent_id="a1",
            timestamp=datetime.now(timezone.utc),
            check_name="x:1.2.3.4:80",
            domain="x",
            type="tcp",
            target_ip="1.2.3.4",
            port=80,
            status="banana",  # некорректный статус
            latency_ms=12.3
        )