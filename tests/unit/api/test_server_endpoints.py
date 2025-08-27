import base64
import json
import pytest

try:
    from fastapi.testclient import TestClient
    from dragonslayer.api.server import create_app
    FASTAPI_AVAILABLE = True
except Exception:
    FASTAPI_AVAILABLE = False


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not available")
def test_health_and_status_basic():
    app = create_app()
    client = TestClient(app)

    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data.get("status") in {"healthy", "active"}
    assert "uptime_seconds" in data

    s = client.get("/status")
    assert s.status_code == 200
    sd = s.json()
    assert sd["status"] in {"active"}
    assert isinstance(sd["active_analyses"], int)
    assert isinstance(sd["total_analyses"], int)


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not available")
def test_analysis_types():
    app = create_app()
    client = TestClient(app)

    r = client.get("/analysis-types")
    assert r.status_code == 200
    data = r.json()
    assert "analysis_types" in data
    assert isinstance(data["analysis_types"], list)
    assert "workflow_strategies" in data


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not available")
def test_analyze_minimal_roundtrip(monkeypatch):
    app = create_app()
    client = TestClient(app)

    # Use small payload
    sample = b"hello world"
    payload = {
        "sample_data": base64.b64encode(sample).decode(),
        "analysis_type": "hybrid"
    }

    # If core API performs heavy work, stub a minimal fast result
    from dragonslayer.core.api import VMDragonSlayerAPI

    async def fake_analyze_binary_data_async(self, binary_data, analysis_type, metadata=None, **options):
        md = metadata or {}
        class R:
            request_id = "req-1"
            success = True
            results = {"echo_size": len(binary_data)}
            errors = []
            warnings = []
            execution_time = 0.01
            metadata = md
        return R()

    monkeypatch.setattr(VMDragonSlayerAPI, "analyze_binary_data_async", fake_analyze_binary_data_async)

    r = client.post("/analyze", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["request_id"] == "req-1"
    assert data["success"] is True
    assert data["results"]["echo_size"] == len(sample)


@pytest.mark.skipif(not FASTAPI_AVAILABLE, reason="FastAPI not available")
def test_metrics_shape(monkeypatch):
    app = create_app()
    client = TestClient(app)

    from dragonslayer.core.api import VMDragonSlayerAPI

    def fake_get_metrics(self):
        return {"cpu": 10, "mem": 20}

    monkeypatch.setattr(VMDragonSlayerAPI, "get_metrics", fake_get_metrics)

    r = client.get("/metrics")
    assert r.status_code == 200
    data = r.json()
    assert data["cpu"] == 10 and data["mem"] == 20
    assert "api_total_analyses" in data
    assert "api_active_analyses" in data
    assert "api_uptime_seconds" in data
