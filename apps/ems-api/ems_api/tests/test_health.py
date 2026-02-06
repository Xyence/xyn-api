from fastapi.testclient import TestClient
from ems_api.main import app


def test_health_placeholder():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
