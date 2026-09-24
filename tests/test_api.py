"""
test_api.py
Integration tests for FastAPI REST API endpoints.
"""

from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)


def test_api_root():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert "version" in data


def test_api_metrics():
    response = client.get("/api/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "high" in data


def test_api_brands():
    response = client.get("/api/brands")
    assert response.status_code == 200
    data = response.json()
    assert "brands" in data
    assert len(data["brands"]) > 0


def test_api_candidates_list():
    response = client.get("/api/candidates")
    assert response.status_code == 200
    data = response.json()
    assert "candidates" in data
    assert "count" in data


def test_api_status_update():
    # Fetch first candidate
    cand_resp = client.get("/api/candidates")
    candidates = cand_resp.json().get("candidates", [])
    if candidates:
        first_id = candidates[0]["id"]
        update_resp = client.patch(
            f"/api/candidates/{first_id}/status",
            json={"status": "investigating", "analyst_notes": "API test note"}
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["new_status"] == "investigating"
