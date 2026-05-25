import sys
import os
import json
import pytest

# Ensure the parent directory is on the path so we can import app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "healthy"


def test_info(client):
    resp = client.get("/api/info")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["app"] == "jerney-api"
    assert "version" in data


def test_data(client):
    payload = {"key": "value", "number": 42}
    resp = client.post(
        "/api/data",
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["received"] == payload
