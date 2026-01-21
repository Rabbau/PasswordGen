from fastapi.testclient import TestClient
import sys
from pathlib import Path

# Добавляем корень проекта в PYTHONPATH, чтобы можно было импортировать main
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from main import app, get_settings


client = TestClient(app)


def test_root_ok():
    resp = client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert "app" in data
    assert "message" in data


def test_generate_endpoint_default():
    resp = client.post("/generate", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert "password" in data
    assert isinstance(data["password"], str)
    assert data["length"] == get_settings().password_default_length


def test_generate_endpoint_custom_length_and_sets():
    payload = {
        "length": 24,
        "include_lowercase": True,
        "include_uppercase": True,
        "include_digits": True,
        "include_symbols": True,
    }
    resp = client.post("/generate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["password"]) == 24


def test_generate_endpoint_invalid_length():
    settings = get_settings()
    payload = {"length": settings.password_min_length - 1}
    resp = client.post("/generate", json=payload)
    assert resp.status_code == 400


def test_strength_check_endpoint():
    resp = client.post("/strength-check", json={"password": "Aa1!Aa1!"})
    assert resp.status_code == 200
    data = resp.json()
    assert "entropy_bits" in data
    assert "score" in data


def test_entropy_endpoint():
    resp = client.post("/entropy", json={"password": "Aa1!Aa1!"})
    assert resp.status_code == 200
    data = resp.json()
    assert "entropy_bits" in data
    assert data["length"] == 8


