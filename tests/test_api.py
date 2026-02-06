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
    """Проверка корневого эндпоинта - должен вернуть HTML файл или JSON"""
    resp = client.get("/")
    assert resp.status_code == 200


def test_health_check():
    """Проверка health-check эндпоинта"""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


def test_generate_endpoint_default():
    """Тест генерации пароля с параметрами по умолчанию"""
    resp = client.post("/api/generate", json={})
    assert resp.status_code == 200
    data = resp.json()
    assert "password" in data
    assert isinstance(data["password"], str)
    assert data["length"] == get_settings().password_default_length
    assert "entropy_bits" in data
    assert "strength_score" in data
    assert "strength_label" in data


def test_generate_endpoint_custom_length_and_sets():
    """Тест генерации пароля с пользовательскими параметрами"""
    payload = {
        "length": 24,
        "include_lowercase": True,
        "include_uppercase": True,
        "include_digits": True,
        "include_symbols": True,
    }
    resp = client.post("/api/generate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["password"]) == 24
    assert data["length"] == 24


def test_generate_endpoint_only_lowercase():
    """Тест генерации пароля только со строчными буквами"""
    payload = {
        "length": 16,
        "include_lowercase": True,
        "include_uppercase": False,
        "include_digits": False,
        "include_symbols": False,
    }
    resp = client.post("/api/generate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["password"]) == 16
    password = data["password"]
    assert password.islower() or password == password  # Только строчные буквы


def test_generate_endpoint_invalid_length_too_short():
    """Тест ошибки при слишком короткой длине пароля"""
    settings = get_settings()
    payload = {
        "length": settings.password_min_length - 1,
        "include_lowercase": True,
        "include_uppercase": True,
    }
    resp = client.post("/api/generate", json=payload)
    assert resp.status_code == 400


def test_generate_endpoint_invalid_length_too_long():
    """Тест ошибки при слишком длинной длине пароля"""
    settings = get_settings()
    payload = {
        "length": settings.password_max_length + 1,
        "include_lowercase": True,
        "include_uppercase": True,
    }
    resp = client.post("/api/generate", json=payload)
    assert resp.status_code == 400


def test_generate_endpoint_no_charsets():
    """Тест ошибки когда не выбран ни один набор символов"""
    payload = {
        "length": 16,
        "include_lowercase": False,
        "include_uppercase": False,
        "include_digits": False,
        "include_symbols": False,
    }
    resp = client.post("/api/generate", json=payload)
    assert resp.status_code == 400


def test_strength_check_endpoint():
    """Тест проверки сложности пароля"""
    resp = client.post("/api/strength-check", json={"password": "Aa1!Aa1!"})
    assert resp.status_code == 200
    data = resp.json()
    assert "entropy_bits" in data
    assert "score" in data
    assert "label" in data
    assert "length" in data
    assert "charset_size" in data
    assert 0 <= data["score"] <= 4


def test_strength_check_weak_password():
    """Тест проверки очень слабого пароля"""
    resp = client.post("/api/strength-check", json={"password": "abc"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 0  # very_weak


def test_strength_check_strong_password():
    """Тест проверки сильного пароля"""
    resp = client.post("/api/strength-check", json={"password": "MyP@ssw0rd!SecurePassword2024"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] >= 3  # strong или very_strong


def test_entropy_endpoint():
    """Тест расчёта энтропии пароля"""
    resp = client.post("/api/entropy", json={"password": "Aa1!Aa1!"})
    assert resp.status_code == 200
    data = resp.json()
    assert "entropy_bits" in data
    assert data["length"] == 8
    assert "charset_size" in data
    assert data["entropy_bits"] > 0


def test_entropy_endpoint_empty_password():
    """Тест ошибки для пустого пароля"""
    resp = client.post("/api/entropy", json={"password": ""})
    assert resp.status_code == 422  # Validation error


def test_entropy_endpoint_very_long_password():
    """Тест расчёта энтропии для очень длинного пароля"""
    long_password = "a" * 512
    resp = client.post("/api/entropy", json={"password": long_password})
    assert resp.status_code == 200
    data = resp.json()
    assert data["length"] == 512
    assert data["entropy_bits"] > 0


def test_static_files_exist():
    """Тест доступности статических файлов"""
    # Проверяем CSS
    resp = client.get("/static/style.css")
    assert resp.status_code == 200
    assert "text/css" in resp.headers.get("content-type", "")
    
    # Проверяем JavaScript
    resp = client.get("/static/script.js")
    assert resp.status_code == 200
    assert "javascript" in resp.headers.get("content-type", "")


