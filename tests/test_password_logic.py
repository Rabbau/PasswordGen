import re

from fastapi.testclient import TestClient

from main import (
    EntropyRequest,
    EntropyResponse,
    PasswordGenerateRequest,
    PasswordGenerateResponse,
    StrengthCheckRequest,
    StrengthCheckResponse,
    app,
    calculate_entropy_bits,
    classify_strength,
    detect_charset_size,
    generate_password,
    get_settings,
)


client = TestClient(app)


def test_generate_password_basic():
    settings = get_settings()
    req = PasswordGenerateRequest(length=20)
    resp = generate_password(req, settings)
    assert isinstance(resp, PasswordGenerateResponse)
    assert len(resp.password) == 20
    # Убеждаемся, что есть буквы и цифры по умолчанию
    assert any(c.islower() for c in resp.password)
    assert any(c.isupper() for c in resp.password)
    assert any(c.isdigit() for c in resp.password)


def test_generate_password_length_validation():
    settings = get_settings()
    req = PasswordGenerateRequest(length=settings.password_min_length - 1)
    from fastapi import HTTPException

    try:
        generate_password(req, settings)
    except HTTPException as exc:
        assert exc.status_code == 400
        assert "length must be between" in exc.detail
    else:
        assert False, "Expected HTTPException due to invalid length"


def test_detect_charset_size():
    assert detect_charset_size("aaaa") == 26
    assert detect_charset_size("AAAA") == 26
    assert detect_charset_size("1111") == 10
    size = detect_charset_size("Aa1!")
    # Должен включать все четыре множества
    assert size >= 26 + 26 + 10


def test_entropy_and_strength():
    entropy = calculate_entropy_bits(10, 62)
    assert entropy > 0
    score, label = classify_strength(entropy, 10)
    assert 0 <= score <= 4
    assert isinstance(label, str)


def test_entropy_request_response_models():
    body = EntropyRequest(password="Aa1!")
    resp = EntropyResponse(length=4, charset_size=62, entropy_bits=24.0)
    assert body.password == "Aa1!"
    assert resp.length == 4


def test_strength_request_response_models():
    body = StrengthCheckRequest(password="Aa1!")
    resp = StrengthCheckResponse(
        length=4, charset_size=62, entropy_bits=24.0, score=0, label="very_weak"
    )
    assert body.password == "Aa1!"
    assert resp.label == "very_weak"


