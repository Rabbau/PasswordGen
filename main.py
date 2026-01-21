from __future__ import annotations

import math
import secrets
import string
from functools import lru_cache
from typing import Annotated, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address


class AppSettings(BaseSettings):
    """Конфигурация приложения через переменные окружения."""

    model_config = SettingsConfigDict(env_prefix="", extra="ignore")

    app_name: str = "PasswordGen API"

    password_min_length: int = 8
    password_max_length: int = 128
    password_default_length: int = 16

    # Формат лимита: "N/minute", "N/hour" и т.п. (поддерживается slowapi)
    rate_limit: str = "30/minute"

    # Разрешённые origins для CORS, через запятую
    cors_origins: str = ""

    @property
    def cors_origins_list(self) -> List[str]:
        if not self.cors_origins:
            return ["*"]
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> AppSettings:
    return AppSettings()


settings_dependency = Annotated[AppSettings, Depends(get_settings)]


class PasswordGenerateRequest(BaseModel):
    length: Optional[int] = Field(default=None, description="Длина пароля. Если не указана — используется значение по умолчанию.")
    include_lowercase: bool = Field(default=True, description="Включать строчные буквы a-z")
    include_uppercase: bool = Field(default=True, description="Включать заглавные буквы A-Z")
    include_digits: bool = Field(default=True, description="Включать цифры 0-9")
    include_symbols: bool = Field(default=False, description="Включать символы пунктуации")

    @field_validator("length")
    @classmethod
    def non_negative_length(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v <= 0:
            raise ValueError("length must be positive")
        return v

    @field_validator("include_lowercase", "include_uppercase", "include_digits", "include_symbols")
    @classmethod
    def at_least_one_charset(cls, v: bool, info):
        # Валидация в целом будет в методе validate_charsets; этот валидатор просто
        # оставлен для совместимости pydantic v2 (не используется напрямую).
        return v

    def validate_charsets(self) -> None:
        if not any(
            [
                self.include_lowercase,
                self.include_uppercase,
                self.include_digits,
                self.include_symbols,
            ]
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="At least one character set must be enabled.",
            )


class PasswordGenerateResponse(BaseModel):
    password: str
    length: int
    entropy_bits: float
    strength_score: int
    strength_label: str


class StrengthCheckRequest(BaseModel):
    password: str = Field(min_length=1, max_length=512)


class StrengthCheckResponse(BaseModel):
    length: int
    charset_size: int
    entropy_bits: float
    score: int = Field(ge=0, le=4)
    label: str


class EntropyRequest(BaseModel):
    password: str = Field(min_length=1, max_length=512, description="Пароль, для которого нужно посчитать энтропию.")


class EntropyResponse(BaseModel):
    length: int
    charset_size: int
    entropy_bits: float


def build_alphabet(req: PasswordGenerateRequest) -> str:
    alphabet = ""
    if req.include_lowercase:
        alphabet += string.ascii_lowercase
    if req.include_uppercase:
        alphabet += string.ascii_uppercase
    if req.include_digits:
        alphabet += string.digits
    if req.include_symbols:
        # Берём стандартный набор символов пунктуации
        alphabet += string.punctuation
    return alphabet


def generate_password(req: PasswordGenerateRequest, settings: AppSettings) -> PasswordGenerateResponse:
    req.validate_charsets()

    length = req.length or settings.password_default_length
    if length < settings.password_min_length or length > settings.password_max_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"length must be between {settings.password_min_length} and {settings.password_max_length}",
        )

    alphabet = build_alphabet(req)
    if not alphabet:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Alphabet is empty. Enable at least one character set.",
        )

    # Гарантируем, что в пароле будет хотя бы один символ из каждого выбранного множества
    mandatory_chars = []
    if req.include_lowercase:
        mandatory_chars.append(secrets.choice(string.ascii_lowercase))
    if req.include_uppercase:
        mandatory_chars.append(secrets.choice(string.ascii_uppercase))
    if req.include_digits:
        mandatory_chars.append(secrets.choice(string.digits))
    if req.include_symbols:
        mandatory_chars.append(secrets.choice(string.punctuation))

    if length < len(mandatory_chars):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"length must be at least {len(mandatory_chars)} to include all selected character sets",
        )

    remaining_length = length - len(mandatory_chars)
    password_chars = mandatory_chars + [secrets.choice(alphabet) for _ in range(remaining_length)]
    # Перемешиваем пароль криптостойким способом
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    password = "".join(password_chars)

    charset_size = len(set(alphabet))
    entropy_bits = calculate_entropy_bits(length, charset_size)
    score, label = classify_strength(entropy_bits, length)

    return PasswordGenerateResponse(
        password=password,
        length=length,
        entropy_bits=entropy_bits,
        strength_score=score,
        strength_label=label,
    )


def detect_charset_size(password: str) -> int:
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    size = 0
    if has_lower:
        size += len(string.ascii_lowercase)
    if has_upper:
        size += len(string.ascii_uppercase)
    if has_digit:
        size += len(string.digits)
    if has_symbol:
        size += len(string.punctuation)

    # fallback — если ничего не распознали, предполагаем как минимум 26 символов
    return size or 26


def calculate_entropy_bits(length: int, charset_size: int) -> float:
    return round(length * math.log2(charset_size), 2)


def classify_strength(entropy_bits: float, length: int) -> tuple[int, str]:
    """
    Очень приблизительная классификация.
    0 — очень слабый, 4 — очень сильный.
    """
    if entropy_bits < 28 or length < 6:
        return 0, "very_weak"
    if entropy_bits < 36:
        return 1, "weak"
    if entropy_bits < 60:
        return 2, "medium"
    if entropy_bits < 80:
        return 3, "strong"
    return 4, "very_strong"


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="PasswordGen API",
    description="REST API для генерации паролей, проверки сложности и расчёта энтропии.",
    version="1.0.0",
)

# Настройки загружаем один раз при инициализации приложения
_settings_for_app = get_settings()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings_for_app.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting error handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.get("/", tags=["meta"])
async def root(settings: settings_dependency):
    return {"app": settings.app_name, "message": "Password generation API is running."}


@limiter.limit(get_settings().rate_limit)
@app.post("/generate", response_model=PasswordGenerateResponse, tags=["password"])
async def generate_password_endpoint(
    request: Request,
    req: PasswordGenerateRequest,
    settings: settings_dependency,
):
    """
    Сгенерировать криптостойкий пароль с заданными параметрами.
    """
    # request нужен slowapi для определения клиента; не используется явно
    return generate_password(req, settings)


@limiter.limit(get_settings().rate_limit)
@app.post("/strength-check", response_model=StrengthCheckResponse, tags=["password"])
async def strength_check_endpoint(request: Request, body: StrengthCheckRequest):
    """
    Оценка сложности переданного пароля.
    """
    # request нужен slowapi для определения клиента; не используется явно
    password = body.password
    length = len(password)
    charset_size = detect_charset_size(password)
    entropy_bits = calculate_entropy_bits(length, charset_size)
    score, label = classify_strength(entropy_bits, length)

    return StrengthCheckResponse(
        length=length,
        charset_size=charset_size,
        entropy_bits=entropy_bits,
        score=score,
        label=label,
    )


@limiter.limit(get_settings().rate_limit)
@app.post("/entropy", response_model=EntropyResponse, tags=["password"])
async def entropy_endpoint(request: Request, body: EntropyRequest):
    """
    Посчитать энтропию пароля по его содержимому.
    """
    # request нужен slowapi для определения клиента; не используется явно
    password = body.password
    length = len(password)
    charset_size = detect_charset_size(password)
    entropy_bits = calculate_entropy_bits(length, charset_size)
    return EntropyResponse(
        length=length,
        charset_size=charset_size,
        entropy_bits=entropy_bits,
    )


@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """
    Пример middleware; можно расширить логированием и метриками.
    """
    response = await call_next(request)
    return response


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)


