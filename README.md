## PasswordGen — REST API для генерации паролей

Это демонстрационное FastAPI‑приложение, показывающее:

- **Асинхронный REST API** на FastAPI
- **OpenAPI** (автодокументация по адресу `/docs` и `/redoc`)
- **Pydantic v2 и pydantic‑settings** для валидации и конфигурации через переменные окружения
- **Dependency Injection** (зависимости через `Depends`)
- **Безопасность**: CORS и **rate limiting** через `slowapi`

### Эндпоинты

- **POST `/generate`** — генерация криптографически стойкого пароля
- **POST `/strength-check`** — оценка сложности пароля
- **POST `/entropy`** — расчёт энтропии пароля

### Быстрый старт

1. **Создать и активировать виртуальное окружение (опционально)**

```bash
python -m venv env
env\Scripts\activate  # Windows
```

2. **Установить зависимости**

```bash
pip install -r requirements.txt
```

3. **Запустить приложение**

```bash
uvicorn main:app --reload
```

Приложение будет доступно по адресу `http://127.0.0.1:8000`.

- **Swagger UI**: `http://127.0.0.1:8000/docs`
- **ReDoc**: `http://127.0.0.1:8000/redoc`

### Конфигурация через переменные окружения

Используется `pydantic-settings`. Основные переменные:

- **`APP_NAME`** — имя приложения (по умолчанию: `"PasswordGen API"`)
- **`PASSWORD_MIN_LENGTH`** — минимальная длина генерируемого пароля (по умолчанию: `8`)
- **`PASSWORD_MAX_LENGTH`** — максимальная длина генерируемого пароля (по умолчанию: `128`)
- **`PASSWORD_DEFAULT_LENGTH`** — длина по умолчанию (по умолчанию: `16`)
- **`RATE_LIMIT`** — лимит запросов, формат `"<N>/minute"` (по умолчанию: `"30/minute"`)
- **`CORS_ORIGINS`** — список разрешённых origins через запятую, например: `"http://localhost:3000,https://myapp.com"`

Пример запуска с переменными окружения (PowerShell):

```bash
$env:RATE_LIMIT="10/minute"
$env:PASSWORD_DEFAULT_LENGTH="20"
uvicorn main:app --reload
```

### Тесты

Запуск тестов (используется `pytest`):

```bash
pytest
```

### Деплой (Render)

Выполнял через рендер с привязкой на репозиторий

Общий алгоритм:

- **Render**
  - Создал новый **Web Service**, указал репозиторий с кодом
  - Build command: `pip install -r requirements.txt`
  - Start command: `uvicorn main:app --host 0.0.0.0 --port 10000`


- **Продакшен URL**: 

- https://passwordgen-atoj.onrender.com
