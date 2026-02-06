## PasswordGen — REST API для генерации паролей

Это демонстрационное FastAPI‑приложение, показывающее:

- **Асинхронный REST API** на FastAPI
- **Веб-интерфейс** с демонстрацией всех возможностей (HTML5 + CSS3 + Vanilla JS)
- **OpenAPI** (автодокументация по адресу `/docs` и `/redoc`)
- **Pydantic v2 и pydantic‑settings** для валидации и конфигурации через переменные окружения
- **Dependency Injection** (зависимости через `Depends`)
- **Безопасность**: CORS и **rate limiting** через `slowapi`

### 🌟 Особенности

- ✅ **Криптостойкая генерация паролей** используя модуль `secrets` Python
- ✅ **Анализ сложности пароля** с визуализацией
- ✅ **Расчёт энтропии** и рекомендации по улучшению
- ✅ **Интерактивный веб-интерфейс** без зависимостей (чистый JavaScript)
- ✅ **Полностью типизированный Python код** (type hints)
- ✅ **Строгая валидация** данных через Pydantic
- ✅ **Rate limiting** для защиты от абуза
- ✅ **CORS поддержка** для кросс-доменных запросов

### 🚀 Быстрый старт

1. **Создать и активировать виртуальное окружение (опционально)**

```bash
python -m venv env
env\Scripts\activate  # Windows
source env/bin/activate  # Unix/MacOS
```

2. **Установить зависимости**

```bash
pip install -r requirements.txt
```

3. **Запустить приложение**

```bash
uvicorn main:app --reload
```

или просто:

```bash
python main.py
```

Приложение будет доступно по адресу `http://127.0.0.1:8000`.

### 📍 Доступные ресурсы

- **Главная страница / Демо-сайт**: `http://127.0.0.1:8000/` (веб-интерфейс)
- **Swagger UI (интерактивная документация)**: `http://127.0.0.1:8000/docs`
- **ReDoc (красивая документация)**: `http://127.0.0.1:8000/redoc`
- **Healthcheck**: `http://127.0.0.1:8000/health`

### 📚 API Эндпоинты

#### 1. **POST `/api/generate`** — Генерация пароля

Генерирует криптостойкий пароль с заданными параметрами.

**Пример запроса:**
```json
{
  "length": 20,
  "include_lowercase": true,
  "include_uppercase": true,
  "include_digits": true,
  "include_symbols": false
}
```

**Пример ответа:**
```json
{
  "password": "aBc123XyZ789qWeRtYuIo",
  "length": 20,
  "entropy_bits": 119.28,
  "strength_score": 4,
  "strength_label": "very_strong"
}
```

#### 2. **POST `/api/strength-check`** — Проверка сложности пароля

Анализирует введённый пароль и определяет его сложность.

**Пример запроса:**
```json
{
  "password": "MyPassword123!"
}
```

**Пример ответа:**
```json
{
  "length": 13,
  "charset_size": 94,
  "entropy_bits": 86.35,
  "score": 3,
  "label": "strong"
}
```

#### 3. **POST `/api/entropy`** — Расчёт энтропии

Вычисляет информационную энтропию пароля.

**Пример запроса:**
```json
{
  "password": "test123"
}
```

**Пример ответа:**
```json
{
  "length": 7,
  "charset_size": 36,
  "entropy_bits": 36.20
}
```

### ⚙️ Конфигурация через переменные окружения

Используется `pydantic-settings`. Основные переменные:

- **`APP_NAME`** — имя приложения (по умолчанию: `"PasswordGen API"`)
- **`PASSWORD_MIN_LENGTH`** — минимальная длина генерируемого пароля (по умолчанию: `8`)
- **`PASSWORD_MAX_LENGTH`** — максимальная длина генерируемого пароля (по умолчанию: `128`)
- **`PASSWORD_DEFAULT_LENGTH`** — длина по умолчанию (по умолчанию: `16`)
- **`RATE_LIMIT`** — лимит запросов, формат `"<N>/minute"` (по умолчанию: `"30/minute"`)
- **`CORS_ORIGINS`** — список разрешённых origins через запятую, например: `"http://localhost:3000,https://myapp.com"`

**Пример запуска с переменными окружения (PowerShell):**

```powershell
$env:RATE_LIMIT="10/minute"
$env:PASSWORD_DEFAULT_LENGTH="20"
$env:CORS_ORIGINS="http://localhost:3000,https://myapp.com"
uvicorn main:app --reload
```

**Пример запуска с переменными окружения (Bash):**

```bash
export RATE_LIMIT="10/minute"
export PASSWORD_DEFAULT_LENGTH="20"
uvicorn main:app --reload
```

### 🧪 Тесты

Запуск тестов (используется `pytest`):

```bash
pytest
```

Запуск тестов с подробным выводом:

```bash
pytest -v
```

### 🏗️ Структура проекта

```
PasswordGen/
├── main.py                 # Основное приложение FastAPI
├── requirements.txt        # Зависимости Python
├── README.md              # Этот файл
├── static/                # Статические файлы для веб-интерфейса
│   ├── index.html        # HTML-разметка демо-сайта
│   ├── style.css         # Стили (CSS3 с переменными)
│   └── script.js         # Логика интерфейса (Vanilla JS)
├── tests/                 # Тесты
│   ├── test_api.py       # Тесты API эндпоинтов
│   └── test_password_logic.py  # Тесты логики генерации
└── env/                   # Виртуальное окружение (создаётся при установке)
```

### 🌐 Деплой на Render

Приложение готово к деплою на Render:

1. Отправьте код в GitHub репозиторий
2. На Render создайте новый **Web Service**
3. Укажите:
   - **Build command**: `pip install -r requirements.txt`
   - **Start command**: `uvicorn main:app --host 0.0.0.0 --port 10000`

**Продакшен URL**: https://passwordgen-atoj.onrender.com

### 📖 Рефакторинг и улучшения

Код был полностью рефакторен для лучшей читаемости и поддерживаемости:

- ✅ Разделение кода на логические секции (конфиг, модели, бизнес-логика, эндпоинты)
- ✅ Использование type hints для всех функций и переменных
- ✅ Добавление подробной документации через docstrings
- ✅ Использование `lru_cache` для оптимизации настроек
- ✅ Правильная обработка ошибок с информативными сообщениями
- ✅ Криптостойкий Fisher-Yates shuffle для перемешивания пароля
- ✅ Гарантирование присутствия символов из каждого выбранного набора

### 🔒 Безопасность

- Используется модуль `secrets` для криптографически стойкой генерации
- Rate limiting защищает от DDoS-атак (по умолчанию 30 запросов/минуту)
- CORS настроен для контроля доступа между доменами
- Полная валидация входных данных через Pydantic
- Паролю не стоит логировать в логи приложения

### 📝 Лицензия

MIT
