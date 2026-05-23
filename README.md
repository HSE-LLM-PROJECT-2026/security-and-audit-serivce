# Security and Audit Service

[HSE-LLM-PROJECT-2026/security-and-audit-serivce](https://github.com/HSE-LLM-PROJECT-2026/security-and-audit-serivce)

## Описание

FastAPI-сервис для аутентификации, RBAC, управления пользователями, командами, ролями и audit log. Название папки `security-and-audit-serivce` оставлено как есть, потому что так репозиторий уже используется в инфраструктуре.

## Основные возможности

- регистрация и логин пользователей
- выпуск access/refresh JWT
- проверка bearer token для других сервисов
- управление пользователями, командами и ролями
- whitelist моделей для пользователей
- service accounts и API-key доступ
- запись и просмотр audit events
- demo seed пользователей для стенда

## Основные API-ручки

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/verify`
- `GET /users`
- `GET /teams`
- `GET /project/roles`
- `GET /audit`
- `POST /audit/events`
- `GET /health`, `GET /livez`

## Структура проекта

- `app/main.py` — FastAPI API
- `app/database.py` — работа с PostgreSQL
- `app/auth.py` — пароли, JWT, API keys
- `app/rbac.py` — роли и permissions
- `app/models.py` — Pydantic-схемы
- `tests/` — тесты auth/RBAC/demo seed
- `deploy/` — скрипты деплоя
- `k8s/` — базовые Kubernetes-манифесты

## Быстрый старт локально

```bash
uv sync --frozen --extra dev
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Проверка тестов:

```bash
uv run pytest -q
```

## Переменные окружения

- `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD` — PostgreSQL
- `JWT_SECRET`, `JWT_ALGORITHM` — подпись токенов
- `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME`, `ADMIN_TEAM` — seed admin
- `DEMO_USERS_ENABLED`, `DEMO_USERS_PASSWORD` — demo-пользователи
- `CORS_ORIGINS` — CORS

Пример лежит в `.env.example`.

## Docker

```bash
docker build -t awesomecosmonaut/security-audit-service:latest .
docker run --env-file .env -p 8000:8000 awesomecosmonaut/security-audit-service:latest
```

## Деплой

```bash
cd deploy
./deploy-from-scratch.sh
```

Полная пересборка и переустановка:

```bash
cd deploy
./rebuild-delete-deploy.sh
```

## Автор

Igor Malysh
