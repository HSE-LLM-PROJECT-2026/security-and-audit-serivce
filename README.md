# Security And Audit Service

## Описание

Сервис аутентификации, RBAC и аудита для платформы. Обрабатывает логин/refresh/verify, управление пользователями и ролями, а также запись audit-событий.

## Основные возможности

- JWT-аутентификация и refresh flow
- управление пользователями, командами и ролями
- выдача и проверка service account/API token
- immutable audit log и API чтения аудита

## Структура проекта

- `app/` - основной код FastAPI-сервиса
- `tests/` - unit/integration тесты
- `k8s/` - базовые kubernetes-манифесты
- `deploy/` - скрипты и helm-файлы деплоя
- `pyproject.toml`, `requirements*.txt`, `Dockerfile`

## Быстрый старт (локально)

1. Установить зависимости:
   `uv sync --frozen --extra dev`
2. Запустить сервис:
   `uv run uvicorn app.main:app --host 0.0.0.0 --port 8000`
3. Запустить тесты:
   `uv run pytest -q`

## Переменные окружения

- `POSTGRES_*` - параметры PostgreSQL
- `JWT_SECRET`, `JWT_ALGORITHM`, `JWT_EXPIRATION_MINUTES`
- `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME`, `ADMIN_TEAM`
- `DEMO_USERS_ENABLED`, `DEMO_USERS_PASSWORD`

## Docker

- Сборка: `docker build -t security-and-audit-service:local .`
- Запуск: `docker run --rm -p 8000:8000 --env-file .env security-and-audit-service:local`

## Деплой

- основные скрипты: `deploy/deploy-from-scratch.sh`, `deploy/rebuild-delete-deploy.sh`
- helm-описание: `deploy/helm/security-audit-service/`
