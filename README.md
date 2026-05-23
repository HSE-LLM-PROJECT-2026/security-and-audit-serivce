# Security and Audit Service

## Описание

Этот репозиторий содержит сервис аутентификации, RBAC и аудита. Он выпускает JWT, хранит пользователей, команды, роли, технические токены и audit log для действий платформы.

## Основные возможности
- регистрация и логин пользователей
- выпуск access/refresh JWT
- проверка bearer token для других сервисов
- управление пользователями, командами и ролями
- whitelist моделей для пользователей
- запись и просмотр audit events

## Структура проекта

- `app/` — основной код приложения
  - `main.py` — FastAPI-приложение и HTTP-ручки
  - `config.py` — настройки сервиса
  - `auth.py` — JWT, пароли и service tokens
  - `database.py` — работа с PostgreSQL
  - `models.py` — Pydantic-схемы
  - `rbac.py` — роли и наборы прав

- `deploy/` — файлы и переменные для развертывания
- `.env.example` — пример переменных окружения
- `Dockerfile` — сборка Docker-образа
- `pyproject.toml` — зависимости и настройки Python-проекта
- `requirements.txt` — список зависимостей для совместимого запуска без uv

## Быстрый старт локально

1. Установите зависимости:
   ```bash
   uv sync
   ```

2. Создайте `.env` на основе `.env.example`:
   ```bash
   cp .env.example .env
   ```

3. Запустите сервис:
   ```bash
   uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

Если `uv` не используется, можно запустить через обычный virtualenv:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## Переменные окружения
- `DATABASE_URL`
- `JWT_SECRET`
- `JWT_ACCESS_TTL_MINUTES`
- `JWT_REFRESH_TTL_DAYS`
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `ADMIN_NAME`
- `DEMO_USERS_ENABLED`
- `LOG_LEVEL`

Пример `.env`:

```env
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/llm_platform
SERVICE_TOKEN=change-me
LOG_LEVEL=INFO
```

## Основные API-ручки

| Метод | Ручка | Назначение |
|--------|-------|------------|
| `POST` | `/auth/register` | Создает пользователя и возвращает его профиль. |
| `POST` | `/auth/login` | Проверяет логин и пароль, выпускает access и refresh token. |
| `POST` | `/auth/refresh` | Обновляет access token по refresh token. |
| `POST` | `/auth/verify` | Проверяет bearer token или service token и возвращает principal. |
| `GET` | `/users` | Возвращает список пользователей платформы. |
| `GET` | `/users/{user_id}` | Возвращает профиль конкретного пользователя. |
| `PATCH` | `/users/{user_id}/role` | Меняет платформенную роль пользователя. |
| `PATCH` | `/users/{user_id}/team` | Обновляет основную команду пользователя. |
| `DELETE` | `/users/{user_id}` | Удаляет пользователя. |
| `POST` | `/users/service-account` | Создает техническую учетную запись для программного доступа. |
| `GET` | `/teams` | Возвращает список команд. |
| `POST` | `/teams` | Создает команду и базовые роли внутри нее. |
| `GET` | `/teams/{team_name}/roles` | Возвращает роли конкретной команды. |
| `PUT` | `/teams/{team_name}/roles/{role_name}` | Создает или обновляет роль команды и набор permissions. |
| `DELETE` | `/teams/{team_name}/roles/{role_name}` | Удаляет роль команды. |
| `GET` | `/users/{user_id}/team-roles` | Возвращает членство пользователя в командах и роли внутри них. |
| `PUT` | `/users/{user_id}/team-roles` | Назначает пользователю роли в командах. |
| `GET` | `/project/roles` | Возвращает платформенные роли. |
| `PUT` | `/project/roles/{role_name}` | Создает или обновляет платформенную роль. |
| `DELETE` | `/project/roles/{role_name}` | Удаляет платформенную роль. |
| `GET` | `/users/{user_id}/project-roles` | Возвращает платформенные роли пользователя. |
| `PUT` | `/users/{user_id}/project-roles` | Назначает пользователю платформенные роли. |
| `GET` | `/users/{user_id}/allowed-models` | Возвращает whitelist моделей пользователя. |
| `PUT` | `/users/{user_id}/allowed-models` | Обновляет whitelist моделей пользователя. |
| `POST` | `/audit/events` | Записывает audit event по управленческому или inference-действию. |
| `GET` | `/audit` | Возвращает журнал аудита с фильтрами по пользователю, действию и времени. |
| `GET` | `/health` | Проверяет доступность security/audit service. |
| `GET` | `/livez` | Liveness probe контейнера. |

## Сборка и запуск в Docker

```bash
docker build -t hse-llm-project-2026/security-and-audit-serivce:local .
docker run --env-file .env -p 8000:8000 hse-llm-project-2026/security-and-audit-serivce:local
```

## Деплой в Kubernetes

Файлы развертывания лежат в папке `deploy/`. Для сервисов, которые уже подключены к стенду, используются Helm values и deploy-скрипты из соответствующего репозитория или общего инфраструктурного пайплайна.

## Метрики и документация

- Swagger UI: `/docs`
- OpenAPI: `/openapi.json`
- Health check: `/health`
- Liveness check: `/livez`

## Автор

Igor Malysh
