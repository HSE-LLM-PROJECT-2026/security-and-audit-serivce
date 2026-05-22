import asyncio
import json
import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from time import monotonic
from typing import Any
from uuid import UUID, uuid4

import asyncpg
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import Counter
from prometheus_fastapi_instrumentator import Instrumentator

from app.auth import AuthError, AuthPrincipal, AuthService
from app.config import get_settings
from app.database import Database
from app.models import (
    AccessTokenResponse,
    AllowedModelsResponse,
    AllowedModelsUpdateRequest,
    AuditEventCreateRequest,
    AuditEventResponse,
    HealthResponse,
    LoginRequest,
    ProjectRoleResponse,
    ProjectRoleUpsertRequest,
    RefreshRequest,
    RegisterRequest,
    ServiceAccountCreateRequest,
    ServiceAccountCreateResponse,
    TeamCreateRequest,
    TeamResponse,
    TeamRoleResponse,
    TeamRoleUpsertRequest,
    TokenPairResponse,
    UpdateUserRoleRequest,
    UpdateUserTeamRequest,
    UserProjectRolesResponse,
    UserProjectRolesUpdateRequest,
    UserTeamRolesResponse,
    UserTeamRolesUpdateRequest,
    UserResponse,
    VerifyRequest,
    VerifyResponse,
)
from app.rbac import normalize_model_patterns, normalize_scopes

logger = logging.getLogger("security_audit")
OPENAPI_TAGS = [
    {
        "name": "Authentication",
        "description": "Регистрация, логин, refresh и verify токенов.",
    },
    {
        "name": "Users",
        "description": "Управление пользователями, ролями, командами и service accounts.",
    },
    {
        "name": "Project Roles",
        "description": "Кастомные роли и scopes в пределах одного проекта.",
    },
    {
        "name": "Teams",
        "description": "Создание команд и кастомные роли внутри каждой команды.",
    },
    {
        "name": "Allowed Models",
        "description": "Управление списками разрешённых моделей для пользователя.",
    },
    {
        "name": "Audit",
        "description": "Запись и чтение audit-событий.",
    },
    {
        "name": "Health",
        "description": "Проверка доступности сервиса и PostgreSQL.",
    },
]
AUDIT_EVENTS = Counter(
    "platform_audit_events_total",
    "Total audit log entries",
    ["action_type"],
)
AUDIT_EVENTS.labels(action_type="unknown").inc(0)


@dataclass(frozen=True)
class _DemoHumanUserSpec:
    email: str
    name: str
    team: str
    role: str
    allowed_models: tuple[str, ...] = ()


DEMO_HUMAN_USERS: tuple[_DemoHumanUserSpec, ...] = (
    _DemoHumanUserSpec(
        email="admin.demo@platform.local",
        name="Demo Platform Admin",
        team="platform-admin",
        role="admin",
    ),
    _DemoHumanUserSpec(
        email="manager.demo@platform.local",
        name="Demo Manager",
        team="ai-platform",
        role="manager",
    ),
    _DemoHumanUserSpec(
        email="dev.ai.demo@platform.local",
        name="Demo AI Developer",
        team="ai-platform",
        role="developer",
        allowed_models=("HuggingFaceTB/*",),
    ),
    _DemoHumanUserSpec(
        email="dev.ml.demo@platform.local",
        name="Demo ML Developer",
        team="ml-platform",
        role="developer",
        allowed_models=("Qwen/*", "meta-llama/*"),
    ),
    _DemoHumanUserSpec(
        email="viewer.demo@platform.local",
        name="Demo Viewer",
        team="ai-platform",
        role="viewer",
    ),
    _DemoHumanUserSpec(
        email="dev.data-science.demo@platform.local",
        name="Demo Data Science Developer",
        team="Data Science",
        role="developer",
        allowed_models=("HuggingFaceTB/*",),
    ),
    _DemoHumanUserSpec(
        email="dev.backend-api.demo@platform.local",
        name="Demo Backend API Developer",
        team="Backend API",
        role="developer",
        allowed_models=("HuggingFaceTB/*",),
    ),
    _DemoHumanUserSpec(
        email="dev.analytics.demo@platform.local",
        name="Demo Analytics Developer",
        team="Analytics",
        role="developer",
        allowed_models=("Qwen/*",),
    ),
    _DemoHumanUserSpec(
        email="dev.rnd.demo@platform.local",
        name="Demo R&D Developer",
        team="R&D",
        role="developer",
        allowed_models=("meta-llama/*",),
    ),
)

DEMO_SERVICE_ACCOUNT_EMAIL = "ci.demo@platform.local"
DEMO_SERVICE_ACCOUNT_NAME = "Demo CI Bot"
DEMO_SERVICE_ACCOUNT_TEAM = "ai-platform"
DEMO_SERVICE_ACCOUNT_ROLE = "developer"
DEMO_SERVICE_ACCOUNT_ALLOWED_MODELS = ("HuggingFaceTB/*",)


def _extract_bearer_token(authorization: str | None) -> str | None:
    if authorization is None:
        return None
    header = authorization.strip()
    if not header:
        return None

    prefix, sep, value = header.partition(" ")
    if sep != " " or prefix.lower() != "bearer":
        return None

    token = value.strip()
    return token or None


def _to_user_response(row: dict[str, Any]) -> UserResponse:
    return UserResponse(
        id=row["id"],
        email=row["email"],
        name=row["name"],
        team=row["team"],
        role=row["role"],
        is_service_account=row["is_service_account"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _to_audit_response(row: dict[str, Any]) -> AuditEventResponse:
    return AuditEventResponse(
        id=row["id"],
        user_id=row.get("user_id"),
        user_email=row.get("user_email"),
        is_service_account=row.get("is_service_account", False),
        action=row["action"],
        resource_type=row.get("resource_type"),
        resource_id=row.get("resource_id"),
        details=row.get("details"),
        result=row["result"],
        ip_address=row.get("ip_address"),
        created_at=row["created_at"],
    )


def _client_ip(request: Request) -> str | None:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        candidate = forwarded.split(",", maxsplit=1)[0].strip()
        if candidate:
            return candidate

    if request.client is None:
        return None
    return request.client.host


def _normalize_action_type(action: str | None) -> str:
    normalized = str(action or "").strip().lower().replace(" ", "_")
    if not normalized:
        return "unknown"
    return normalized[:64]


def _normalize_role_name(value: str) -> str:
    token = str(value or "").strip().lower()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="role_name must be non-empty.",
        )
    if len(token) > 64:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="role_name is too long (max 64 characters).",
        )
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
    if any(ch not in allowed for ch in token):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="role_name can contain only lowercase letters, digits, '-' or '_'.",
        )
    return token


def _normalize_project_role_name(value: str) -> str:
    return _normalize_role_name(value)


def _normalize_team_role_name(value: str) -> str:
    return _normalize_role_name(value)


def _normalize_team_name(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="team must be non-empty.",
        )
    if len(text) > 128:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="team is too long (max 128 characters).",
        )
    return text


def _to_project_role_response(row: dict[str, Any]) -> ProjectRoleResponse:
    scopes = normalize_scopes(list(row.get("scopes") or []))
    return ProjectRoleResponse(
        project_key=str(row.get("project_key") or ""),
        role_name=str(row.get("role_name") or ""),
        scopes=scopes,
        description=row.get("description"),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _to_team_response(row: dict[str, Any]) -> TeamResponse:
    return TeamResponse(
        id=row["id"],
        team=str(row.get("team") or ""),
        description=row.get("description"),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _to_team_role_response(row: dict[str, Any]) -> TeamRoleResponse:
    scopes = normalize_scopes(list(row.get("scopes") or []))
    return TeamRoleResponse(
        team=str(row.get("team") or ""),
        role_name=str(row.get("role_name") or ""),
        scopes=scopes,
        description=row.get("description"),
        is_default=bool(row.get("is_default")),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


async def _write_audit_event_safe(
    *,
    db: Database,
    user_id: UUID | None,
    user_email: str | None,
    is_service_account: bool,
    action: str,
    resource_type: str | None,
    resource_id: str | None,
    details: dict[str, Any] | None,
    result: str,
    ip_address: str | None,
) -> None:
    try:
        await db.create_audit_event(
            user_id=user_id,
            user_email=user_email,
            is_service_account=is_service_account,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            result=result,
            ip_address=ip_address,
            created_at=None,
        )
        AUDIT_EVENTS.labels(action_type=_normalize_action_type(action)).inc()
    except Exception:
        logger.exception("Failed to write audit event: %s", action)


async def _ensure_demo_seed_users(
    *,
    db: Database,
    auth: AuthService,
    settings: Any,
) -> dict[str, int]:
    stats = {"created": 0, "updated": 0, "skipped": 0}
    shared_password_hash = auth.hash_password(settings.demo_users_password)

    for spec in DEMO_HUMAN_USERS:
        expected_allowed_models = normalize_model_patterns(list(spec.allowed_models))
        existing = await db.get_user_by_email(spec.email)
        if existing is None:
            created = await db.create_user(
                user_id=uuid4(),
                email=spec.email,
                password_hash=shared_password_hash,
                name=spec.name,
                team=spec.team,
                role=spec.role,
                is_service_account=False,
                api_key=None,
            )
            if expected_allowed_models:
                await db.set_allowed_models(
                    user_id=created["id"],
                    patterns=expected_allowed_models,
                )
            stats["created"] += 1
            continue

        if existing["is_service_account"]:
            logger.warning(
                "Demo user seed skipped for %s: existing account is service account.",
                spec.email,
            )
            stats["skipped"] += 1
            continue

        changed = False
        if str(existing.get("role") or "") != spec.role:
            await db.update_user_role(user_id=existing["id"], role=spec.role)
            changed = True
        if str(existing.get("team") or "") != spec.team:
            await db.update_user_team(user_id=existing["id"], team=spec.team)
            changed = True

        current_allowed_models = await db.get_allowed_models(user_id=existing["id"])
        if current_allowed_models != expected_allowed_models:
            await db.set_allowed_models(
                user_id=existing["id"],
                patterns=expected_allowed_models,
            )
            changed = True

        if changed:
            stats["updated"] += 1

    demo_service_allowed_models = normalize_model_patterns(
        list(DEMO_SERVICE_ACCOUNT_ALLOWED_MODELS)
    )
    existing_service = await db.get_user_by_email(DEMO_SERVICE_ACCOUNT_EMAIL)
    if existing_service is None:
        existing_by_api_key = await db.get_user_by_api_key(
            settings.demo_service_account_api_key
        )
        if existing_by_api_key is not None:
            existing_service = existing_by_api_key
            logger.warning(
                "Demo service account email %s not found, but API key is already used by %s. "
                "Reusing existing service account record.",
                DEMO_SERVICE_ACCOUNT_EMAIL,
                existing_by_api_key.get("email"),
            )

    if existing_service is None:
        created_service = await db.create_user(
            user_id=uuid4(),
            email=DEMO_SERVICE_ACCOUNT_EMAIL,
            password_hash=None,
            name=DEMO_SERVICE_ACCOUNT_NAME,
            team=DEMO_SERVICE_ACCOUNT_TEAM,
            role=DEMO_SERVICE_ACCOUNT_ROLE,
            is_service_account=True,
            api_key=settings.demo_service_account_api_key,
        )
        if demo_service_allowed_models:
            await db.set_allowed_models(
                user_id=created_service["id"],
                patterns=demo_service_allowed_models,
            )
        stats["created"] += 1
    elif not existing_service["is_service_account"]:
        logger.warning(
            "Demo service account seed skipped for %s: existing account is human user.",
            DEMO_SERVICE_ACCOUNT_EMAIL,
        )
        stats["skipped"] += 1
    else:
        changed = False
        if str(existing_service.get("role") or "") != DEMO_SERVICE_ACCOUNT_ROLE:
            await db.update_user_role(
                user_id=existing_service["id"],
                role=DEMO_SERVICE_ACCOUNT_ROLE,
            )
            changed = True
        if str(existing_service.get("team") or "") != DEMO_SERVICE_ACCOUNT_TEAM:
            await db.update_user_team(
                user_id=existing_service["id"],
                team=DEMO_SERVICE_ACCOUNT_TEAM,
            )
            changed = True

        if str(existing_service.get("api_key") or "") != settings.demo_service_account_api_key:
            logger.warning(
                "Demo service account %s already exists with another API key. "
                "Keeping existing key.",
                DEMO_SERVICE_ACCOUNT_EMAIL,
            )

        current_allowed_models = await db.get_allowed_models(user_id=existing_service["id"])
        if current_allowed_models != demo_service_allowed_models:
            await db.set_allowed_models(
                user_id=existing_service["id"],
                patterns=demo_service_allowed_models,
            )
            changed = True

        if changed:
            stats["updated"] += 1

    return stats


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )

    db = Database(settings=settings)
    auth = AuthService(settings=settings)

    try:
        await db.connect()
        await db.init_schema()

        admin_created = await db.ensure_admin_user(
            admin_email=settings.admin_email,
            admin_password_hash=auth.hash_password(settings.admin_password),
            admin_name=settings.admin_name,
            admin_team=settings.admin_team,
        )
        if admin_created:
            logger.info("Default admin user created: %s", settings.admin_email)
        else:
            logger.info("Default admin user already exists: %s", settings.admin_email)

        if settings.demo_users_enabled:
            demo_seed_stats = await _ensure_demo_seed_users(
                db=db,
                auth=auth,
                settings=settings,
            )
            logger.info(
                "Demo users seed processed: created=%s updated=%s skipped=%s",
                demo_seed_stats["created"],
                demo_seed_stats["updated"],
                demo_seed_stats["skipped"],
            )
    except Exception:
        logger.exception("Failed to initialize security & audit service.")
        await db.close()
        raise

    app.state.settings = settings
    app.state.db = db
    app.state.auth = auth
    app.state.short_read_cache = {"entries": {}, "lock": asyncio.Lock()}
    logger.info("Security & Audit service started.")
    try:
        yield
    finally:
        await db.close()
        logger.info("Security & Audit service stopped.")


runtime_settings = get_settings()

app = FastAPI(
    title="Platform Flow Security & Audit Service",
    lifespan=lifespan,
    openapi_tags=OPENAPI_TAGS,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=runtime_settings.cors_allow_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
Instrumentator().instrument(app).expose(app, include_in_schema=False)
bearer_auth = HTTPBearer(auto_error=False)


@app.middleware("http")
async def clear_short_read_cache_on_mutation(request: Request, call_next):
    response = await call_next(request)
    if request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and response.status_code < 500:
        _clear_short_read_cache(request)
    return response


def _get_db(request: Request) -> Database:
    return request.app.state.db


def _get_auth(request: Request) -> AuthService:
    return request.app.state.auth


def _get_runtime_settings(request: Request):
    return request.app.state.settings


def _get_short_read_cache(request: Request) -> dict[str, Any]:
    cache = getattr(request.app.state, "short_read_cache", None)
    if cache is None:
        cache = {"entries": {}, "lock": asyncio.Lock()}
        request.app.state.short_read_cache = cache
    return cache


def _clear_short_read_cache(request: Request) -> None:
    cache = _get_short_read_cache(request)
    entries = cache.get("entries")
    if isinstance(entries, dict):
        entries.clear()


def _principal_cache_scope(principal: AuthPrincipal) -> str:
    team_part = str(principal.team or "").strip().lower() or "<none>"
    return f"{principal.user_id}|{principal.role}|{team_part}"


def _build_short_cache_key(
    *,
    endpoint: str,
    principal: AuthPrincipal,
    params: dict[str, Any] | None = None,
) -> str:
    payload = {
        "endpoint": endpoint,
        "scope": _principal_cache_scope(principal),
        "params": params or {},
    }
    return json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)


async def _short_cache_get(request: Request, cache_key: str) -> Any | None:
    settings = _get_runtime_settings(request)
    ttl_seconds = max(float(settings.short_read_cache_ttl_seconds), 0.0)
    if ttl_seconds <= 0:
        return None

    cache = _get_short_read_cache(request)
    entries = cache.setdefault("entries", {})
    lock = cache.setdefault("lock", asyncio.Lock())
    now = monotonic()

    cached_entry = entries.get(cache_key)
    if isinstance(cached_entry, dict) and float(cached_entry.get("expires_at", 0.0)) > now:
        return cached_entry.get("value")

    async with lock:
        now = monotonic()
        cached_entry = entries.get(cache_key)
        if isinstance(cached_entry, dict) and float(cached_entry.get("expires_at", 0.0)) > now:
            return cached_entry.get("value")
    return None


async def _short_cache_set(request: Request, cache_key: str, value: Any) -> None:
    settings = _get_runtime_settings(request)
    ttl_seconds = max(float(settings.short_read_cache_ttl_seconds), 0.0)
    if ttl_seconds <= 0:
        return

    cache = _get_short_read_cache(request)
    entries = cache.setdefault("entries", {})
    lock = cache.setdefault("lock", asyncio.Lock())
    now = monotonic()

    async with lock:
        entries[cache_key] = {"expires_at": now + ttl_seconds, "value": value}

        stale_keys = [
            key
            for key, entry in entries.items()
            if not isinstance(entry, dict) or float(entry.get("expires_at", 0.0)) <= now
        ]
        for key in stale_keys:
            entries.pop(key, None)

        max_entries = max(int(settings.short_read_cache_max_entries), 1)
        overflow = len(entries) - max_entries
        if overflow > 0:
            oldest_first = sorted(
                entries.items(),
                key=lambda item: float(item[1].get("expires_at", 0.0)),
            )
            for key, _entry in oldest_first[:overflow]:
                entries.pop(key, None)


def _forbidden(detail: str = "You do not have permission to perform this action.") -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def _principal_has_permission(principal: AuthPrincipal, permission: str) -> bool:
    return permission in set(principal.permissions)


def _require_principal_permission(principal: AuthPrincipal, permission: str) -> None:
    if _principal_has_permission(principal, permission):
        return
    raise _forbidden(f"Permission denied: '{permission}' is required.")


def _require_any_principal_permission(principal: AuthPrincipal, permissions: set[str]) -> None:
    for permission in permissions:
        if _principal_has_permission(principal, permission):
            return
    raise _forbidden(
        "Permission denied: one of the following permissions is required: "
        + ", ".join(sorted(permissions))
    )


def _can_manage_team(principal: AuthPrincipal, target_team: str) -> bool:
    if _principal_has_permission(principal, "roles:manage"):
        return True
    if not _principal_has_permission(principal, "teams:manage"):
        return False
    return str(principal.team or "").strip().lower() == target_team.strip().lower()


def _require_manage_team(principal: AuthPrincipal, target_team: str) -> None:
    if _can_manage_team(principal, target_team):
        return
    raise _forbidden(
        "Permission denied: you can manage team roles only for your own team "
        "(unless you have 'roles:manage')."
    )


async def get_current_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_auth),
) -> AuthPrincipal:
    authorization: str | None = None
    if credentials is not None:
        authorization = f"{credentials.scheme} {credentials.credentials}"
    token = _extract_bearer_token(authorization)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header with Bearer token is required.",
        )

    db = _get_db(request)
    auth = _get_auth(request)

    try:
        return await auth.resolve_access_or_api_key(token=token, db=db)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to authenticate principal.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc


@app.post(
    "/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"],
)
async def register(payload: RegisterRequest, request: Request) -> UserResponse:
    db = _get_db(request)
    auth = _get_auth(request)
    settings = _get_runtime_settings(request)

    email = str(payload.email).strip().lower()

    try:
        user = await db.create_user(
            user_id=uuid4(),
            email=email,
            password_hash=auth.hash_password(payload.password),
            name=payload.name,
            team=settings.default_user_team,
            role="viewer",
            is_service_account=False,
            api_key=None,
        )
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists.",
        ) from exc
    except asyncpg.CheckViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid user payload: {str(exc)}",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to register user: %s", email)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    await _write_audit_event_safe(
        db=db,
        user_id=user["id"],
        user_email=user["email"],
        is_service_account=False,
        action="user.create",
        resource_type="user",
        resource_id=str(user["id"]),
        details={"source": "self_register", "role": user["role"], "team": user["team"]},
        result="success",
        ip_address=_client_ip(request),
    )

    return _to_user_response(user)


@app.post("/auth/login", response_model=TokenPairResponse, tags=["Authentication"])
async def login(payload: LoginRequest, request: Request) -> TokenPairResponse:
    db = _get_db(request)
    auth = _get_auth(request)

    email = str(payload.email).strip().lower()
    try:
        user = await auth.authenticate_user(email=email, password=payload.password, db=db)
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to login user: %s", email)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    access_token = auth.create_access_token(user=user)
    refresh_token = auth.create_refresh_token(user=user)

    await _write_audit_event_safe(
        db=db,
        user_id=user["id"],
        user_email=user["email"],
        is_service_account=False,
        action="auth.login",
        resource_type="user",
        resource_id=str(user["id"]),
        details=None,
        result="success",
        ip_address=_client_ip(request),
    )

    return TokenPairResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=auth.access_expires_in_seconds,
        user=_to_user_response(user),
    )


@app.post("/auth/refresh", response_model=AccessTokenResponse, tags=["Authentication"])
async def refresh(payload: RefreshRequest, request: Request) -> AccessTokenResponse:
    db = _get_db(request)
    auth = _get_auth(request)

    try:
        principal = await auth.resolve_refresh_token(token=payload.refresh_token, db=db)
        user = await db.get_user_by_id(user_id=principal.user_id)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to refresh access token.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User does not exist.",
        )

    access_token = auth.create_access_token(user=user)
    return AccessTokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=auth.access_expires_in_seconds,
    )


@app.post("/auth/verify", response_model=VerifyResponse, tags=["Authentication"])
async def verify(
    request: Request,
    payload: VerifyRequest | None = None,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_auth),
) -> VerifyResponse:
    db = _get_db(request)
    auth = _get_auth(request)

    authorization: str | None = None
    if credentials is not None:
        authorization = f"{credentials.scheme} {credentials.credentials}"
    token = _extract_bearer_token(authorization)
    if token is None and payload is not None:
        if payload.token is not None and payload.token.strip():
            token = payload.token.strip()

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is required either in Authorization Bearer header or request body.",
        )

    try:
        principal = await auth.resolve_access_or_api_key(token=token, db=db)
    except AuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to verify token.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    return VerifyResponse(
        user_id=principal.user_id,
        email=principal.email,
        team=principal.team,
        role=principal.role,
        is_service_account=principal.is_service_account,
        permissions=principal.permissions,
        allowed_models=principal.allowed_models,
        project_key=principal.project_key,
        project_roles=principal.project_roles,
        project_scopes=principal.project_scopes,
        team_roles=principal.team_roles,
        team_scopes=principal.team_scopes,
    )


@app.get("/users", response_model=list[UserResponse], tags=["Users"])
async def list_users(
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> list[UserResponse]:
    _require_principal_permission(principal, "users:manage")
    cache_key = _build_short_cache_key(endpoint="users.list", principal=principal)
    cached = await _short_cache_get(request, cache_key)
    if cached is not None:
        return cached

    db = _get_db(request)
    try:
        users = await db.list_users()
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to list users.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    result = [_to_user_response(item) for item in users]
    await _short_cache_set(request, cache_key, result)
    return result


@app.get("/users/{user_id}", response_model=UserResponse, tags=["Users"])
async def get_user(
    user_id: UUID,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> UserResponse:
    _require_principal_permission(principal, "users:manage")
    cache_key = _build_short_cache_key(
        endpoint="users.get",
        principal=principal,
        params={"user_id": str(user_id)},
    )
    cached = await _short_cache_get(request, cache_key)
    if cached is not None:
        return cached

    db = _get_db(request)
    try:
        user = await db.get_user_by_id(user_id=user_id)
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to get user %s.", user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    result = _to_user_response(user)
    await _short_cache_set(request, cache_key, result)
    return result


@app.patch("/users/{user_id}/role", response_model=UserResponse, tags=["Users"])
async def update_user_role(
    user_id: UUID,
    payload: UpdateUserRoleRequest,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> UserResponse:
    _require_principal_permission(principal, "roles:manage")

    db = _get_db(request)

    try:
        user_before = await db.get_user_by_id(user_id=user_id)
        if user_before is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        updated = await db.update_user_role(user_id=user_id, role=payload.role)
    except HTTPException:
        raise
    except asyncpg.CheckViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role payload: {str(exc)}",
        ) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to update user role for %s.", user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    await _write_audit_event_safe(
        db=db,
        user_id=principal.user_id,
        user_email=principal.email,
        is_service_account=principal.is_service_account,
        action="role.change",
        resource_type="user",
        resource_id=str(user_id),
        details={"old_role": user_before["role"], "new_role": payload.role},
        result="success",
        ip_address=_client_ip(request),
    )

    return _to_user_response(updated)


@app.patch("/users/{user_id}/team", response_model=UserResponse, tags=["Users"])
async def update_user_team(
    user_id: UUID,
    payload: UpdateUserTeamRequest,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> UserResponse:
    _require_principal_permission(principal, "users:manage")

    db = _get_db(request)

    try:
        user_before = await db.get_user_by_id(user_id=user_id)
        if user_before is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        updated = await db.update_user_team(user_id=user_id, team=payload.team)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to update user team for %s.", user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    if updated is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    await _write_audit_event_safe(
        db=db,
        user_id=principal.user_id,
        user_email=principal.email,
        is_service_account=principal.is_service_account,
        action="team.change",
        resource_type="user",
        resource_id=str(user_id),
        details={"old_team": user_before["team"], "new_team": payload.team},
        result="success",
        ip_address=_client_ip(request),
    )

    return _to_user_response(updated)


@app.delete("/users/{user_id}", tags=["Users"])
async def delete_user(
    user_id: UUID,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> dict[str, str]:
    _require_principal_permission(principal, "users:manage")
    if principal.user_id == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admin cannot delete own account.",
        )

    db = _get_db(request)
    try:
        deleted = await db.delete_user(user_id=user_id)
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to delete user %s.", user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    await _write_audit_event_safe(
        db=db,
        user_id=principal.user_id,
        user_email=principal.email,
        is_service_account=principal.is_service_account,
        action="user.delete",
        resource_type="user",
        resource_id=str(user_id),
        details=None,
        result="success",
        ip_address=_client_ip(request),
    )

    return {"id": str(user_id), "status": "deleted"}


@app.post(
    "/users/service-account",
    response_model=ServiceAccountCreateResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Users"],
)
async def create_service_account(
    payload: ServiceAccountCreateRequest,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> ServiceAccountCreateResponse:
    _require_principal_permission(principal, "users:manage")

    db = _get_db(request)
    auth = _get_auth(request)
    api_key = auth.generate_api_key()
    allowed_models = normalize_model_patterns(payload.allowed_models)
    service_team = payload.team if payload.team is not None else principal.team

    try:
        user = await db.create_user(
            user_id=uuid4(),
            email=str(payload.email).strip().lower(),
            password_hash=None,
            name=payload.name,
            team=service_team,
            role=payload.role,
            is_service_account=True,
            api_key=api_key,
        )
        if allowed_models:
            await db.set_allowed_models(user_id=user["id"], patterns=allowed_models)
    except asyncpg.UniqueViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Service account with this email or API key already exists.",
        ) from exc
    except asyncpg.CheckViolationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid service account payload: {str(exc)}",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to create service account.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    await _write_audit_event_safe(
        db=db,
        user_id=principal.user_id,
        user_email=principal.email,
        is_service_account=principal.is_service_account,
        action="user.create",
        resource_type="user",
        resource_id=str(user["id"]),
        details={"service_account": True, "role": payload.role, "team": service_team},
        result="success",
        ip_address=_client_ip(request),
    )

    return ServiceAccountCreateResponse(
        user=_to_user_response(user),
        api_key=api_key,
    )


@app.get(
    "/teams",
    response_model=list[TeamResponse],
    tags=["Teams"],
)
async def list_teams(
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> list[TeamResponse]:
    db = _get_db(request)
    can_list_all = _principal_has_permission(principal, "roles:manage") or _principal_has_permission(
        principal, "users:manage"
    )
    can_manage_team_only = _principal_has_permission(principal, "teams:manage")

    if not can_list_all and not can_manage_team_only:
        raise _forbidden(
            "Permission denied: 'roles:manage', 'users:manage' or 'teams:manage' is required."
        )
    cache_key = _build_short_cache_key(
        endpoint="teams.list",
        principal=principal,
        params={
            "can_list_all": can_list_all,
            "can_manage_team_only": can_manage_team_only,
        },
    )
    cached = await _short_cache_get(request, cache_key)
    if cached is not None:
        return cached

    try:
        if can_list_all:
            rows = await db.list_teams()
        else:
            own_team = await db.get_team(team_name=principal.team)
            rows = [own_team] if own_team is not None else []
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to list teams.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    result = [_to_team_response(item) for item in rows]
    await _short_cache_set(request, cache_key, result)
    return result


@app.post(
    "/teams",
    response_model=TeamResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Teams"],
)
async def create_team(
    payload: TeamCreateRequest,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> TeamResponse:
    _require_principal_permission(principal, "roles:manage")
    db = _get_db(request)

    normalized_team = _normalize_team_name(payload.team)

    try:
        row = await db.ensure_team(
            team_name=normalized_team,
            description=payload.description,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to create team '%s'.", normalized_team)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    await _write_audit_event_safe(
        db=db,
        user_id=principal.user_id,
        user_email=principal.email,
        is_service_account=principal.is_service_account,
        action="team.create",
        resource_type="team",
        resource_id=normalized_team,
        details={"team": normalized_team},
        result="success",
        ip_address=_client_ip(request),
    )

    return _to_team_response(row)


@app.get(
    "/teams/{team_name}/roles",
    response_model=list[TeamRoleResponse],
    tags=["Teams"],
)
async def list_team_roles(
    team_name: str,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> list[TeamRoleResponse]:
    normalized_team = _normalize_team_name(team_name)
    _require_manage_team(principal, normalized_team)
    cache_key = _build_short_cache_key(
        endpoint="teams.roles.list",
        principal=principal,
        params={"team": normalized_team},
    )
    cached = await _short_cache_get(request, cache_key)
    if cached is not None:
        return cached
    db = _get_db(request)
    try:
        team = await db.get_team(team_name=normalized_team)
        if team is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found.")
        rows = await db.list_team_roles(team_name=normalized_team)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to list team roles for '%s'.", normalized_team)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    result = [_to_team_role_response(item) for item in rows]
    await _short_cache_set(request, cache_key, result)
    return result


@app.put(
    "/teams/{team_name}/roles/{role_name}",
    response_model=TeamRoleResponse,
    tags=["Teams"],
)
async def upsert_team_role(
    team_name: str,
    role_name: str,
    payload: TeamRoleUpsertRequest,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> TeamRoleResponse:
    normalized_team = _normalize_team_name(team_name)
    normalized_role_name = _normalize_team_role_name(role_name)
    _require_manage_team(principal, normalized_team)
    db = _get_db(request)
    normalized_scopes = normalize_scopes(payload.scopes)

    try:
        team = await db.get_team(team_name=normalized_team)
        if team is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found.")
        row = await db.upsert_team_role(
            team_name=normalized_team,
            role_name=normalized_role_name,
            scopes=normalized_scopes,
            description=payload.description,
            is_default=False,
        )
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except asyncpg.PostgresError as exc:
        logger.exception(
            "Failed to upsert team role '%s' for team '%s'.",
            normalized_role_name,
            normalized_team,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    await _write_audit_event_safe(
        db=db,
        user_id=principal.user_id,
        user_email=principal.email,
        is_service_account=principal.is_service_account,
        action="team_role.upsert",
        resource_type="team_role",
        resource_id=f"{normalized_team}:{normalized_role_name}",
        details={
            "team": normalized_team,
            "role_name": normalized_role_name,
            "scopes_count": len(normalized_scopes),
        },
        result="success",
        ip_address=_client_ip(request),
    )

    return _to_team_role_response(row)


@app.delete(
    "/teams/{team_name}/roles/{role_name}",
    tags=["Teams"],
)
async def delete_team_role(
    team_name: str,
    role_name: str,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> dict[str, str]:
    normalized_team = _normalize_team_name(team_name)
    normalized_role_name = _normalize_team_role_name(role_name)
    _require_manage_team(principal, normalized_team)
    db = _get_db(request)

    try:
        team = await db.get_team(team_name=normalized_team)
        if team is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team not found.")
        existing_role = await db.get_team_role(
            team_name=normalized_team,
            role_name=normalized_role_name,
        )
        if existing_role is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team role not found.")
        if bool(existing_role.get("is_default")):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Default team role cannot be deleted.",
            )
        deleted = await db.delete_team_role(
            team_name=normalized_team,
            role_name=normalized_role_name,
        )
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except asyncpg.PostgresError as exc:
        logger.exception(
            "Failed to delete team role '%s' for team '%s'.",
            normalized_role_name,
            normalized_team,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Team role not found.")

    await _write_audit_event_safe(
        db=db,
        user_id=principal.user_id,
        user_email=principal.email,
        is_service_account=principal.is_service_account,
        action="team_role.delete",
        resource_type="team_role",
        resource_id=f"{normalized_team}:{normalized_role_name}",
        details={"team": normalized_team, "role_name": normalized_role_name},
        result="success",
        ip_address=_client_ip(request),
    )

    return {"team": normalized_team, "role_name": normalized_role_name, "status": "deleted"}


@app.get(
    "/users/{user_id}/team-roles",
    response_model=UserTeamRolesResponse,
    tags=["Teams"],
)
async def get_user_team_roles(
    user_id: UUID,
    request: Request,
    team: str | None = Query(default=None),
    principal: AuthPrincipal = Depends(get_current_principal),
) -> UserTeamRolesResponse:
    _require_any_principal_permission(principal, {"roles:manage", "teams:manage"})
    db = _get_db(request)
    cache_key = _build_short_cache_key(
        endpoint="users.team_roles.get",
        principal=principal,
        params={"user_id": str(user_id), "team": team or ""},
    )
    cached = await _short_cache_get(request, cache_key)
    if cached is not None:
        return cached

    try:
        user = await db.get_user_by_id(user_id=user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        target_team = _normalize_team_name(team if team is not None else str(user.get("team") or ""))
        _require_manage_team(principal, target_team)
        role_names, scopes = await db.get_user_team_role_scopes(
            user_id=user_id,
            team_name=target_team,
        )
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to read team roles for user %s.", user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    result = UserTeamRolesResponse(
        user_id=user_id,
        team=target_team,
        role_names=role_names,
        effective_scopes=scopes,
    )
    await _short_cache_set(request, cache_key, result)
    return result


@app.put(
    "/users/{user_id}/team-roles",
    response_model=UserTeamRolesResponse,
    tags=["Teams"],
)
async def put_user_team_roles(
    user_id: UUID,
    payload: UserTeamRolesUpdateRequest,
    request: Request,
    team: str | None = Query(default=None),
    principal: AuthPrincipal = Depends(get_current_principal),
) -> UserTeamRolesResponse:
    _require_any_principal_permission(principal, {"roles:manage", "teams:manage"})
    db = _get_db(request)
    role_names = [_normalize_team_role_name(item) for item in payload.role_names]

    try:
        user = await db.get_user_by_id(user_id=user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        target_team = _normalize_team_name(team if team is not None else str(user.get("team") or ""))
        _require_manage_team(principal, target_team)

        existing_team_roles = await db.list_team_roles(team_name=target_team)
        existing_names = {str(item.get("role_name") or "").strip().lower() for item in existing_team_roles}
        missing = [role_name for role_name in role_names if role_name not in existing_names]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Unknown team role(s): " + ", ".join(sorted(missing)),
            )

        assigned_role_names = await db.set_user_team_roles(
            user_id=user_id,
            team_name=target_team,
            role_names=role_names,
        )
        _assigned, scopes = await db.get_user_team_role_scopes(
            user_id=user_id,
            team_name=target_team,
        )
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to update team roles for user %s.", user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    await _write_audit_event_safe(
        db=db,
        user_id=principal.user_id,
        user_email=principal.email,
        is_service_account=principal.is_service_account,
        action="team_role.assign",
        resource_type="user",
        resource_id=str(user_id),
        details={
            "team": target_team,
            "role_names": assigned_role_names,
            "effective_scopes": scopes,
        },
        result="success",
        ip_address=_client_ip(request),
    )

    return UserTeamRolesResponse(
        user_id=user_id,
        team=target_team,
        role_names=assigned_role_names,
        effective_scopes=scopes,
    )


@app.get(
    "/project/roles",
    response_model=list[ProjectRoleResponse],
    tags=["Project Roles"],
)
async def list_project_roles(
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> list[ProjectRoleResponse]:
    _require_principal_permission(principal, "roles:manage")
    cache_key = _build_short_cache_key(endpoint="project.roles.list", principal=principal)
    cached = await _short_cache_get(request, cache_key)
    if cached is not None:
        return cached

    db = _get_db(request)
    settings = _get_runtime_settings(request)
    try:
        rows = await db.list_project_roles(project_key=settings.project_key)
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to list project roles.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    result = [_to_project_role_response(row) for row in rows]
    await _short_cache_set(request, cache_key, result)
    return result


@app.put(
    "/project/roles/{role_name}",
    response_model=ProjectRoleResponse,
    tags=["Project Roles"],
)
async def upsert_project_role(
    role_name: str,
    payload: ProjectRoleUpsertRequest,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> ProjectRoleResponse:
    _require_principal_permission(principal, "roles:manage")

    normalized_role_name = _normalize_project_role_name(role_name)
    db = _get_db(request)
    settings = _get_runtime_settings(request)
    normalized_scopes = normalize_scopes(payload.scopes)

    try:
        row = await db.upsert_project_role(
            project_key=settings.project_key,
            role_name=normalized_role_name,
            scopes=normalized_scopes,
            description=payload.description,
        )
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to upsert project role '%s'.", normalized_role_name)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    await _write_audit_event_safe(
        db=db,
        user_id=principal.user_id,
        user_email=principal.email,
        is_service_account=principal.is_service_account,
        action="project_role.upsert",
        resource_type="project_role",
        resource_id=f"{settings.project_key}:{normalized_role_name}",
        details={
            "project_key": settings.project_key,
            "role_name": normalized_role_name,
            "scopes_count": len(normalized_scopes),
        },
        result="success",
        ip_address=_client_ip(request),
    )

    return _to_project_role_response(row)


@app.delete(
    "/project/roles/{role_name}",
    tags=["Project Roles"],
)
async def delete_project_role(
    role_name: str,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> dict[str, str]:
    _require_principal_permission(principal, "roles:manage")

    normalized_role_name = _normalize_project_role_name(role_name)
    db = _get_db(request)
    settings = _get_runtime_settings(request)
    try:
        deleted = await db.delete_project_role(
            project_key=settings.project_key,
            role_name=normalized_role_name,
        )
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to delete project role '%s'.", normalized_role_name)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project role not found.",
        )

    await _write_audit_event_safe(
        db=db,
        user_id=principal.user_id,
        user_email=principal.email,
        is_service_account=principal.is_service_account,
        action="project_role.delete",
        resource_type="project_role",
        resource_id=f"{settings.project_key}:{normalized_role_name}",
        details={
            "project_key": settings.project_key,
            "role_name": normalized_role_name,
        },
        result="success",
        ip_address=_client_ip(request),
    )

    return {"project_key": settings.project_key, "role_name": normalized_role_name, "status": "deleted"}


@app.get(
    "/users/{user_id}/project-roles",
    response_model=UserProjectRolesResponse,
    tags=["Project Roles"],
)
async def get_user_project_roles(
    user_id: UUID,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> UserProjectRolesResponse:
    _require_principal_permission(principal, "roles:manage")
    cache_key = _build_short_cache_key(
        endpoint="users.project_roles.get",
        principal=principal,
        params={"user_id": str(user_id)},
    )
    cached = await _short_cache_get(request, cache_key)
    if cached is not None:
        return cached

    db = _get_db(request)
    settings = _get_runtime_settings(request)

    try:
        user = await db.get_user_by_id(user_id=user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        role_names, scopes = await db.get_user_project_role_scopes(
            user_id=user_id,
            project_key=settings.project_key,
        )
    except HTTPException:
        raise
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to read project roles for user %s.", user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    result = UserProjectRolesResponse(
        user_id=user_id,
        project_key=settings.project_key,
        role_names=role_names,
        effective_scopes=scopes,
    )
    await _short_cache_set(request, cache_key, result)
    return result


@app.put(
    "/users/{user_id}/project-roles",
    response_model=UserProjectRolesResponse,
    tags=["Project Roles"],
)
async def put_user_project_roles(
    user_id: UUID,
    payload: UserProjectRolesUpdateRequest,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> UserProjectRolesResponse:
    _require_principal_permission(principal, "roles:manage")

    db = _get_db(request)
    settings = _get_runtime_settings(request)
    role_names = [_normalize_project_role_name(item) for item in payload.role_names]

    try:
        user = await db.get_user_by_id(user_id=user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        existing_project_roles = await db.list_project_roles(project_key=settings.project_key)
        existing_names = {str(item.get("role_name") or "").strip().lower() for item in existing_project_roles}
        missing = [role_name for role_name in role_names if role_name not in existing_names]
        if missing:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "Unknown project role(s): " + ", ".join(sorted(missing))
                ),
            )

        assigned_role_names = await db.set_user_project_roles(
            user_id=user_id,
            project_key=settings.project_key,
            role_names=role_names,
        )
        _assigned, scopes = await db.get_user_project_role_scopes(
            user_id=user_id,
            project_key=settings.project_key,
        )
    except HTTPException:
        raise
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to update project roles for user %s.", user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    await _write_audit_event_safe(
        db=db,
        user_id=principal.user_id,
        user_email=principal.email,
        is_service_account=principal.is_service_account,
        action="project_role.assign",
        resource_type="user",
        resource_id=str(user_id),
        details={
            "project_key": settings.project_key,
            "role_names": assigned_role_names,
            "effective_scopes": scopes,
        },
        result="success",
        ip_address=_client_ip(request),
    )

    return UserProjectRolesResponse(
        user_id=user_id,
        project_key=settings.project_key,
        role_names=assigned_role_names,
        effective_scopes=scopes,
    )


@app.get(
    "/users/{user_id}/allowed-models",
    response_model=AllowedModelsResponse,
    tags=["Allowed Models"],
)
async def get_allowed_models(
    user_id: UUID,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> AllowedModelsResponse:
    _require_principal_permission(principal, "allowed_models:manage")
    cache_key = _build_short_cache_key(
        endpoint="users.allowed_models.get",
        principal=principal,
        params={"user_id": str(user_id)},
    )
    cached = await _short_cache_get(request, cache_key)
    if cached is not None:
        return cached

    db = _get_db(request)
    try:
        user = await db.get_user_by_id(user_id=user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        patterns = await db.get_allowed_models(user_id=user_id)
    except HTTPException:
        raise
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to read allowed models for user %s.", user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    result = AllowedModelsResponse(user_id=user_id, allowed_models=patterns)
    await _short_cache_set(request, cache_key, result)
    return result


@app.put(
    "/users/{user_id}/allowed-models",
    response_model=AllowedModelsResponse,
    tags=["Allowed Models"],
)
async def put_allowed_models(
    user_id: UUID,
    payload: AllowedModelsUpdateRequest,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> AllowedModelsResponse:
    _require_principal_permission(principal, "allowed_models:manage")

    db = _get_db(request)
    normalized_patterns = normalize_model_patterns(payload.allowed_models)

    try:
        user = await db.get_user_by_id(user_id=user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
        patterns = await db.set_allowed_models(user_id=user_id, patterns=normalized_patterns)
    except HTTPException:
        raise
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to update allowed models for user %s.", user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    await _write_audit_event_safe(
        db=db,
        user_id=principal.user_id,
        user_email=principal.email,
        is_service_account=principal.is_service_account,
        action="allowed_models.update",
        resource_type="user",
        resource_id=str(user_id),
        details={"allowed_models": patterns},
        result="success",
        ip_address=_client_ip(request),
    )

    return AllowedModelsResponse(user_id=user_id, allowed_models=patterns)


@app.post(
    "/audit/events",
    response_model=AuditEventResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Audit"],
)
async def create_audit_event(
    payload: AuditEventCreateRequest,
    request: Request,
    principal: AuthPrincipal = Depends(get_current_principal),
) -> AuditEventResponse:
    _require_principal_permission(principal, "audit:write")

    db = _get_db(request)
    ip_address = payload.ip_address or _client_ip(request)

    try:
        event = await db.create_audit_event(
            user_id=payload.user_id,
            user_email=str(payload.user_email) if payload.user_email else None,
            is_service_account=payload.is_service_account,
            action=payload.action,
            resource_type=payload.resource_type,
            resource_id=payload.resource_id,
            details=payload.details,
            result=payload.result,
            ip_address=ip_address,
            created_at=payload.timestamp,
        )
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to write audit event %s.", payload.action)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    AUDIT_EVENTS.labels(action_type=_normalize_action_type(payload.action)).inc()
    return _to_audit_response(event)


@app.get("/audit", response_model=list[AuditEventResponse], tags=["Audit"])
async def list_audit(
    request: Request,
    user_id: UUID | None = Query(default=None),
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    principal: AuthPrincipal = Depends(get_current_principal),
) -> list[AuditEventResponse]:
    _require_principal_permission(principal, "audit:read")

    db = _get_db(request)
    normalized_action = action.strip() if action else None
    normalized_resource_type = resource_type.strip() if resource_type else None
    cache_key = _build_short_cache_key(
        endpoint="audit.list",
        principal=principal,
        params={
            "user_id": str(user_id) if user_id is not None else "",
            "action": normalized_action or "",
            "resource_type": normalized_resource_type or "",
            "date_from": date_from.isoformat() if date_from is not None else "",
            "date_to": date_to.isoformat() if date_to is not None else "",
            "limit": limit,
            "offset": offset,
        },
    )
    cached = await _short_cache_get(request, cache_key)
    if cached is not None:
        return cached

    try:
        rows = await db.list_audit_events(
            user_id=user_id,
            action=normalized_action,
            resource_type=normalized_resource_type,
            date_from=date_from,
            date_to=date_to,
            limit=limit,
            offset=offset,
        )
    except asyncpg.PostgresError as exc:
        logger.exception("Failed to list audit events.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error: {str(exc)}",
        ) from exc

    result = [_to_audit_response(row) for row in rows]
    await _short_cache_set(request, cache_key, result)
    return result


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def healthcheck(request: Request) -> HealthResponse:
    db = _get_db(request)

    details: dict[str, str] = {}
    db_ok = False

    try:
        await db.ping()
        db_ok = True
    except Exception as exc:
        details["postgresql"] = str(exc)

    if db_ok:
        return HealthResponse(status="ok", details=None)

    body = HealthResponse(status="degraded", details=details).model_dump(mode="json")
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=body)


@app.get("/livez", response_model=HealthResponse, tags=["Health"])
async def livecheck() -> HealthResponse:
    return HealthResponse(status="ok", details=None)
