from typing import Any
from uuid import UUID, uuid4

import pytest

from app.auth import AuthError, AuthService
from app.config import Settings


class FakeDB:
    def __init__(
        self,
        *,
        users_by_id: dict[UUID, dict[str, Any]] | None = None,
        users_by_email: dict[str, dict[str, Any]] | None = None,
        users_by_api_key: dict[str, dict[str, Any]] | None = None,
        allowed_models: dict[UUID, list[str]] | None = None,
        project_roles_and_scopes: dict[UUID, tuple[list[str], list[str]]] | None = None,
        team_roles_and_scopes: dict[UUID, tuple[list[str], list[str]]] | None = None,
    ):
        self.users_by_id = users_by_id or {}
        self.users_by_email = users_by_email or {}
        self.users_by_api_key = users_by_api_key or {}
        self.allowed_models = allowed_models or {}
        self.project_roles_and_scopes = project_roles_and_scopes or {}
        self.team_roles_and_scopes = team_roles_and_scopes or {}

    async def get_user_by_id(self, *, user_id: UUID) -> dict[str, Any] | None:
        return self.users_by_id.get(user_id)

    async def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        return self.users_by_email.get(email.lower())

    async def get_user_by_api_key(self, api_key: str) -> dict[str, Any] | None:
        return self.users_by_api_key.get(api_key)

    async def get_allowed_models(self, *, user_id: UUID) -> list[str]:
        return self.allowed_models.get(user_id, [])

    async def get_user_project_role_scopes(
        self, *, user_id: UUID, project_key: str
    ) -> tuple[list[str], list[str]]:
        return self.project_roles_and_scopes.get(user_id, ([], []))

    async def get_user_team_role_scopes(
        self, *, user_id: UUID, team_name: str
    ) -> tuple[list[str], list[str]]:
        return self.team_roles_and_scopes.get(user_id, ([], []))


@pytest.fixture
def settings() -> Settings:
    return Settings(
        jwt_secret="unit-test-secret",
        jwt_expiration_minutes=30,
        refresh_token_expiration_hours=168,
    )


@pytest.fixture
def auth_service(settings: Settings) -> AuthService:
    return AuthService(settings=settings)


def _make_human_user(*, user_id: UUID, role: str = "developer") -> dict[str, Any]:
    return {
        "id": user_id,
        "email": "dev@example.com",
        "name": "Dev",
        "team": "ai-platform",
        "role": role,
        "is_service_account": False,
        "password_hash": None,
    }


def _make_service_user(*, user_id: UUID, role: str = "developer") -> dict[str, Any]:
    return {
        "id": user_id,
        "email": "ci-bot@example.com",
        "name": "CI Bot",
        "team": "ci-team",
        "role": role,
        "is_service_account": True,
        "password_hash": None,
    }


@pytest.mark.asyncio
async def test_authenticate_user_success_and_failure(auth_service: AuthService) -> None:
    user_id = uuid4()
    user = _make_human_user(user_id=user_id)
    user["password_hash"] = auth_service.hash_password("qwerty")

    db = FakeDB(users_by_email={"dev@example.com": user})

    ok = await auth_service.authenticate_user(email="dev@example.com", password="qwerty", db=db)
    bad_password = await auth_service.authenticate_user(
        email="dev@example.com", password="wrong", db=db
    )
    unknown = await auth_service.authenticate_user(
        email="unknown@example.com", password="qwerty", db=db
    )

    assert ok is not None
    assert ok["id"] == user_id
    assert bad_password is None
    assert unknown is None


@pytest.mark.asyncio
async def test_resolve_access_token_returns_principal(auth_service: AuthService) -> None:
    user_id = uuid4()
    user = _make_human_user(user_id=user_id)
    token = auth_service.create_access_token(user=user)

    db = FakeDB(
        users_by_id={user_id: user},
        allowed_models={user_id: ["HuggingFaceTB/*"]},
    )

    principal = await auth_service.resolve_access_or_api_key(token=token, db=db)

    assert principal.user_id == user_id
    assert principal.email == "dev@example.com"
    assert principal.team == "ai-platform"
    assert principal.role == "developer"
    assert principal.project_key == "default"
    assert principal.allowed_models == ["HuggingFaceTB/*"]
    assert "deployments:create" in principal.permissions
    assert principal.team_roles == []
    assert principal.team_scopes == []


@pytest.mark.asyncio
async def test_resolve_refresh_token_returns_principal(auth_service: AuthService) -> None:
    user_id = uuid4()
    user = _make_human_user(user_id=user_id)
    refresh_token = auth_service.create_refresh_token(user=user)

    db = FakeDB(users_by_id={user_id: user})

    principal = await auth_service.resolve_refresh_token(token=refresh_token, db=db)
    assert principal.user_id == user_id
    assert principal.team == "ai-platform"
    assert principal.role == "developer"


@pytest.mark.asyncio
async def test_resolve_access_token_merges_project_scopes(auth_service: AuthService) -> None:
    user_id = uuid4()
    user = _make_human_user(user_id=user_id)
    token = auth_service.create_access_token(user=user)

    db = FakeDB(
        users_by_id={user_id: user},
        project_roles_and_scopes={
            user_id: (
                ["prompt-auditor", "llm-operator"],
                ["deployments:proxy:any", "deployments:delete:any", "deployments:proxy:any"],
            )
        },
    )

    principal = await auth_service.resolve_access_or_api_key(token=token, db=db)

    assert principal.project_roles == ["prompt-auditor", "llm-operator"]
    assert principal.project_scopes == ["deployments:delete:any", "deployments:proxy:any"]
    assert "deployments:create" in principal.permissions
    assert "deployments:proxy:any" in principal.permissions


@pytest.mark.asyncio
async def test_resolve_access_token_merges_team_scopes(auth_service: AuthService) -> None:
    user_id = uuid4()
    user = _make_human_user(user_id=user_id)
    token = auth_service.create_access_token(user=user)

    db = FakeDB(
        users_by_id={user_id: user},
        team_roles_and_scopes={
            user_id: (
                ["team_operator", "team_inference"],
                [
                    "deployments:manage:any",
                    "deployments:inference:any",
                    "deployments:manage:any",
                ],
            )
        },
    )

    principal = await auth_service.resolve_access_or_api_key(token=token, db=db)

    assert principal.team_roles == ["team_operator", "team_inference"]
    assert principal.team_scopes == ["deployments:inference:any", "deployments:manage:any"]
    assert "deployments:manage:any" in principal.permissions
    assert "deployments:inference:any" in principal.permissions


@pytest.mark.asyncio
async def test_resolve_api_key_for_service_account(auth_service: AuthService) -> None:
    user_id = uuid4()
    service_user = _make_service_user(user_id=user_id)
    api_key = "ci_service_api_key_123"

    db = FakeDB(
        users_by_api_key={api_key: service_user},
        allowed_models={user_id: ["*"]},
    )

    principal = await auth_service.resolve_access_or_api_key(token=api_key, db=db)

    assert principal.user_id == user_id
    assert principal.team == "ci-team"
    assert principal.is_service_account is True
    assert principal.allowed_models == ["*"]


@pytest.mark.asyncio
async def test_refresh_rejects_non_jwt_token(auth_service: AuthService) -> None:
    db = FakeDB()
    with pytest.raises(AuthError, match="Invalid refresh token"):
        await auth_service.resolve_refresh_token(token="plain-api-key", db=db)
