from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.main import (
    DEMO_HUMAN_USERS,
    DEMO_SERVICE_ACCOUNT_EMAIL,
    DEMO_SERVICE_ACCOUNT_ROLE,
    DEMO_SERVICE_ACCOUNT_TEAM,
    _ensure_demo_seed_users,
)


class FakeDB:
    def __init__(self) -> None:
        self.users_by_email: dict[str, dict[str, Any]] = {}
        self.allowed_models_by_user: dict[UUID, list[str]] = {}

    async def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        return self.users_by_email.get(email.lower())

    async def create_user(
        self,
        *,
        user_id: UUID,
        email: str,
        password_hash: str | None,
        name: str,
        team: str,
        role: str,
        is_service_account: bool,
        api_key: str | None,
    ) -> dict[str, Any]:
        row = {
            "id": user_id,
            "email": email.lower(),
            "password_hash": password_hash,
            "name": name,
            "team": team,
            "role": role,
            "is_service_account": is_service_account,
            "api_key": api_key,
        }
        self.users_by_email[row["email"]] = row
        self.allowed_models_by_user.setdefault(user_id, [])
        return row

    async def get_user_by_api_key(self, api_key: str) -> dict[str, Any] | None:
        for row in self.users_by_email.values():
            if row.get("is_service_account") and row.get("api_key") == api_key:
                return row
        return None

    async def update_user_role(self, *, user_id: UUID, role: str) -> dict[str, Any] | None:
        user = self._get_user_by_id(user_id)
        if user is None:
            return None
        user["role"] = role
        return user

    async def update_user_team(self, *, user_id: UUID, team: str) -> dict[str, Any] | None:
        user = self._get_user_by_id(user_id)
        if user is None:
            return None
        user["team"] = team
        return user

    async def get_allowed_models(self, *, user_id: UUID) -> list[str]:
        return list(self.allowed_models_by_user.get(user_id, []))

    async def set_allowed_models(self, *, user_id: UUID, patterns: list[str]) -> list[str]:
        self.allowed_models_by_user[user_id] = list(patterns)
        return list(patterns)

    def _get_user_by_id(self, user_id: UUID) -> dict[str, Any] | None:
        for row in self.users_by_email.values():
            if row["id"] == user_id:
                return row
        return None


class FakeAuth:
    def hash_password(self, password: str) -> str:
        return f"hashed::{password}"


@dataclass
class FakeSettings:
    demo_users_password: str = "demo123"
    demo_service_account_api_key: str = "demo-ci-bot-api-key-platform-v2"


@pytest.mark.asyncio
async def test_demo_seed_creates_expected_users() -> None:
    db = FakeDB()
    stats = await _ensure_demo_seed_users(
        db=db,
        auth=FakeAuth(),
        settings=FakeSettings(),
    )

    assert stats == {"created": len(DEMO_HUMAN_USERS) + 1, "updated": 0, "skipped": 0}
    assert "admin.demo@platform.local" in db.users_by_email
    assert "manager.demo@platform.local" in db.users_by_email
    assert "dev.ai.demo@platform.local" in db.users_by_email
    assert "dev.ml.demo@platform.local" in db.users_by_email
    assert "viewer.demo@platform.local" in db.users_by_email
    assert "dev.data-science.demo@platform.local" in db.users_by_email
    assert "dev.backend-api.demo@platform.local" in db.users_by_email
    assert "dev.analytics.demo@platform.local" in db.users_by_email
    assert "dev.rnd.demo@platform.local" in db.users_by_email
    assert DEMO_SERVICE_ACCOUNT_EMAIL in db.users_by_email

    dev_ai = db.users_by_email["dev.ai.demo@platform.local"]
    assert dev_ai["is_service_account"] is False
    assert db.allowed_models_by_user[dev_ai["id"]] == ["HuggingFaceTB/*"]

    service = db.users_by_email[DEMO_SERVICE_ACCOUNT_EMAIL]
    assert service["is_service_account"] is True
    assert service["role"] == DEMO_SERVICE_ACCOUNT_ROLE
    assert service["team"] == DEMO_SERVICE_ACCOUNT_TEAM
    assert db.allowed_models_by_user[service["id"]] == ["HuggingFaceTB/*"]

    dev_data_science = db.users_by_email["dev.data-science.demo@platform.local"]
    assert dev_data_science["team"] == "Data Science"
    assert db.allowed_models_by_user[dev_data_science["id"]] == ["HuggingFaceTB/*"]


@pytest.mark.asyncio
async def test_demo_seed_syncs_existing_accounts() -> None:
    db = FakeDB()
    ai_id = uuid4()
    svc_id = uuid4()
    await db.create_user(
        user_id=ai_id,
        email="dev.ai.demo@platform.local",
        password_hash="old-hash",
        name="Old Name",
        team="wrong-team",
        role="viewer",
        is_service_account=False,
        api_key=None,
    )
    await db.set_allowed_models(user_id=ai_id, patterns=["wrong/*"])

    await db.create_user(
        user_id=svc_id,
        email=DEMO_SERVICE_ACCOUNT_EMAIL,
        password_hash=None,
        name="Old CI",
        team="wrong-team",
        role="viewer",
        is_service_account=True,
        api_key="another-key",
    )
    await db.set_allowed_models(user_id=svc_id, patterns=["wrong/*"])

    stats = await _ensure_demo_seed_users(
        db=db,
        auth=FakeAuth(),
        settings=FakeSettings(),
    )

    assert stats["updated"] >= 2
    dev_ai = db.users_by_email["dev.ai.demo@platform.local"]
    assert dev_ai["role"] == "developer"
    assert dev_ai["team"] == "ai-platform"
    assert db.allowed_models_by_user[dev_ai["id"]] == ["HuggingFaceTB/*"]

    service = db.users_by_email[DEMO_SERVICE_ACCOUNT_EMAIL]
    assert service["role"] == DEMO_SERVICE_ACCOUNT_ROLE
    assert service["team"] == DEMO_SERVICE_ACCOUNT_TEAM
    assert db.allowed_models_by_user[service["id"]] == ["HuggingFaceTB/*"]


@pytest.mark.asyncio
async def test_demo_seed_skips_conflicting_account_types() -> None:
    db = FakeDB()
    manager_spec = DEMO_HUMAN_USERS[0]
    await db.create_user(
        user_id=uuid4(),
        email=manager_spec.email,
        password_hash=None,
        name="Service by mistake",
        team="ai-platform",
        role="developer",
        is_service_account=True,
        api_key="test-api-key",
    )
    await db.create_user(
        user_id=uuid4(),
        email=DEMO_SERVICE_ACCOUNT_EMAIL,
        password_hash="hashed",
        name="Human by mistake",
        team="ai-platform",
        role="viewer",
        is_service_account=False,
        api_key=None,
    )

    stats = await _ensure_demo_seed_users(
        db=db,
        auth=FakeAuth(),
        settings=FakeSettings(),
    )

    assert stats["skipped"] >= 2


@pytest.mark.asyncio
async def test_demo_seed_reuses_service_account_when_api_key_already_exists() -> None:
    db = FakeDB()
    legacy_service_id = uuid4()
    await db.create_user(
        user_id=legacy_service_id,
        email="ci.demo@legacy.local",
        password_hash=None,
        name="Legacy CI",
        team="wrong-team",
        role="viewer",
        is_service_account=True,
        api_key=FakeSettings().demo_service_account_api_key,
    )
    await db.set_allowed_models(user_id=legacy_service_id, patterns=["wrong/*"])

    stats = await _ensure_demo_seed_users(
        db=db,
        auth=FakeAuth(),
        settings=FakeSettings(),
    )

    # Human demo users are created, service account is reused instead of duplicate insert.
    assert stats["created"] == len(DEMO_HUMAN_USERS)
    reused = db.users_by_email["ci.demo@legacy.local"]
    assert reused["id"] == legacy_service_id
    assert reused["role"] == DEMO_SERVICE_ACCOUNT_ROLE
    assert reused["team"] == DEMO_SERVICE_ACCOUNT_TEAM
    assert db.allowed_models_by_user[legacy_service_id] == ["HuggingFaceTB/*"]
