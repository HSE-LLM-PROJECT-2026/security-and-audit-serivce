import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import asyncpg

from app.config import Settings
from app.rbac import get_default_team_role_templates, normalize_scopes


class Database:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._pool: asyncpg.Pool | None = None
        self._logger = logging.getLogger("security_audit.database")

    async def connect(self) -> None:
        self._pool = await asyncpg.create_pool(
            dsn=self._settings.postgres_dsn,
            min_size=1,
            max_size=10,
            command_timeout=30,
        )
        self._logger.info("Connected to PostgreSQL at %s", self._settings.postgres_host)

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._logger.info("PostgreSQL connection pool closed.")

    async def init_schema(self) -> None:
        pool = self._require_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT,
                    name TEXT NOT NULL,
                    team TEXT NOT NULL DEFAULT 'default',
                    role TEXT NOT NULL DEFAULT 'viewer',
                    is_service_account BOOLEAN NOT NULL DEFAULT FALSE,
                    api_key TEXT UNIQUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    CONSTRAINT users_role_check
                        CHECK (role IN ('admin', 'developer', 'manager', 'viewer')),
                    CONSTRAINT users_auth_check
                        CHECK (
                            (is_service_account = FALSE AND password_hash IS NOT NULL AND api_key IS NULL)
                            OR
                            (is_service_account = TRUE AND password_hash IS NULL AND api_key IS NOT NULL)
                        )
                );
                """
            )
            await conn.execute(
                """
                ALTER TABLE users
                ADD COLUMN IF NOT EXISTS team TEXT NOT NULL DEFAULT 'default';
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS allowed_models (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    model_pattern TEXT NOT NULL,
                    UNIQUE (user_id, model_pattern)
                );
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS teams (
                    id UUID PRIMARY KEY,
                    team_name TEXT NOT NULL UNIQUE,
                    description TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS team_roles (
                    id UUID PRIMARY KEY,
                    team_name TEXT NOT NULL,
                    role_name TEXT NOT NULL,
                    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
                    description TEXT,
                    is_default BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (team_name, role_name)
                );
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_team_roles (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    team_name TEXT NOT NULL,
                    role_name TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (user_id, team_name, role_name)
                );
                """
            )
            await conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_teams_team_name
                ON teams (team_name);
                """
            )
            await conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_team_roles_team_name
                ON team_roles (team_name);
                """
            )
            await conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_user_team_roles_user_team
                ON user_team_roles (user_id, team_name);
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS project_roles (
                    id UUID PRIMARY KEY,
                    project_key TEXT NOT NULL,
                    role_name TEXT NOT NULL,
                    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
                    description TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (project_key, role_name)
                );
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS user_project_roles (
                    id UUID PRIMARY KEY,
                    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    project_key TEXT NOT NULL,
                    role_name TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    UNIQUE (user_id, project_key, role_name)
                );
                """
            )
            await conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_project_roles_project_key
                ON project_roles (project_key);
                """
            )
            await conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_user_project_roles_user_project
                ON user_project_roles (user_id, project_key);
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    id UUID PRIMARY KEY,
                    user_id UUID,
                    user_email TEXT,
                    is_service_account BOOLEAN NOT NULL DEFAULT FALSE,
                    action TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id TEXT,
                    details JSONB,
                    result TEXT NOT NULL CHECK (result IN ('success', 'failure')),
                    ip_address TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                """
            )
            await conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
                ON audit_log (created_at DESC);
                """
            )
            await conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_audit_log_user_id
                ON audit_log (user_id);
                """
            )
        await self._ensure_all_teams_initialized()
        self._logger.info("Database schema initialized.")

    async def ensure_admin_user(
        self,
        *,
        admin_email: str,
        admin_password_hash: str,
        admin_name: str,
        admin_team: str,
    ) -> bool:
        existing = await self.get_user_by_email(admin_email)
        if existing is not None:
            return False

        try:
            await self.create_user(
                user_id=uuid4(),
                email=admin_email,
                password_hash=admin_password_hash,
                name=admin_name,
                team=admin_team,
                role="admin",
                is_service_account=False,
                api_key=None,
            )
            return True
        except asyncpg.UniqueViolationError:
            return False

    async def ensure_team(
        self,
        *,
        team_name: str,
        description: str | None,
    ) -> dict[str, Any]:
        normalized_team = self._normalize_team_name(team_name)
        normalized_description = self._normalize_optional_text(description)
        pool = self._require_pool()
        async with pool.acquire() as conn:
            team = await self._ensure_team_conn(
                conn=conn,
                team_name=normalized_team,
                description=normalized_description,
            )
        return team

    async def get_team(self, *, team_name: str) -> dict[str, Any] | None:
        normalized_team = self._normalize_team_name(team_name)
        query = """
        SELECT id, team_name, description, created_at, updated_at
        FROM teams
        WHERE LOWER(team_name) = LOWER($1)
        """
        pool = self._require_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, normalized_team)
        if row is None:
            return None
        return self._team_row_to_dict(row)

    async def list_teams(self) -> list[dict[str, Any]]:
        query = """
        SELECT id, team_name, description, created_at, updated_at
        FROM teams
        ORDER BY LOWER(team_name) ASC
        """
        pool = self._require_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query)
        return [self._team_row_to_dict(row) for row in rows]

    async def get_team_role(
        self,
        *,
        team_name: str,
        role_name: str,
    ) -> dict[str, Any] | None:
        normalized_team = self._normalize_team_name(team_name)
        normalized_role = self._normalize_role_name(role_name)
        query = """
        SELECT
            id, team_name, role_name, scopes, description, is_default, created_at, updated_at
        FROM team_roles
        WHERE LOWER(team_name) = LOWER($1) AND role_name = $2
        """
        pool = self._require_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, normalized_team, normalized_role)
        if row is None:
            return None
        return self._team_role_row_to_dict(row)

    async def list_team_roles(self, *, team_name: str) -> list[dict[str, Any]]:
        normalized_team = self._normalize_team_name(team_name)
        query = """
        SELECT
            id, team_name, role_name, scopes, description, is_default, created_at, updated_at
        FROM team_roles
        WHERE LOWER(team_name) = LOWER($1)
        ORDER BY role_name ASC
        """
        pool = self._require_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, normalized_team)
        return [self._team_role_row_to_dict(row) for row in rows]

    async def upsert_team_role(
        self,
        *,
        team_name: str,
        role_name: str,
        scopes: list[str],
        description: str | None,
        is_default: bool,
    ) -> dict[str, Any]:
        normalized_team = self._normalize_team_name(team_name)
        normalized_role = self._normalize_role_name(role_name)
        normalized_scopes = normalize_scopes(scopes)
        normalized_description = self._normalize_optional_text(description)
        now = datetime.now(timezone.utc)

        query = """
        INSERT INTO team_roles (
            id, team_name, role_name, scopes, description, is_default, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)
        ON CONFLICT (team_name, role_name)
        DO UPDATE SET
            scopes = EXCLUDED.scopes,
            description = EXCLUDED.description,
            is_default = team_roles.is_default OR EXCLUDED.is_default,
            updated_at = EXCLUDED.updated_at
        RETURNING
            id, team_name, role_name, scopes, description, is_default, created_at, updated_at
        """
        pool = self._require_pool()
        async with pool.acquire() as conn:
            await self._ensure_team_conn(
                conn=conn,
                team_name=normalized_team,
                description=None,
            )
            row = await conn.fetchrow(
                query,
                uuid4(),
                normalized_team,
                normalized_role,
                json.dumps(normalized_scopes),
                normalized_description,
                is_default,
                now,
                now,
            )
        if row is None:
            raise RuntimeError("Failed to upsert team role.")
        return self._team_role_row_to_dict(row)

    async def delete_team_role(
        self,
        *,
        team_name: str,
        role_name: str,
    ) -> bool:
        normalized_team = self._normalize_team_name(team_name)
        normalized_role = self._normalize_role_name(role_name)
        pool = self._require_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    """
                    DELETE FROM user_team_roles
                    WHERE LOWER(team_name) = LOWER($1) AND role_name = $2
                    """,
                    normalized_team,
                    normalized_role,
                )
                deleted = await conn.fetchrow(
                    """
                    DELETE FROM team_roles
                    WHERE LOWER(team_name) = LOWER($1) AND role_name = $2
                    RETURNING id
                    """,
                    normalized_team,
                    normalized_role,
                )
        return deleted is not None

    async def list_user_team_roles(
        self,
        *,
        user_id: UUID,
        team_name: str,
    ) -> list[str]:
        normalized_team = self._normalize_team_name(team_name)
        query = """
        SELECT role_name
        FROM user_team_roles
        WHERE user_id = $1 AND LOWER(team_name) = LOWER($2)
        ORDER BY role_name ASC
        """
        pool = self._require_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, user_id, normalized_team)
        return [str(row["role_name"]) for row in rows]

    async def set_user_team_roles(
        self,
        *,
        user_id: UUID,
        team_name: str,
        role_names: list[str],
    ) -> list[str]:
        normalized_team = self._normalize_team_name(team_name)
        normalized_role_names = sorted(
            {
                self._normalize_role_name(role_name)
                for role_name in role_names
                if str(role_name or "").strip()
            }
        )
        now = datetime.now(timezone.utc)
        pool = self._require_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                await self._ensure_team_conn(
                    conn=conn,
                    team_name=normalized_team,
                    description=None,
                )
                await conn.execute(
                    """
                    DELETE FROM user_team_roles
                    WHERE user_id = $1 AND LOWER(team_name) = LOWER($2)
                    """,
                    user_id,
                    normalized_team,
                )
                for role_name in normalized_role_names:
                    await conn.execute(
                        """
                        INSERT INTO user_team_roles (
                            id, user_id, team_name, role_name, created_at
                        )
                        VALUES ($1, $2, $3, $4, $5)
                        """,
                        uuid4(),
                        user_id,
                        normalized_team,
                        role_name,
                        now,
                    )

        return await self.list_user_team_roles(user_id=user_id, team_name=normalized_team)

    async def get_user_team_role_scopes(
        self,
        *,
        user_id: UUID,
        team_name: str,
    ) -> tuple[list[str], list[str]]:
        normalized_team = self._normalize_team_name(team_name)
        query = """
        SELECT utr.role_name, tr.scopes
        FROM user_team_roles utr
        LEFT JOIN team_roles tr
               ON LOWER(tr.team_name) = LOWER(utr.team_name)
              AND tr.role_name = utr.role_name
        WHERE utr.user_id = $1
          AND LOWER(utr.team_name) = LOWER($2)
        ORDER BY utr.role_name ASC
        """
        pool = self._require_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, user_id, normalized_team)

        role_names: list[str] = []
        scopes_set: set[str] = set()
        for row in rows:
            role_name = str(row["role_name"] or "").strip().lower()
            if not role_name:
                continue
            role_names.append(role_name)
            scopes = row["scopes"]
            if isinstance(scopes, str):
                try:
                    scopes = json.loads(scopes)
                except ValueError:
                    scopes = []
            if not isinstance(scopes, list):
                continue
            for raw_scope in scopes:
                scope = str(raw_scope or "").strip().lower()
                if scope:
                    scopes_set.add(scope)

        role_names = sorted(set(role_names))
        return role_names, sorted(scopes_set)

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
        now = datetime.now(timezone.utc)
        normalized_team = self._normalize_team_name(team)
        query = """
        INSERT INTO users (
            id, email, password_hash, name, team, role,
            is_service_account, api_key, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING
            id, email, password_hash, name, team, role,
            is_service_account, api_key, created_at, updated_at
        """

        pool = self._require_pool()
        async with pool.acquire() as conn:
            await self._ensure_team_conn(conn=conn, team_name=normalized_team, description=None)
            row = await conn.fetchrow(
                query,
                user_id,
                email,
                password_hash,
                name,
                normalized_team,
                role,
                is_service_account,
                api_key,
                now,
                now,
            )
        if row is None:
            raise RuntimeError("Failed to create user.")
        return self._user_row_to_dict(row)

    async def get_user_by_id(self, *, user_id: UUID) -> dict[str, Any] | None:
        query = """
        SELECT
            id, email, password_hash, name, team, role,
            is_service_account, api_key, created_at, updated_at
        FROM users
        WHERE id = $1
        """

        pool = self._require_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, user_id)
        if row is None:
            return None
        return self._user_row_to_dict(row)

    async def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        query = """
        SELECT
            id, email, password_hash, name, team, role,
            is_service_account, api_key, created_at, updated_at
        FROM users
        WHERE LOWER(email) = LOWER($1)
        """

        pool = self._require_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, email)
        if row is None:
            return None
        return self._user_row_to_dict(row)

    async def get_user_by_api_key(self, api_key: str) -> dict[str, Any] | None:
        query = """
        SELECT
            id, email, password_hash, name, team, role,
            is_service_account, api_key, created_at, updated_at
        FROM users
        WHERE is_service_account = TRUE AND api_key = $1
        """

        pool = self._require_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, api_key)
        if row is None:
            return None
        return self._user_row_to_dict(row)

    async def list_users(self) -> list[dict[str, Any]]:
        query = """
        SELECT
            id, email, password_hash, name, team, role,
            is_service_account, api_key, created_at, updated_at
        FROM users
        ORDER BY created_at DESC
        """

        pool = self._require_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query)
        return [self._user_row_to_dict(row) for row in rows]

    async def update_user_role(self, *, user_id: UUID, role: str) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc)
        query = """
        UPDATE users
        SET role = $2, updated_at = $3
        WHERE id = $1
        RETURNING
            id, email, password_hash, name, team, role,
            is_service_account, api_key, created_at, updated_at
        """

        pool = self._require_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, user_id, role, now)
        if row is None:
            return None
        return self._user_row_to_dict(row)

    async def update_user_team(self, *, user_id: UUID, team: str) -> dict[str, Any] | None:
        now = datetime.now(timezone.utc)
        normalized_team = self._normalize_team_name(team)
        query = """
        UPDATE users
        SET team = $2, updated_at = $3
        WHERE id = $1
        RETURNING
            id, email, password_hash, name, team, role,
            is_service_account, api_key, created_at, updated_at
        """

        pool = self._require_pool()
        async with pool.acquire() as conn:
            await self._ensure_team_conn(conn=conn, team_name=normalized_team, description=None)
            row = await conn.fetchrow(query, user_id, normalized_team, now)
        if row is None:
            return None
        return self._user_row_to_dict(row)

    async def delete_user(self, *, user_id: UUID) -> bool:
        query = "DELETE FROM users WHERE id = $1 RETURNING id"
        pool = self._require_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, user_id)
        return row is not None

    async def get_project_role(
        self,
        *,
        project_key: str,
        role_name: str,
    ) -> dict[str, Any] | None:
        query = """
        SELECT
            id, project_key, role_name, scopes, description, created_at, updated_at
        FROM project_roles
        WHERE project_key = $1 AND role_name = $2
        """
        pool = self._require_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(query, project_key, role_name)
        if row is None:
            return None
        return self._project_role_row_to_dict(row)

    async def list_project_roles(self, *, project_key: str) -> list[dict[str, Any]]:
        query = """
        SELECT
            id, project_key, role_name, scopes, description, created_at, updated_at
        FROM project_roles
        WHERE project_key = $1
        ORDER BY role_name ASC
        """
        pool = self._require_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, project_key)
        return [self._project_role_row_to_dict(row) for row in rows]

    async def upsert_project_role(
        self,
        *,
        project_key: str,
        role_name: str,
        scopes: list[str],
        description: str | None,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        query = """
        INSERT INTO project_roles (
            id, project_key, role_name, scopes, description, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7)
        ON CONFLICT (project_key, role_name)
        DO UPDATE SET
            scopes = EXCLUDED.scopes,
            description = EXCLUDED.description,
            updated_at = EXCLUDED.updated_at
        RETURNING
            id, project_key, role_name, scopes, description, created_at, updated_at
        """
        pool = self._require_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                query,
                uuid4(),
                project_key,
                role_name,
                json.dumps(scopes),
                description,
                now,
                now,
            )
        if row is None:
            raise RuntimeError("Failed to upsert project role.")
        return self._project_role_row_to_dict(row)

    async def delete_project_role(
        self,
        *,
        project_key: str,
        role_name: str,
    ) -> bool:
        pool = self._require_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    """
                    DELETE FROM user_project_roles
                    WHERE project_key = $1 AND role_name = $2
                    """,
                    project_key,
                    role_name,
                )
                deleted = await conn.fetchrow(
                    """
                    DELETE FROM project_roles
                    WHERE project_key = $1 AND role_name = $2
                    RETURNING id
                    """,
                    project_key,
                    role_name,
                )
        return deleted is not None

    async def list_user_project_roles(
        self,
        *,
        user_id: UUID,
        project_key: str,
    ) -> list[str]:
        query = """
        SELECT role_name
        FROM user_project_roles
        WHERE user_id = $1 AND project_key = $2
        ORDER BY role_name ASC
        """
        pool = self._require_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, user_id, project_key)
        return [str(row["role_name"]) for row in rows]

    async def set_user_project_roles(
        self,
        *,
        user_id: UUID,
        project_key: str,
        role_names: list[str],
    ) -> list[str]:
        pool = self._require_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    """
                    DELETE FROM user_project_roles
                    WHERE user_id = $1 AND project_key = $2
                    """,
                    user_id,
                    project_key,
                )
                for role_name in role_names:
                    await conn.execute(
                        """
                        INSERT INTO user_project_roles (
                            id, user_id, project_key, role_name, created_at
                        )
                        VALUES ($1, $2, $3, $4, $5)
                        """,
                        uuid4(),
                        user_id,
                        project_key,
                        role_name,
                        datetime.now(timezone.utc),
                    )

        return await self.list_user_project_roles(user_id=user_id, project_key=project_key)

    async def get_user_project_role_scopes(
        self,
        *,
        user_id: UUID,
        project_key: str,
    ) -> tuple[list[str], list[str]]:
        query = """
        SELECT upr.role_name, pr.scopes
        FROM user_project_roles upr
        LEFT JOIN project_roles pr
            ON pr.project_key = upr.project_key
           AND pr.role_name = upr.role_name
        WHERE upr.user_id = $1
          AND upr.project_key = $2
        ORDER BY upr.role_name ASC
        """
        pool = self._require_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, user_id, project_key)

        role_names: list[str] = []
        scopes_set: set[str] = set()
        for row in rows:
            role_name = str(row["role_name"] or "").strip().lower()
            if not role_name:
                continue
            role_names.append(role_name)
            scopes = row["scopes"]
            if isinstance(scopes, str):
                try:
                    scopes = json.loads(scopes)
                except ValueError:
                    scopes = []
            if not isinstance(scopes, list):
                continue
            for raw_scope in scopes:
                scope = str(raw_scope or "").strip().lower()
                if scope:
                    scopes_set.add(scope)

        role_names = sorted(set(role_names))
        return role_names, sorted(scopes_set)

    async def get_allowed_models(self, *, user_id: UUID) -> list[str]:
        query = """
        SELECT model_pattern
        FROM allowed_models
        WHERE user_id = $1
        ORDER BY model_pattern ASC
        """

        pool = self._require_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, user_id)
        return [str(row["model_pattern"]) for row in rows]

    async def set_allowed_models(self, *, user_id: UUID, patterns: list[str]) -> list[str]:
        pool = self._require_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("DELETE FROM allowed_models WHERE user_id = $1", user_id)

                for pattern in patterns:
                    await conn.execute(
                        """
                        INSERT INTO allowed_models (id, user_id, model_pattern)
                        VALUES ($1, $2, $3)
                        """,
                        uuid4(),
                        user_id,
                        pattern,
                    )

        return await self.get_allowed_models(user_id=user_id)

    async def create_audit_event(
        self,
        *,
        user_id: UUID | None,
        user_email: str | None,
        is_service_account: bool,
        action: str,
        resource_type: str | None,
        resource_id: str | None,
        details: dict[str, Any] | None,
        result: str,
        ip_address: str | None,
        created_at: datetime | None,
    ) -> dict[str, Any]:
        event_id = uuid4()
        timestamp = created_at or datetime.now(timezone.utc)
        details_json = json.dumps(details) if details is not None else None

        query = """
        INSERT INTO audit_log (
            id, user_id, user_email, is_service_account, action,
            resource_type, resource_id, details, result, ip_address, created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11)
        RETURNING
            id, user_id, user_email, is_service_account, action,
            resource_type, resource_id, details, result, ip_address, created_at
        """

        pool = self._require_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                query,
                event_id,
                user_id,
                user_email,
                is_service_account,
                action,
                resource_type,
                resource_id,
                details_json,
                result,
                ip_address,
                timestamp,
            )
        if row is None:
            raise RuntimeError("Failed to create audit event.")
        return self._audit_row_to_dict(row)

    async def list_audit_events(
        self,
        *,
        user_id: UUID | None,
        action: str | None,
        resource_type: str | None,
        date_from: datetime | None,
        date_to: datetime | None,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        query = """
        SELECT
            id, user_id, user_email, is_service_account, action,
            resource_type, resource_id, details, result, ip_address, created_at
        FROM audit_log
        WHERE 1 = 1
        """
        params: list[Any] = []

        if user_id is not None:
            params.append(user_id)
            query += f" AND user_id = ${len(params)}"

        if action:
            params.append(action)
            query += f" AND action = ${len(params)}"

        if resource_type:
            params.append(resource_type)
            query += f" AND resource_type = ${len(params)}"

        if date_from is not None:
            params.append(date_from)
            query += f" AND created_at >= ${len(params)}"

        if date_to is not None:
            params.append(date_to)
            query += f" AND created_at <= ${len(params)}"

        params.append(limit)
        query += f" ORDER BY created_at DESC LIMIT ${len(params)}"
        params.append(offset)
        query += f" OFFSET ${len(params)}"

        pool = self._require_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        return [self._audit_row_to_dict(row) for row in rows]

    async def ping(self) -> None:
        pool = self._require_pool()
        async with pool.acquire() as conn:
            await conn.execute("SELECT 1")

    async def _ensure_all_teams_initialized(self) -> None:
        required_teams: set[str] = {
            self._normalize_team_name(self._settings.default_user_team),
            self._normalize_team_name(self._settings.admin_team),
        }
        pool = self._require_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT DISTINCT team
                FROM users
                WHERE TRIM(team) <> ''
                """
            )
            for row in rows:
                raw_team = str(row["team"] or "").strip()
                if raw_team:
                    required_teams.add(self._normalize_team_name(raw_team))

            for team_name in sorted(required_teams):
                await self._ensure_team_conn(
                    conn=conn,
                    team_name=team_name,
                    description=None,
                )

    async def _ensure_team_conn(
        self,
        *,
        conn: asyncpg.Connection,
        team_name: str,
        description: str | None,
    ) -> dict[str, Any]:
        normalized_team = self._normalize_team_name(team_name)
        normalized_description = self._normalize_optional_text(description)
        now = datetime.now(timezone.utc)
        row = await conn.fetchrow(
            """
            INSERT INTO teams (id, team_name, description, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (team_name)
            DO UPDATE SET
                description = COALESCE(EXCLUDED.description, teams.description),
                updated_at = CASE
                    WHEN EXCLUDED.description IS NOT NULL
                         AND EXCLUDED.description IS DISTINCT FROM teams.description
                    THEN EXCLUDED.updated_at
                    ELSE teams.updated_at
                END
            RETURNING id, team_name, description, created_at, updated_at
            """,
            uuid4(),
            normalized_team,
            normalized_description,
            now,
            now,
        )
        if row is None:
            raise RuntimeError(f"Failed to ensure team '{normalized_team}'.")

        await self._ensure_default_team_roles_conn(conn=conn, team_name=normalized_team)
        return self._team_row_to_dict(row)

    async def _ensure_default_team_roles_conn(
        self,
        *,
        conn: asyncpg.Connection,
        team_name: str,
    ) -> None:
        templates = get_default_team_role_templates()
        now = datetime.now(timezone.utc)
        for role_name, template in templates.items():
            scopes = normalize_scopes(list(template.get("scopes") or []))
            description_raw = template.get("description")
            description = (
                self._normalize_optional_text(str(description_raw))
                if description_raw is not None
                else None
            )
            await conn.execute(
                """
                INSERT INTO team_roles (
                    id, team_name, role_name, scopes, description, is_default, created_at, updated_at
                )
                VALUES ($1, $2, $3, $4::jsonb, $5, TRUE, $6, $7)
                ON CONFLICT (team_name, role_name) DO NOTHING
                """,
                uuid4(),
                team_name,
                role_name,
                json.dumps(scopes),
                description,
                now,
                now,
            )

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise RuntimeError("Database connection pool is not initialized.")
        return self._pool

    @staticmethod
    def _normalize_optional_text(value: str | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _normalize_team_name(value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("team_name must be non-empty.")
        if len(text) > 128:
            raise ValueError("team_name is too long (max 128 characters).")
        return text

    @staticmethod
    def _normalize_role_name(value: str) -> str:
        token = str(value or "").strip().lower()
        if not token:
            raise ValueError("role_name must be non-empty.")
        if len(token) > 64:
            raise ValueError("role_name is too long (max 64 characters).")
        allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-_")
        if any(ch not in allowed for ch in token):
            raise ValueError(
                "role_name can contain only lowercase letters, digits, '-' or '_'."
            )
        return token

    @staticmethod
    def _user_row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
        return dict(row)

    @staticmethod
    def _team_row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
        data = dict(row)
        team_name = data.pop("team_name", None)
        data["team"] = str(team_name or "")
        return data

    @staticmethod
    def _team_role_row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
        data = dict(row)
        team_name = data.pop("team_name", None)
        data["team"] = str(team_name or "")
        scopes = data.get("scopes")
        if isinstance(scopes, str):
            data["scopes"] = json.loads(scopes)
        return data

    @staticmethod
    def _project_role_row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
        data = dict(row)
        scopes = data.get("scopes")
        if isinstance(scopes, str):
            data["scopes"] = json.loads(scopes)
        return data

    @staticmethod
    def _audit_row_to_dict(row: asyncpg.Record) -> dict[str, Any]:
        data = dict(row)
        details = data.get("details")
        if isinstance(details, str):
            data["details"] = json.loads(details)
        return data
