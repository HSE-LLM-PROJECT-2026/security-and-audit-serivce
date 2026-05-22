import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from jose import ExpiredSignatureError, JWTError, jwt
from passlib.context import CryptContext

from app.config import Settings
from app.rbac import get_permissions, normalize_scopes


class AuthError(Exception):
    def __init__(self, message: str, *, status_code: int = 401):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


@dataclass
class AuthPrincipal:
    user_id: UUID
    email: str
    name: str
    team: str
    role: str
    is_service_account: bool
    project_key: str
    project_roles: list[str]
    project_scopes: list[str]
    team_roles: list[str]
    team_scopes: list[str]
    permissions: list[str]
    allowed_models: list[str]


class AuthService:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @property
    def access_expires_in_seconds(self) -> int:
        return max(1, int(self._settings.jwt_expiration_minutes * 60))

    def hash_password(self, password: str) -> str:
        return self._pwd_context.hash(password)

    def verify_password(self, plain_password: str, password_hash: str | None) -> bool:
        if not password_hash:
            return False
        return self._pwd_context.verify(plain_password, password_hash)

    def generate_api_key(self) -> str:
        return secrets.token_urlsafe(48)

    def create_access_token(self, *, user: dict[str, Any]) -> str:
        return self._create_token(user=user, token_type="access")

    def create_refresh_token(self, *, user: dict[str, Any]) -> str:
        return self._create_token(user=user, token_type="refresh")

    async def authenticate_user(
        self, *, email: str, password: str, db: Any
    ) -> dict[str, Any] | None:
        user = await db.get_user_by_email(email)
        if user is None:
            return None
        if user["is_service_account"]:
            return None
        if not self.verify_password(password, user.get("password_hash")):
            return None
        return user

    async def resolve_access_or_api_key(self, *, token: str, db: Any) -> AuthPrincipal:
        try:
            payload = self._decode_token(token=token, expected_type="access")
            user = await self._load_user_from_payload(payload=payload, db=db)
        except ExpiredSignatureError as exc:
            raise AuthError("Access token has expired.") from exc
        except JWTError:
            user = await db.get_user_by_api_key(token)
            if user is None:
                raise AuthError("Invalid authentication token.")

        return await self._build_principal(user=user, db=db)

    async def resolve_refresh_token(self, *, token: str, db: Any) -> AuthPrincipal:
        try:
            payload = self._decode_token(token=token, expected_type="refresh")
        except ExpiredSignatureError as exc:
            raise AuthError("Refresh token has expired.") from exc
        except JWTError as exc:
            raise AuthError("Invalid refresh token.") from exc

        user = await self._load_user_from_payload(payload=payload, db=db)
        if user["is_service_account"]:
            raise AuthError("Service accounts cannot use refresh tokens.")
        return await self._build_principal(user=user, db=db)

    async def _build_principal(self, *, user: dict[str, Any], db: Any) -> AuthPrincipal:
        allowed_models = await db.get_allowed_models(user_id=user["id"])
        project_roles, project_scopes = await db.get_user_project_role_scopes(
            user_id=user["id"],
            project_key=self._settings.project_key,
        )
        team_roles, team_scopes = await db.get_user_team_role_scopes(
            user_id=user["id"],
            team_name=user["team"],
        )
        normalized_project_scopes = sorted(set(normalize_scopes(project_scopes)))
        normalized_team_scopes = sorted(set(normalize_scopes(team_scopes)))
        effective_permissions = sorted(
            set(get_permissions(user["role"]))
            | set(normalized_project_scopes)
            | set(normalized_team_scopes)
        )
        return AuthPrincipal(
            user_id=user["id"],
            email=user["email"],
            name=user["name"],
            team=user["team"],
            role=user["role"],
            is_service_account=user["is_service_account"],
            project_key=self._settings.project_key,
            project_roles=project_roles,
            project_scopes=normalized_project_scopes,
            team_roles=team_roles,
            team_scopes=normalized_team_scopes,
            permissions=effective_permissions,
            allowed_models=allowed_models,
        )

    def _decode_token(self, *, token: str, expected_type: str) -> dict[str, Any]:
        payload = jwt.decode(
            token,
            self._settings.jwt_secret,
            algorithms=[self._settings.jwt_algorithm],
        )

        token_type = str(payload.get("type") or "").strip().lower()
        if token_type != expected_type:
            raise JWTError(f"Unexpected token type: {token_type!r}.")

        return payload

    async def _load_user_from_payload(self, *, payload: dict[str, Any], db: Any) -> dict[str, Any]:
        raw_user_id = payload.get("sub")
        try:
            user_id = UUID(str(raw_user_id))
        except (TypeError, ValueError) as exc:
            raise AuthError("Token payload is invalid.") from exc

        user = await db.get_user_by_id(user_id=user_id)
        if user is None:
            raise AuthError("User from token does not exist.")
        return user

    def _create_token(self, *, user: dict[str, Any], token_type: str) -> str:
        now = datetime.now(timezone.utc)
        if token_type == "access":
            exp = now + timedelta(minutes=self._settings.jwt_expiration_minutes)
        elif token_type == "refresh":
            exp = now + timedelta(hours=self._settings.refresh_token_expiration_hours)
        else:
            raise ValueError(f"Unsupported token type: {token_type}")

        payload = {
            "sub": str(user["id"]),
            "email": user["email"],
            "team": user.get("team"),
            "role": user["role"],
            "type": token_type,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
        }

        return jwt.encode(
            payload,
            self._settings.jwt_secret,
            algorithm=self._settings.jwt_algorithm,
        )
