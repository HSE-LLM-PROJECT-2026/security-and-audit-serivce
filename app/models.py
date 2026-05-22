from datetime import datetime
import re
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.rbac import RoleLiteral, normalize_scopes

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+$")


def _normalize_email(value: str, *, field_name: str = "email") -> str:
    text = str(value or "").strip().lower()
    if not text:
        raise ValueError(f"{field_name} must be non-empty.")
    if not EMAIL_RE.match(text):
        raise ValueError(f"{field_name} must be a valid email-like value.")
    return text


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str
    password: str = Field(..., min_length=3)
    name: str = Field(..., min_length=1)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return _normalize_email(value, field_name="email")

    @field_validator("name", mode="before")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("name must be non-empty.")
        return text


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str
    password: str = Field(..., min_length=1)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return _normalize_email(value, field_name="email")


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(..., min_length=1)


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str | None = None


class UserResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    email: str
    name: str
    team: str
    role: RoleLiteral
    is_service_account: bool
    created_at: datetime
    updated_at: datetime

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return _normalize_email(value, field_name="email")


class TokenPairResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    user: UserResponse


class AccessTokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int


class VerifyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    email: str
    team: str
    role: RoleLiteral
    is_service_account: bool
    permissions: list[str]
    allowed_models: list[str]
    project_key: str
    project_roles: list[str]
    project_scopes: list[str]
    team_roles: list[str]
    team_scopes: list[str]

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return _normalize_email(value, field_name="email")


class UpdateUserRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: RoleLiteral


class ProjectRoleUpsertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scopes: list[str] = Field(default_factory=list)
    description: str | None = None

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: list[str]) -> list[str]:
        return normalize_scopes(value)

    @field_validator("description", mode="before")
    @classmethod
    def normalize_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


class ProjectRoleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_key: str
    role_name: str
    scopes: list[str]
    description: str | None = None
    created_at: datetime
    updated_at: datetime


class TeamCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    team: str = Field(..., min_length=1)
    description: str | None = None

    @field_validator("team", mode="before")
    @classmethod
    def normalize_team(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("team must be non-empty.")
        return text

    @field_validator("description", mode="before")
    @classmethod
    def normalize_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


class TeamResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    team: str
    description: str | None = None
    created_at: datetime
    updated_at: datetime


class TeamRoleUpsertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scopes: list[str] = Field(default_factory=list)
    description: str | None = None

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: list[str]) -> list[str]:
        return normalize_scopes(value)

    @field_validator("description", mode="before")
    @classmethod
    def normalize_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None


class TeamRoleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    team: str
    role_name: str
    scopes: list[str]
    description: str | None = None
    is_default: bool
    created_at: datetime
    updated_at: datetime


class UserProjectRolesUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_names: list[str] = Field(default_factory=list)

    @field_validator("role_names", mode="before")
    @classmethod
    def normalize_role_names(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("role_names must be a list.")
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw_item in value:
            token = str(raw_item or "").strip().lower()
            if not token:
                continue
            if token in seen:
                continue
            seen.add(token)
            cleaned.append(token)
        return cleaned


class UserProjectRolesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    project_key: str
    role_names: list[str]
    effective_scopes: list[str]


class UserTeamRolesUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_names: list[str] = Field(default_factory=list)

    @field_validator("role_names", mode="before")
    @classmethod
    def normalize_role_names(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ValueError("role_names must be a list.")
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw_item in value:
            token = str(raw_item or "").strip().lower()
            if not token:
                continue
            if token in seen:
                continue
            seen.add(token)
            cleaned.append(token)
        return cleaned


class UserTeamRolesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    team: str
    role_names: list[str]
    effective_scopes: list[str]


class UpdateUserTeamRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    team: str = Field(..., min_length=1)

    @field_validator("team", mode="before")
    @classmethod
    def normalize_team(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("team must be non-empty.")
        return text


class ServiceAccountCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str
    name: str = Field(..., min_length=1)
    team: str | None = Field(default=None, min_length=1)
    role: RoleLiteral = "developer"
    allowed_models: list[str] = Field(default_factory=list)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        return _normalize_email(value, field_name="email")

    @field_validator("name", mode="before")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("name must be non-empty.")
        return text

    @field_validator("team", mode="before")
    @classmethod
    def normalize_team(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            raise ValueError("team must be non-empty.")
        return text


class ServiceAccountCreateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user: UserResponse
    api_key: str


class AllowedModelsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID
    allowed_models: list[str]


class AllowedModelsUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed_models: list[str]


class AuditEventCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID | None = None
    user_email: str | None = None
    is_service_account: bool = False
    action: str = Field(..., min_length=1)
    resource_type: str | None = None
    resource_id: str | None = None
    details: dict[str, Any] | None = None
    result: Literal["success", "failure"] = "success"
    ip_address: str | None = None
    timestamp: datetime | None = None

    @field_validator("action", mode="before")
    @classmethod
    def normalize_action(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("action must be non-empty.")
        return text

    @field_validator("resource_type", "resource_id", "ip_address", mode="before")
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @field_validator("user_email", mode="before")
    @classmethod
    def normalize_user_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalize_email(value, field_name="user_email")


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID
    user_id: UUID | None = None
    user_email: str | None = None
    is_service_account: bool
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    details: dict[str, Any] | None = None
    result: Literal["success", "failure"]
    ip_address: str | None = None
    created_at: datetime


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ok", "degraded"]
    details: dict[str, Any] | None = None
