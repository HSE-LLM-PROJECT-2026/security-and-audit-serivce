from fnmatch import fnmatchcase
import re
from typing import Literal, cast
from uuid import UUID

RoleLiteral = Literal["admin", "developer", "manager", "viewer"]
SCOPE_RE = re.compile(r"^[a-z0-9][a-z0-9:_-]{1,127}$")

ROLE_PERMISSIONS: dict[RoleLiteral, set[str]] = {
    "admin": {
        "deployments:create",
        "deployments:delete:any",
        "deployments:read",
        "traffic_routes:read",
        "traffic_routes:manage",
        "users:manage",
        "roles:manage",
        "audit:read",
        "audit:write",
        "allowed_models:manage",
    },
    "developer": {
        "deployments:create",
        "deployments:delete:own",
        "deployments:read",
        "traffic_routes:read",
        "traffic_routes:manage",
        "audit:write",
    },
    "manager": {
        "deployments:read",
        "traffic_routes:read",
        "traffic_routes:manage",
        "audit:read",
        "audit:write",
        "allowed_models:manage",
    },
    "viewer": {
        "deployments:read",
        "traffic_routes:read",
    },
}

TEAM_DEFAULT_ROLE_TEMPLATES: dict[str, dict[str, object]] = {
    "manager": {
        "description": "Team manager: manage team roles and full deployment operations for team resources.",
        "scopes": [
            "teams:manage",
            "deployments:read",
            "deployments:create",
            "deployments:delete:own",
            "deployments:manage:any",
            "deployments:inference:any",
            "traffic_routes:read",
            "traffic_routes:manage",
        ],
    },
    "developer": {
        "description": "Team developer: create/manage deployments and run inference for team resources.",
        "scopes": [
            "deployments:read",
            "deployments:create",
            "deployments:delete:own",
            "deployments:manage:any",
            "deployments:inference:any",
            "traffic_routes:read",
            "traffic_routes:manage",
        ],
    },
    "viewer": {
        "description": "Team viewer: read-only access for team resources.",
        "scopes": [
            "deployments:read",
            "traffic_routes:read",
        ],
    },
    # Backward-compatible aliases for previously seeded environments.
    "team_admin": {
        "description": "Legacy alias of manager role.",
        "scopes": [
            "teams:manage",
            "deployments:read",
            "deployments:create",
            "deployments:delete:own",
            "deployments:manage:any",
            "deployments:inference:any",
            "traffic_routes:read",
            "traffic_routes:manage",
        ],
    },
    "team_operator": {
        "description": "Legacy alias of developer role.",
        "scopes": [
            "deployments:read",
            "deployments:create",
            "deployments:delete:own",
            "deployments:manage:any",
            "deployments:inference:any",
            "traffic_routes:read",
            "traffic_routes:manage",
        ],
    },
    "team_inference": {
        "description": "Legacy inference-only role.",
        "scopes": [
            "deployments:read",
            "deployments:inference:any",
            "traffic_routes:read",
        ],
    },
    "team_viewer": {
        "description": "Legacy alias of viewer role.",
        "scopes": [
            "deployments:read",
            "traffic_routes:read",
        ],
    },
}


def normalize_role(raw_role: str) -> RoleLiteral:
    role = str(raw_role or "").strip().lower()
    if role not in ROLE_PERMISSIONS:
        raise ValueError(
            "Unsupported role. Allowed roles: admin, developer, manager, viewer."
        )
    return cast(RoleLiteral, role)


def get_permissions(role: str) -> list[str]:
    normalized = normalize_role(role)
    return sorted(ROLE_PERMISSIONS[normalized])


def has_permission(role: str, permission: str) -> bool:
    normalized = normalize_role(role)
    return permission in ROLE_PERMISSIONS[normalized]


def can_read_audit(role: str) -> bool:
    return has_permission(role, "audit:read")


def can_manage_users(role: str) -> bool:
    return has_permission(role, "users:manage")


def can_manage_roles(role: str) -> bool:
    return has_permission(role, "roles:manage")


def can_manage_allowed_models(role: str) -> bool:
    return has_permission(role, "allowed_models:manage")


def can_delete_deployment(role: str, *, actor_user_id: UUID, owner_user_id: UUID) -> bool:
    normalized = normalize_role(role)
    if normalized == "admin":
        return True
    if normalized == "developer":
        return actor_user_id == owner_user_id
    return False


def normalize_model_patterns(patterns: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for item in patterns:
        pattern = str(item or "").strip()
        if not pattern:
            continue
        if pattern in seen:
            continue
        seen.add(pattern)
        result.append(pattern)
    return result


def normalize_scopes(scopes: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for raw_scope in scopes:
        scope = str(raw_scope or "").strip().lower()
        if not scope:
            continue
        if not SCOPE_RE.match(scope):
            raise ValueError(
                "Invalid scope format. Use lowercase alphanumeric scope tokens "
                "with separators ':', '_' or '-'."
            )
        if scope in seen:
            continue
        seen.add(scope)
        result.append(scope)
    return result


def get_default_team_role_templates() -> dict[str, dict[str, object]]:
    templates: dict[str, dict[str, object]] = {}
    for role_name, raw_template in TEAM_DEFAULT_ROLE_TEMPLATES.items():
        scopes_raw = raw_template.get("scopes") if isinstance(raw_template, dict) else []
        scopes = normalize_scopes(list(scopes_raw or []))
        description_raw = raw_template.get("description") if isinstance(raw_template, dict) else None
        description = str(description_raw).strip() if description_raw is not None else None
        templates[role_name] = {
            "description": description or None,
            "scopes": scopes,
        }
    return templates


def is_model_allowed(role: str, model_name: str, allowed_patterns: list[str]) -> bool:
    normalized_role = normalize_role(role)
    if normalized_role == "admin":
        return True

    normalized_model = str(model_name or "").strip()
    if not normalized_model:
        return False

    for pattern in normalize_model_patterns(allowed_patterns):
        if pattern == "*":
            return True
        if fnmatchcase(normalized_model, pattern):
            return True
    return False
