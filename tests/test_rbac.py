import pytest

from app.rbac import (
    get_default_team_role_templates,
    get_permissions,
    is_model_allowed,
    normalize_model_patterns,
    normalize_scopes,
)


def test_permissions_matrix_core_rules() -> None:
    admin_permissions = set(get_permissions("admin"))
    developer_permissions = set(get_permissions("developer"))
    manager_permissions = set(get_permissions("manager"))
    viewer_permissions = set(get_permissions("viewer"))

    assert "deployments:create" in admin_permissions
    assert "deployments:create" in developer_permissions
    assert "audit:read" in manager_permissions
    assert "allowed_models:manage" in manager_permissions
    assert "users:manage" not in developer_permissions
    assert "users:manage" not in viewer_permissions


def test_normalize_model_patterns_removes_duplicates_and_blanks() -> None:
    patterns = ["HuggingFaceTB/*", "", "  ", "HuggingFaceTB/*", "meta-llama/*"]
    normalized = normalize_model_patterns(patterns)

    assert normalized == ["HuggingFaceTB/*", "meta-llama/*"]


def test_is_model_allowed_for_admin_and_patterns() -> None:
    assert is_model_allowed("admin", "any/model", []) is True

    allowed_patterns = ["HuggingFaceTB/*", "meta-llama/Llama-3.2-1B-Instruct"]
    assert is_model_allowed("developer", "HuggingFaceTB/SmolLM2-135M-Instruct", allowed_patterns)
    assert is_model_allowed("developer", "meta-llama/Llama-3.2-1B-Instruct", allowed_patterns)
    assert not is_model_allowed("developer", "mistralai/Mistral-7B-Instruct", allowed_patterns)


def test_normalize_scopes_deduplicates_and_validates() -> None:
    scopes = normalize_scopes(
        ["deployments:read", "deployments:read", " custom:scope_1 ", "AUDIT:WRITE"]
    )
    assert scopes == ["deployments:read", "custom:scope_1", "audit:write"]

    with pytest.raises(ValueError):
        normalize_scopes(["bad scope with spaces"])


def test_default_team_role_templates_have_scopes() -> None:
    templates = get_default_team_role_templates()
    assert "team_admin" in templates
    assert "team_operator" in templates
    assert "team_inference" in templates
    assert "team_viewer" in templates
    assert templates["team_admin"]["scopes"]
