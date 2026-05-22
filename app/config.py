import urllib.parse
from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    postgres_host: str = "postgresql.hse-llm-project.svc.cluster.local"
    postgres_port: int = 5432
    postgres_db: str = "default"
    postgres_user: str = "admin"
    postgres_password: str = "admin"

    jwt_secret: str = "change-me"
    jwt_algorithm: str = "HS256"
    jwt_expiration_minutes: int = 30
    refresh_token_expiration_hours: int = 168

    admin_email: str = "admin@platform.local"
    admin_password: str = "admin"
    admin_name: str = "Platform Administrator"
    admin_team: str = "platform-admin"
    default_user_team: str = "default"
    project_key: str = "default"
    demo_users_enabled: bool = False
    demo_users_password: str = "demo123"
    demo_service_account_api_key: str = "demo-ci-bot-api-key-platform-v2"
    short_read_cache_ttl_seconds: float = 10.0
    short_read_cache_max_entries: int = 512

    cors_origins: str = "*"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=str(Path(__file__).resolve().parent.parent / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("jwt_secret", mode="before")
    @classmethod
    def validate_jwt_secret(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("JWT_SECRET must be non-empty.")
        return text

    @field_validator("jwt_algorithm", mode="before")
    @classmethod
    def validate_jwt_algorithm(cls, value: str) -> str:
        text = str(value or "").strip().upper()
        return text or "HS256"

    @field_validator(
        "jwt_expiration_minutes",
        "refresh_token_expiration_hours",
        "short_read_cache_max_entries",
        mode="before",
    )
    @classmethod
    def validate_positive_int(cls, value: int | str) -> int:
        parsed = int(value)
        if parsed <= 0:
            raise ValueError("Value must be greater than zero.")
        return parsed

    @field_validator("short_read_cache_ttl_seconds", mode="before")
    @classmethod
    def validate_positive_float(cls, value: float | str) -> float:
        parsed = float(value)
        if parsed <= 0:
            raise ValueError("short_read_cache_ttl_seconds must be greater than zero.")
        return parsed

    @field_validator(
        "admin_name",
        "admin_team",
        "default_user_team",
        "project_key",
        "demo_users_password",
        "demo_service_account_api_key",
        mode="before",
    )
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("Value must be non-empty.")
        return text

    @property
    def postgres_dsn(self) -> str:
        user = urllib.parse.quote_plus(self.postgres_user)
        password = urllib.parse.quote_plus(self.postgres_password)
        return (
            f"postgresql://{user}:{password}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def cors_allow_origins(self) -> list[str]:
        raw = (self.cors_origins or "*").strip()
        if raw == "*":
            return ["*"]
        values = [item.strip() for item in raw.split(",")]
        cleaned = [item for item in values if item]
        return cleaned or ["*"]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
