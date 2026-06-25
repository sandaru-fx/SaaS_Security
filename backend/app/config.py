from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "AI Software Auditor API"
    app_version: str = "0.1.0"
    environment: str = "development"

    database_url: str = "postgresql+psycopg://auditor:auditor_secret@localhost:5432/auditor_db"
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"

    secret_key: str = "dev-secret-key"
    cors_origins: str = "http://localhost:3000"

    clerk_secret_key: str = ""
    clerk_jwks_url: str = ""
    clerk_jwt_issuer: str = ""

    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = ""

    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"

    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_pro: str = ""
    stripe_price_team: str = ""
    frontend_url: str = "http://localhost:3000"

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_use_tls: bool = True

    github_webhook_secret: str = ""

    zap_enabled: bool = False
    zap_api_url: str = ""
    zap_api_key: str = ""
    zap_timeout_seconds: int = 600

    upload_dir: str = "uploads"
    max_upload_size_mb: int = 150
    max_zip_files: int = 10000
    free_max_upload_size_mb: int = 100
    free_max_zip_files: int = 8000
    allow_local_project_paths: bool = False
    local_projects_root: str = ""

    storage_backend: str = "local"
    s3_bucket: str = ""
    s3_region: str = "us-east-1"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""

    sentry_dsn: str = ""

    @property
    def local_paths_enabled(self) -> bool:
        return self.allow_local_project_paths or self.environment == "development"

    @field_validator("database_url", mode="before")
    @classmethod
    def normalize_database_url(cls, value: str) -> str:
        """Accept Neon/Render `postgresql://` URLs for SQLAlchemy async."""
        if not isinstance(value, str):
            return value
        if value.startswith("postgres://"):
            return "postgresql+psycopg://" + value[len("postgres://") :]
        if value.startswith("postgresql://"):
            return "postgresql+psycopg://" + value[len("postgresql://") :]
        return value

    @property
    def sync_database_url(self) -> str:
        if self.database_url.startswith("sqlite+aiosqlite"):
            return self.database_url.replace("sqlite+aiosqlite", "sqlite", 1)
        return self.database_url

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def clerk_enabled(self) -> bool:
        return bool(self.clerk_secret_key and self.clerk_jwks_url)

    @property
    def ai_enabled(self) -> bool:
        return bool(self.openai_api_key or self.gemini_api_key)

    @property
    def stripe_enabled(self) -> bool:
        return bool(self.stripe_secret_key and self.stripe_price_pro)


@lru_cache
def get_settings() -> Settings:
    return Settings()
