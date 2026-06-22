from functools import lru_cache

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

    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_pro: str = ""
    stripe_price_team: str = ""
    frontend_url: str = "http://localhost:3000"

    upload_dir: str = "uploads"
    max_upload_size_mb: int = 50
    max_zip_files: int = 5000

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def clerk_enabled(self) -> bool:
        return bool(self.clerk_secret_key and self.clerk_jwks_url)

    @property
    def ai_enabled(self) -> bool:
        return bool(self.openai_api_key)

    @property
    def stripe_enabled(self) -> bool:
        return bool(self.stripe_secret_key and self.stripe_price_pro)


@lru_cache
def get_settings() -> Settings:
    return Settings()
