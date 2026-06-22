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

    upload_dir: str = "uploads"
    max_upload_size_mb: int = 50
    max_zip_files: int = 5000

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def clerk_enabled(self) -> bool:
        return bool(self.clerk_secret_key and self.clerk_jwks_url)


@lru_cache
def get_settings() -> Settings:
    return Settings()
