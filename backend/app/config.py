"""Application configuration."""

from functools import lru_cache
from typing import Optional

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:  # pragma: no cover - exercised only before dependencies are installed.
    BaseSettings = object  # type: ignore
    SettingsConfigDict = dict  # type: ignore


class Settings(BaseSettings):
    app_name: str = "VulnSage AI"
    environment: str = "local"
    database_url: str = "postgresql+psycopg://vulnsage:vulnsage@localhost:5432/vulnsage"
    osv_api_url: str = "https://api.osv.dev/v1/query"
    osv_timeout_seconds: int = 20
    log_level: str = "INFO"

    if BaseSettings is not object:
        model_config = SettingsConfigDict(
            env_file=".env",
            env_prefix="VULNSAGE_",
            extra="ignore",
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()


def get_database_url(override: Optional[str] = None) -> str:
    return override or get_settings().database_url

