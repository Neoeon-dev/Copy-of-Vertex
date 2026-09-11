"""Application configuration.

All values can be overridden via environment variables or a .env file.
Secrets (database passwords, API keys) must never be committed to the repo.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # PostgreSQL connection (matches docker-compose defaults).
    database_url: str = (
        "postgresql+psycopg2://mailtrace:mailtrace@localhost:5432/mailtrace"
    )

    # Hard cap on uploaded .eml files, in megabytes. Every uploaded email is
    # treated as hostile input; this bounds memory usage during parsing.
    max_upload_size_mb: int = 10

    # Offline demo mode: external intelligence lookups are replaced by
    # deterministic fixtures. Core parsing/forensics stay real.
    demo_mode: bool = False


settings = Settings()