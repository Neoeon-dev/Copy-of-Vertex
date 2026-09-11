"""Application configuration.

All values can be overridden via environment variables or a .env file.
Secrets (database passwords, API keys) must never be committed to the repo.
"""
from typing import List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Environment mode (development, staging, production)
    environment: str = "development"

    # PostgreSQL connection (matches docker-compose defaults).
    database_url: str = (
        "postgresql+psycopg2://mailtrace:mailtrace@localhost:5432/mailtrace"
    )

    # Application secret key for session signing and future JWT authentication
    secret_key: str = "mailtrace-insecure-dev-secret-key-change-in-production"

    # Allowed CORS origins for frontend access
    cors_origins: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:80",
        "http://localhost",
        "https://copy-of-vertex.vercel.app",
    ]

    # Hard cap on uploaded .eml files, in megabytes. Every uploaded email is
    # treated as hostile input; this bounds memory usage during parsing.
    max_upload_size_mb: int = Field(default=10, ge=1, le=100)

    # Offline demo mode: external intelligence lookups are replaced by
    # deterministic fixtures. Core parsing/forensics stay real.
    demo_mode: bool = False

    # ─── Phase D6: Threat Intelligence ──────────────────────────────
    
    # Enable/disable providers
    threat_intel_openphish_enabled: bool = True
    threat_intel_virustotal_enabled: bool = True
    threat_intel_abuseipdb_enabled: bool = True
    
    # API keys (must be set via environment variables)
    threat_intel_openphish_api_key: str | None = None
    threat_intel_virustotal_api_key: str | None = None
    threat_intel_abuseipdb_api_key: str | None = None
    
    # Query budgets per email analysis
    threat_intel_max_ip_queries: int = 10
    threat_intel_max_domain_queries: int = 20
    threat_intel_max_url_queries: int = 30
    threat_intel_max_hash_queries: int = 10
    threat_intel_max_total_queries: int = 50
    
    # Cache settings
    threat_intel_cache_enabled: bool = True
    threat_intel_cache_ttl_seconds: int = 3600
    threat_intel_cache_max_entries: int = 10000
    
    # Circuit breaker
    threat_intel_cb_failure_threshold: int = 5
    threat_intel_cb_timeout_seconds: float = 60.0
    
    # Rate limiting (requests per minute)
    threat_intel_openphish_rpm: int = 30
    threat_intel_virustotal_rpm: int = 4
    threat_intel_abuseipdb_rpm: int = 30
    
    # Timeouts
    threat_intel_timeout_connect: float = 5.0
    threat_intel_timeout_read: float = 15.0
    threat_intel_timeout_total: float = 30.0
    
    # Aggregation
    threat_intel_min_providers_for_agreement: int = 2
    
    # Privacy
    threat_intel_skip_private_ips: bool = True

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("DATABASE_URL cannot be empty")
        if v.startswith("sqlite"):
            raise ValueError("SQLite is not supported. Use PostgreSQL connection string.")
        return v

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in ("production", "prod")


settings = Settings()