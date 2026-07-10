from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str
    secret_key: str
    access_token_minutes: int
    database_url: str
    upload_dir: Path
    max_upload_bytes: int
    allowed_upload_types: frozenset[str]
    admin_email: str
    admin_password: str
    worker_poll_seconds: float
    audit_log_path: Path


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    secret = os.getenv("APP_SECRET_KEY", "development-only-change-me")
    environment = os.getenv("APP_ENV", "development")
    if environment.lower() in {"production", "prod"} and len(secret) < 32:
        raise RuntimeError("APP_SECRET_KEY must be at least 32 characters in production")
    return Settings(
        environment=environment,
        secret_key=secret,
        access_token_minutes=int(os.getenv("APP_ACCESS_TOKEN_MINUTES", "30")),
        database_url=os.getenv("APP_DATABASE_URL", "sqlite:///./lab-output/secops.db"),
        upload_dir=Path(os.getenv("APP_UPLOAD_DIR", "./uploads")).resolve(),
        max_upload_bytes=int(os.getenv("APP_MAX_UPLOAD_BYTES", str(5 * 1024 * 1024))),
        allowed_upload_types=frozenset(
            item.strip()
            for item in os.getenv(
                "APP_ALLOWED_UPLOAD_TYPES", "text/plain,application/json,application/pdf"
            ).split(",")
            if item.strip()
        ),
        admin_email=os.getenv("APP_ADMIN_EMAIL", "admin@example.com").lower(),
        admin_password=os.getenv("APP_ADMIN_PASSWORD", "ChangeMe-Now-123!"),
        worker_poll_seconds=float(os.getenv("APP_WORKER_POLL_SECONDS", "2")),
        audit_log_path=Path(os.getenv("APP_AUDIT_LOG_PATH", "./lab-output/audit.jsonl")).resolve(),
    )
