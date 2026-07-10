from __future__ import annotations

import os

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("APP_SECRET_KEY", "test-secret-key-that-is-long-enough-for-tests")
os.environ.setdefault("APP_DATABASE_URL", "sqlite:////tmp/security-capabilities-test.db")
os.environ.setdefault("APP_UPLOAD_DIR", "/tmp/security-capabilities-uploads")
os.environ.setdefault("APP_AUDIT_LOG_PATH", "/tmp/security-capabilities-audit/audit.jsonl")
os.environ.setdefault("APP_ADMIN_EMAIL", "admin@example.com")
os.environ.setdefault("APP_ADMIN_PASSWORD", "ChangeMe-Now-123!")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from secops_lab.api.config import get_settings
from secops_lab.api.db import Base, SessionLocal, engine
from secops_lab.api.main import app
from secops_lab.api.models import User
from secops_lab.api.security import hash_password


@pytest.fixture(autouse=True)
def reset_database() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    settings = get_settings()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    for path in settings.upload_dir.glob("*"):
        if path.is_file():
            path.unlink()
    settings.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    settings.audit_log_path.unlink(missing_ok=True)
    with SessionLocal() as db:
        if not db.scalar(select(User).where(User.email == settings.admin_email)):
            db.add(
                User(
                    email=settings.admin_email,
                    password_hash=hash_password(settings.admin_password),
                    role="admin",
                )
            )
            db.commit()
    yield


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def admin_token(client: TestClient) -> str:
    response = client.post(
        "/auth/token",
        data={"username": "admin@example.com", "password": "ChangeMe-Now-123!"},
    )
    assert response.status_code == 200, response.text
    return str(response.json()["access_token"])
