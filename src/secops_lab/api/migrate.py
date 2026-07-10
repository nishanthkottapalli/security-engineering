from __future__ import annotations

from sqlalchemy import select

from secops_lab.api.config import get_settings
from secops_lab.api.db import Base, SessionLocal, engine
from secops_lab.api.models import User
from secops_lab.api.security import hash_password


def migrate() -> None:
    settings = get_settings()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    settings.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == settings.admin_email))
        if user is None:
            db.add(
                User(
                    email=settings.admin_email,
                    password_hash=hash_password(settings.admin_password),
                    role="admin",
                )
            )
            db.commit()
            print(f"Created lab administrator: {settings.admin_email}")
        else:
            print(f"Lab administrator already exists: {settings.admin_email}")


if __name__ == "__main__":
    migrate()
