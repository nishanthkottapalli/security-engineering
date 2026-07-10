from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from secops_lab.api.audit import record_audit
from secops_lab.api.dependencies import AdminUser, CurrentUser, DbSession
from secops_lab.api.models import User
from secops_lab.api.schemas import CreateUserRequest, UserResponse
from secops_lab.api.security import hash_password

router = APIRouter(tags=["users"])


@router.get("/users/me", response_model=UserResponse)
def me(user: CurrentUser) -> User:
    return user


@router.get("/admin/users", response_model=list[UserResponse])
def list_users(_: AdminUser, db: DbSession) -> list[User]:
    return list(db.scalars(select(User).order_by(User.created_at)).all())


@router.post("/admin/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: CreateUserRequest,
    request: Request,
    admin: AdminUser,
    db: DbSession,
) -> User:
    email = payload.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")
    user = User(email=email, password_hash=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.flush()
    record_audit(
        db,
        event_type="identity.user_created",
        outcome="success",
        actor_user_id=admin.id,
        request_id=getattr(request.state, "request_id", None),
        source_ip=request.client.host if request.client else None,
        resource_type="user",
        resource_id=user.id,
        detail={"role": user.role},
    )
    db.commit()
    db.refresh(user)
    return user
