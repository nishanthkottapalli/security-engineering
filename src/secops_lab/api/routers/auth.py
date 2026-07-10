from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select

from secops_lab.api.audit import record_audit
from secops_lab.api.dependencies import DbSession
from secops_lab.api.models import User
from secops_lab.api.schemas import TokenResponse
from secops_lab.api.security import create_access_token, verify_password

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/token", response_model=TokenResponse)
def issue_token(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DbSession,
) -> TokenResponse:
    email = form.username.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    request_id = getattr(request.state, "request_id", None)
    source_ip = request.client.host if request.client else None
    if user is None or not verify_password(form.password, user.password_hash) or not user.is_active:
        record_audit(
            db,
            event_type="authentication.login",
            outcome="failure",
            request_id=request_id,
            source_ip=source_ip,
            detail={"email": email},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token, expires_in = create_access_token(subject=user.id, role=user.role)
    record_audit(
        db,
        event_type="authentication.login",
        outcome="success",
        actor_user_id=user.id,
        request_id=request_id,
        source_ip=source_ip,
    )
    db.commit()
    return TokenResponse(access_token=token, expires_in=expires_in)
