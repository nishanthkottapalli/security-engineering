from __future__ import annotations

from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from secops_lab.api.db import get_db
from secops_lab.api.models import User
from secops_lab.api.security import decode_access_token

OAuth2Scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
DbSession = Annotated[Session, Depends(get_db)]


def current_user(
    token: Annotated[str, Depends(OAuth2Scheme)],
    db: DbSession,
) -> User:
    credentials_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired access token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        claims = decode_access_token(token)
        subject = str(claims["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise credentials_error from None
    user = db.get(User, subject)
    if user is None or not user.is_active:
        raise credentials_error
    return user


CurrentUser = Annotated[User, Depends(current_user)]


def require_admin(user: CurrentUser) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user


AdminUser = Annotated[User, Depends(require_admin)]
