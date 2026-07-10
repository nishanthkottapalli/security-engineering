from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 -- OAuth token type, not a password
    expires_in: int


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime


class CreateUserRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: str = Field(pattern="^(user|admin)$")


class UploadResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    original_filename: str
    declared_content_type: str
    detected_content_type: str
    size_bytes: int
    sha256: str | None
    status: str
    scan_detail: str | None
    created_at: datetime
    processed_at: datetime | None


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    actor_user_id: str | None
    event_type: str
    outcome: str
    request_id: str | None
    source_ip: str | None
    resource_type: str | None
    resource_id: str | None
    detail_json: str
