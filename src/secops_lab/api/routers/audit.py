from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import select

from secops_lab.api.dependencies import AdminUser, DbSession
from secops_lab.api.models import AuditEvent
from secops_lab.api.schemas import AuditEventResponse

router = APIRouter(prefix="/admin/audit", tags=["audit"])


@router.get("", response_model=list[AuditEventResponse])
def list_audit_events(
    _: AdminUser,
    db: DbSession,
    limit: int = Query(100, ge=1, le=500),
) -> list[AuditEvent]:
    query = select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    return list(db.scalars(query).all())
