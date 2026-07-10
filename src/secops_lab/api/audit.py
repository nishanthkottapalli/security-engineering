from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from secops_lab.api.config import get_settings
from secops_lab.api.models import AuditEvent

_LOCK = threading.Lock()


def record_audit(
    db: Session,
    *,
    event_type: str,
    outcome: str,
    actor_user_id: str | None = None,
    request_id: str | None = None,
    source_ip: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    detail: dict[str, Any] | None = None,
) -> AuditEvent:
    detail = detail or {}
    event = AuditEvent(
        actor_user_id=actor_user_id,
        event_type=event_type,
        outcome=outcome,
        request_id=request_id,
        source_ip=source_ip,
        resource_type=resource_type,
        resource_id=resource_id,
        detail_json=json.dumps(detail, sort_keys=True, separators=(",", ":")),
    )
    db.add(event)
    db.flush()

    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "audit_event_id": event.id,
        "actor_user_id": actor_user_id,
        "event_type": event_type,
        "outcome": outcome,
        "request_id": request_id,
        "source_ip": source_ip,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "detail": detail,
    }
    path: Path = get_settings().audit_log_path
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK, path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")
    return event
