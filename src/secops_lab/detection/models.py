from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Literal

EventKind = Literal["failure", "success", "sudo", "other"]
Severity = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high", "very_high"]


@dataclass(frozen=True, slots=True)
class SshEvent:
    timestamp: datetime
    hostname: str
    process_id: int | None
    kind: EventKind
    username: str | None
    source_ip: str | None
    raw: str


@dataclass(slots=True)
class DetectionAlert:
    detection_id: str
    title: str
    generated_at: datetime
    first_seen: datetime
    last_seen: datetime
    hostname: str
    username: str
    source_ip: str
    failure_count: int
    severity: Severity
    confidence: Confidence
    mitre_techniques: list[str]
    evidence: list[str]
    rationale: str

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        for field in ("generated_at", "first_seen", "last_seen"):
            data[field] = getattr(self, field).astimezone(UTC).isoformat()
        return data
