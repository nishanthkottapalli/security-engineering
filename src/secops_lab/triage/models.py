from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal

Severity = Literal["unknown", "negligible", "low", "medium", "high", "critical"]


@dataclass(slots=True)
class Finding:
    finding_id: str
    source: str
    component: str
    installed_version: str | None
    fixed_versions: list[str]
    vulnerability_ids: list[str]
    severity: Severity
    title: str
    description: str
    environment: str = "unknown"
    asset: str = "repository"
    asset_criticality: str = "medium"
    internet_exposed: bool = False
    exploit_available: bool = False
    status: str = "open"
    references: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    risk_score: int = 0
    priority: str = "P4"
    rationale: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.sources:
            self.sources = [self.source]

    def deduplication_key(self) -> tuple[str, str, str]:
        primary_id = (
            sorted(self.vulnerability_ids)[0] if self.vulnerability_ids else self.finding_id
        )
        return (primary_id.lower(), self.component.lower(), (self.installed_version or "").lower())

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
