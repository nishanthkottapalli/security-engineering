from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from secops_lab.detection.models import DetectionAlert, SshEvent


@dataclass(slots=True)
class CorrelationConfig:
    threshold: int = 5
    window_seconds: int = 120
    privileged_users: set[str] = field(default_factory=lambda: {"root", "admin", "administrator"})
    production_hosts: set[str] = field(default_factory=lambda: {"prod-web-01", "prod-api-01"})


class SshCompromiseCorrelator:
    """Correlate repeated failures with a later success for the same tuple."""

    def __init__(self, config: CorrelationConfig | None = None) -> None:
        self.config = config or CorrelationConfig()
        self._failures: dict[tuple[str, str, str], deque[SshEvent]] = defaultdict(deque)
        self._recent_success: dict[tuple[str, str, str], DetectionAlert] = {}

    def _purge(self, key: tuple[str, str, str], now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.config.window_seconds)
        queue = self._failures[key]
        while queue and queue[0].timestamp < cutoff:
            queue.popleft()

    def process(self, event: SshEvent) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        if not event.username or not event.source_ip:
            return alerts
        key = (event.hostname, event.username, event.source_ip)
        self._purge(key, event.timestamp)

        if event.kind == "failure":
            self._failures[key].append(event)
            return alerts

        if event.kind != "success":
            return alerts

        failures = list(self._failures[key])
        if len(failures) < self.config.threshold:
            return alerts

        severity = "high"
        rationale = "Repeated SSH authentication failures were followed by a successful login."
        if (
            event.username.lower() in self.config.privileged_users
            or event.hostname in self.config.production_hosts
        ):
            severity = "critical"
            rationale += " The affected identity or host is privileged/production-scoped."

        alert = DetectionAlert(
            detection_id="DET-LINUX-SSH-001",
            title="SSH password guessing followed by successful authentication",
            generated_at=datetime.now(UTC),
            first_seen=failures[0].timestamp,
            last_seen=event.timestamp,
            hostname=event.hostname,
            username=event.username,
            source_ip=event.source_ip,
            failure_count=len(failures),
            severity=severity,  # type: ignore[arg-type]
            confidence="high",
            mitre_techniques=["T1110", "T1110.001", "T1078", "T1021.004"],
            evidence=[item.raw for item in failures] + [event.raw],
            rationale=rationale,
        )
        self._recent_success[key] = alert
        alerts.append(alert)
        self._failures[key].clear()
        return alerts

    def replay(self, events: list[SshEvent]) -> list[DetectionAlert]:
        alerts: list[DetectionAlert] = []
        for event in sorted(events, key=lambda item: item.timestamp):
            alerts.extend(self.process(event))
        return alerts
