from pathlib import Path

from secops_lab.detection.correlator import SshCompromiseCorrelator
from secops_lab.detection.parser import parse_ssh_event

FIXTURES = Path(__file__).parents[1] / "fixtures" / "detection"


def replay(name: str):
    events = [
        event
        for line in (FIXTURES / name).read_text().splitlines()
        if (event := parse_ssh_event(line)) is not None
    ]
    return SshCompromiseCorrelator().replay(events)


def test_compromise_sequence_generates_critical_alert() -> None:
    alerts = replay("ssh_compromise.log")
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.failure_count == 5
    assert alert.severity == "critical"
    assert alert.confidence == "high"
    assert "T1078" in alert.mitre_techniques


def test_failures_without_success_do_not_generate_compromise_alert() -> None:
    assert replay("ssh_failures_only.log") == []


def test_success_from_different_source_does_not_correlate() -> None:
    assert replay("ssh_different_source.log") == []


def test_parser_rejects_unrelated_line() -> None:
    assert parse_ssh_event("not an ssh event") is None
