from __future__ import annotations

import re
from datetime import UTC, datetime

from secops_lab.detection.models import SshEvent

SYSLOG_RE = re.compile(
    r"^(?:(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})(?:Z|[+-]\d{2}:?\d{2})|"
    r"(?P<mon>[A-Z][a-z]{2})\s+(?P<mday>\d{1,2})\s+"
    r"(?P<shour>\d{2}):(?P<sminute>\d{2}):(?P<ssecond>\d{2}))\s+"
    r"(?P<host>[\w.-]+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
)

FAILED_RE = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>[^ ]+) from "
    r"(?P<src>[0-9a-fA-F:.]+) port \d+ ssh2$"
)
ACCEPTED_RE = re.compile(
    r"^Accepted (?:password|publickey) for (?P<user>[^ ]+) from "
    r"(?P<src>[0-9a-fA-F:.]+) port \d+ ssh2(?:: .*)?$"
)
SUDO_RE = re.compile(
    r"^(?:pam_unix\(sudo:session\): session opened for user root by |"
    r"(?P<user>[^ :]+) : TTY=.*COMMAND=.*)$"
)
MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _timestamp(match: re.Match[str], *, default_year: int) -> datetime:
    if match.group("year"):
        return datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second")),
            tzinfo=UTC,
        )
    return datetime(
        default_year,
        MONTHS[match.group("mon")],
        int(match.group("mday")),
        int(match.group("shour")),
        int(match.group("sminute")),
        int(match.group("ssecond")),
        tzinfo=UTC,
    )


def parse_ssh_event(line: str, *, default_year: int = 2026) -> SshEvent | None:
    """Parse one canonical Linux sshd syslog line.

    The parser deliberately rejects ambiguous input rather than inventing fields.
    """
    raw = line.rstrip("\n")
    match = SYSLOG_RE.match(raw)
    if not match:
        return None
    message = match.group("message")
    username: str | None = None
    source_ip: str | None = None
    kind = "other"

    if failure := FAILED_RE.match(message):
        kind = "failure"
        username = failure.group("user")
        source_ip = failure.group("src")
    elif success := ACCEPTED_RE.match(message):
        kind = "success"
        username = success.group("user")
        source_ip = success.group("src")
    elif SUDO_RE.match(message):
        kind = "sudo"
        sudo_match = SUDO_RE.match(message)
        username = sudo_match.groupdict().get("user") if sudo_match else None

    return SshEvent(
        timestamp=_timestamp(match, default_year=default_year),
        hostname=match.group("host"),
        process_id=int(match.group("pid")),
        kind=kind,  # type: ignore[arg-type]
        username=username,
        source_ip=source_ip,
        raw=raw,
    )
