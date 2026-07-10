from __future__ import annotations

from pathlib import Path

import typer

from secops_lab.detection.correlator import CorrelationConfig, SshCompromiseCorrelator
from secops_lab.detection.parser import parse_ssh_event
from secops_lab.detection.reporting import write_alerts

app = typer.Typer(help="Replay and validate detection telemetry.", no_args_is_help=True)


@app.command("replay")
def replay(
    log_file: Path = typer.Argument(..., exists=True, readable=True),
    output: Path = typer.Option(Path("lab-output/detection-alerts.json"), "--output", "-o"),
    threshold: int = typer.Option(5, min=2, max=100),
    window_seconds: int = typer.Option(120, min=10, max=3600),
) -> None:
    """Replay an SSH auth log through the deterministic correlation engine."""
    events = []
    rejected = 0
    for line in log_file.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        event = parse_ssh_event(line)
        if event is None:
            rejected += 1
            continue
        events.append(event)

    correlator = SshCompromiseCorrelator(
        CorrelationConfig(threshold=threshold, window_seconds=window_seconds)
    )
    alerts = correlator.replay(events)
    write_alerts(alerts, output)
    typer.echo(
        f"Processed {len(events)} events, rejected {rejected}, generated {len(alerts)} alert(s)."
    )
    typer.echo(str(output))
