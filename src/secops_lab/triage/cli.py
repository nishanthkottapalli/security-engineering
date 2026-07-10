from __future__ import annotations

from pathlib import Path

import typer

from secops_lab.triage.engine import deduplicate, prioritise
from secops_lab.triage.parsers import parse_file
from secops_lab.triage.reporting import write_reports

app = typer.Typer(
    help="Normalise, deduplicate and prioritise scanner findings.", no_args_is_help=True
)


@app.command("run")
def run(
    inputs: list[Path] = typer.Argument(..., exists=True, readable=True),
    output_dir: Path = typer.Option(Path("lab-output/triage"), "--output-dir", "-o"),
    environment: str = typer.Option("production", help="development, staging or production"),
    asset_criticality: str = typer.Option("high", help="low, medium, high or critical"),
    internet_exposed: bool = typer.Option(True, "--internet-exposed/--internal-only"),
) -> None:
    """Create JSON, CSV and Markdown triage reports from supported scanner JSON."""
    findings = []
    for path in inputs:
        findings.extend(parse_file(path))
    normalised = prioritise(
        deduplicate(findings),
        environment=environment,
        asset_criticality=asset_criticality,
        internet_exposed=internet_exposed,
    )
    write_reports(normalised, output_dir)
    typer.echo(f"Read {len(findings)} scanner records and produced {len(normalised)} findings.")
    typer.echo(str(output_dir))
