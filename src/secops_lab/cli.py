from __future__ import annotations

from pathlib import Path

import typer

from secops_lab.detection.cli import app as detection_app
from secops_lab.triage.cli import app as triage_app

app = typer.Typer(help="Security engineering capability lab CLI.", no_args_is_help=True)
app.add_typer(detection_app, name="detection")
app.add_typer(triage_app, name="triage")


@app.command("version")
def version() -> None:
    """Print the package version."""
    from secops_lab import __version__

    typer.echo(__version__)


@app.command("validate-path")
def validate_path(path: Path) -> None:
    """Small operational smoke test used by containers and CI."""
    if not path.exists():
        raise typer.BadParameter(f"path does not exist: {path}")
    typer.echo(str(path.resolve()))


if __name__ == "__main__":
    app()
