from __future__ import annotations

import json
from pathlib import Path

from secops_lab.detection.models import DetectionAlert


def write_alerts(alerts: list[DetectionAlert], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps([alert.to_dict() for alert in alerts], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
