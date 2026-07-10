from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from defusedxml import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def validate_structured_files() -> None:
    for path in ROOT.rglob("*.json"):
        if any(part in {".venv", ".terraform"} for part in path.parts):
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")
    for path in ROOT.rglob("*.yml"):
        try:
            yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            fail(f"invalid YAML {path.relative_to(ROOT)}: {exc}")
    for path in ROOT.rglob("*.yaml"):
        try:
            yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            fail(f"invalid YAML {path.relative_to(ROOT)}: {exc}")
    for path in ROOT.rglob("*.xml"):
        text = path.read_text(encoding="utf-8")
        # Wazuh permits multiple top-level decoder/rule elements, so wrap them.
        try:
            ET.fromstring(f"<root>{text}</root>")
        except Exception as exc:  # noqa: BLE001
            fail(f"invalid XML {path.relative_to(ROOT)}: {exc}")


def validate_required_paths() -> None:
    required = [
        "SECURITY.md",
        "VALIDATION.md",
        ".github/workflows/sbom.yml",
        "Vagrantfile",
        "docker-compose.yml",
        "detections/linux/ssh/ssh-bruteforce-followed-by-success/README.md",
        "labs/01-wazuh-ssh-bruteforce/README.md",
        "labs/02-python-vulnerability-triage/README.md",
        "labs/03-aws-security-baseline/README.md",
        "labs/04-fastapi-secure-sdl/README.md",
        "terraform/aws-foundation/main.tf",
    ]
    missing = [item for item in required if not (ROOT / item).exists()]
    if missing:
        fail(f"missing required paths: {', '.join(missing)}")


if __name__ == "__main__":
    validate_required_paths()
    validate_structured_files()
    print("Repository structure and structured files are valid.")
