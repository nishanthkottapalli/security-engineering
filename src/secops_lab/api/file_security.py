from __future__ import annotations

import json
from pathlib import Path


class UnsafeUpload(ValueError):
    pass


def sanitise_filename(filename: str | None) -> str:
    name = Path(filename or "upload.bin").name.replace("\x00", "")
    if not name or name in {".", ".."}:
        raise UnsafeUpload("invalid filename")
    return name[:255]


def detect_content_type(content: bytes) -> str:
    if content.startswith(b"%PDF-"):
        return "application/pdf"
    if content.startswith((b"MZ", b"\x7fELF", b"PK\x03\x04")):
        raise UnsafeUpload("executable or archive content is not accepted by this lab")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsafeUpload("unrecognised binary content") from exc
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        try:
            json.loads(text)
        except json.JSONDecodeError:
            return "text/plain"
        return "application/json"
    if "<script" in stripped.lower() or stripped.lower().startswith("<!doctype html"):
        raise UnsafeUpload("active HTML content is not accepted")
    return "text/plain"


def resolve_storage_path(upload_dir: Path, storage_name: str) -> Path:
    root = upload_dir.resolve()
    candidate = (root / storage_name).resolve()
    if root not in candidate.parents:
        raise UnsafeUpload("invalid storage path")
    return candidate
