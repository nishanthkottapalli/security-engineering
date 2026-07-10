from __future__ import annotations

import hashlib
import signal
import time
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from secops_lab.api.audit import record_audit
from secops_lab.api.config import get_settings
from secops_lab.api.db import SessionLocal
from secops_lab.api.file_security import resolve_storage_path
from secops_lab.api.models import ProcessingJob, Upload

_STOP = False
SAFE_TEST_MARKER = b"LAB-MALWARE-TEST-MARKER"


def _stop(*_: object) -> None:
    global _STOP
    _STOP = True


def claim_job(db: Session) -> ProcessingJob | None:
    query = (
        select(ProcessingJob)
        .where(ProcessingJob.status == "pending")
        .order_by(ProcessingJob.created_at)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    job = db.scalar(query)
    if job is None:
        return None
    job.status = "running"
    job.attempts += 1
    job.started_at = datetime.now(UTC)
    upload = db.get(Upload, job.upload_id)
    if upload:
        upload.status = "processing"
    db.commit()
    db.refresh(job)
    return job


def analyse_file(path: Path) -> tuple[str, str]:
    digest = hashlib.sha256()
    marker_found = False
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            marker_found = marker_found or SAFE_TEST_MARKER in chunk
    status = "quarantined" if marker_found else "clean"
    detail = (
        "Safe lab malware marker detected; file quarantined."
        if marker_found
        else (
            "SHA-256 calculated; no safe lab marker detected. "
            "This is not a replacement for antivirus."
        )
    )
    return digest.hexdigest(), f"{status}|{detail}"


def process_job(job_id: str) -> None:
    settings = get_settings()
    with SessionLocal() as db:
        job = db.get(ProcessingJob, job_id)
        if job is None:
            return
        upload = db.get(Upload, job.upload_id)
        if upload is None:
            job.status = "failed"
            job.error = "upload record missing"
            db.commit()
            return
        try:
            path = resolve_storage_path(settings.upload_dir, upload.storage_name)
            sha256, outcome = analyse_file(path)
            status, detail = outcome.split("|", 1)
            upload.sha256 = sha256
            upload.status = status
            upload.scan_detail = detail
            upload.processed_at = datetime.now(UTC)
            job.status = "done"
            job.finished_at = datetime.now(UTC)
            record_audit(
                db,
                event_type="file.background_analysis",
                outcome="success" if status == "clean" else "blocked",
                actor_user_id=upload.owner_id,
                resource_type="upload",
                resource_id=upload.id,
                detail={"status": status, "sha256": sha256},
            )
            db.commit()
        except Exception as exc:  # noqa: BLE001
            upload.status = "failed"
            upload.scan_detail = "Background processing failed."
            job.status = "failed"
            job.error = str(exc)[:1000]
            job.finished_at = datetime.now(UTC)
            record_audit(
                db,
                event_type="file.background_analysis",
                outcome="failure",
                actor_user_id=upload.owner_id,
                resource_type="upload",
                resource_id=upload.id,
                detail={"error_type": type(exc).__name__},
            )
            db.commit()


def run() -> None:
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    settings = get_settings()
    while not _STOP:
        with SessionLocal() as db:
            job = claim_job(db)
        if job is None:
            time.sleep(settings.worker_poll_seconds)
            continue
        process_job(job.id)


if __name__ == "__main__":
    run()
