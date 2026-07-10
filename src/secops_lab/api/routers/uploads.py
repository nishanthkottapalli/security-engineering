from __future__ import annotations

import os
import uuid

from fastapi import APIRouter, File, HTTPException, Request, UploadFile, status
from sqlalchemy import select

from secops_lab.api.audit import record_audit
from secops_lab.api.config import get_settings
from secops_lab.api.dependencies import CurrentUser, DbSession
from secops_lab.api.file_security import (
    UnsafeUpload,
    detect_content_type,
    resolve_storage_path,
    sanitise_filename,
)
from secops_lab.api.models import ProcessingJob, Upload
from secops_lab.api.schemas import UploadResponse

router = APIRouter(prefix="/uploads", tags=["uploads"])


@router.post("", response_model=UploadResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_upload(
    request: Request,
    user: CurrentUser,
    db: DbSession,
    file: UploadFile = File(...),
) -> Upload:
    settings = get_settings()
    declared = (file.content_type or "application/octet-stream").lower()
    if declared not in settings.allowed_upload_types:
        raise HTTPException(status_code=415, detail="Declared content type is not allowed")

    data = await file.read(settings.max_upload_bytes + 1)
    if not data:
        raise HTTPException(status_code=400, detail="Empty upload")
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="Upload exceeds configured size limit")
    try:
        filename = sanitise_filename(file.filename)
        detected = detect_content_type(data)
    except UnsafeUpload as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    if detected not in settings.allowed_upload_types:
        raise HTTPException(status_code=415, detail="Detected content type is not allowed")
    content_type_exception = declared == "text/plain" and detected == "application/json"
    if declared != detected and not content_type_exception:
        raise HTTPException(
            status_code=415, detail="Declared and detected content types do not match"
        )

    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    storage_name = f"{uuid.uuid4()}.bin"
    path = resolve_storage_path(settings.upload_dir, storage_name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
    except Exception:
        path.unlink(missing_ok=True)
        raise

    upload = Upload(
        owner_id=user.id,
        original_filename=filename,
        storage_name=storage_name,
        declared_content_type=declared,
        detected_content_type=detected,
        size_bytes=len(data),
        status="pending",
    )
    db.add(upload)
    db.flush()
    db.add(ProcessingJob(upload_id=upload.id))
    record_audit(
        db,
        event_type="file.upload_received",
        outcome="success",
        actor_user_id=user.id,
        request_id=getattr(request.state, "request_id", None),
        source_ip=request.client.host if request.client else None,
        resource_type="upload",
        resource_id=upload.id,
        detail={"size_bytes": len(data), "detected_content_type": detected},
    )
    db.commit()
    db.refresh(upload)
    return upload


@router.get("", response_model=list[UploadResponse])
def list_uploads(user: CurrentUser, db: DbSession) -> list[Upload]:
    query = select(Upload).order_by(Upload.created_at.desc())
    if user.role != "admin":
        query = query.where(Upload.owner_id == user.id)
    return list(db.scalars(query).all())


@router.get("/{upload_id}", response_model=UploadResponse)
def get_upload(upload_id: str, user: CurrentUser, db: DbSession) -> Upload:
    upload = db.get(Upload, upload_id)
    if upload is None:
        raise HTTPException(status_code=404, detail="Upload not found")
    if user.role != "admin" and upload.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Upload not found")
    return upload
