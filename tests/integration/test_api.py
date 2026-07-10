from fastapi.testclient import TestClient

from secops_lab.api.db import SessionLocal
from secops_lab.api.models import ProcessingJob
from secops_lab.api.worker import process_job


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_health(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_auth_rbac_upload_background_processing_and_audit(
    client: TestClient, admin_token: str
) -> None:
    me = client.get("/users/me", headers=auth(admin_token))
    assert me.status_code == 200
    assert me.json()["role"] == "admin"

    created = client.post(
        "/admin/users",
        headers=auth(admin_token),
        json={"email": "analyst@example.com", "password": "SecurePassphrase-123", "role": "user"},
    )
    assert created.status_code == 201, created.text

    user_login = client.post(
        "/auth/token",
        data={"username": "analyst@example.com", "password": "SecurePassphrase-123"},
    )
    assert user_login.status_code == 200
    user_token = user_login.json()["access_token"]

    denied = client.get("/admin/users", headers=auth(user_token))
    assert denied.status_code == 403

    upload = client.post(
        "/uploads",
        headers=auth(user_token),
        files={"file": ("evidence.txt", b"safe evidence\n", "text/plain")},
    )
    assert upload.status_code == 202, upload.text
    upload_id = upload.json()["id"]

    with SessionLocal() as db:
        job = db.query(ProcessingJob).filter_by(upload_id=upload_id).one()
        job_id = job.id
    process_job(job_id)

    status = client.get(f"/uploads/{upload_id}", headers=auth(user_token))
    assert status.status_code == 200
    assert status.json()["status"] == "clean"
    assert len(status.json()["sha256"]) == 64

    audit = client.get("/admin/audit", headers=auth(admin_token))
    assert audit.status_code == 200
    event_types = {item["event_type"] for item in audit.json()}
    assert "file.upload_received" in event_types
    assert "file.background_analysis" in event_types


def test_upload_content_validation(client: TestClient, admin_token: str) -> None:
    executable = client.post(
        "/uploads",
        headers=auth(admin_token),
        files={"file": ("program.exe", b"MZ" + b"0" * 20, "text/plain")},
    )
    assert executable.status_code == 415

    html = client.post(
        "/uploads",
        headers=auth(admin_token),
        files={"file": ("page.txt", b"<!doctype html><script>alert(1)</script>", "text/plain")},
    )
    assert html.status_code == 415
