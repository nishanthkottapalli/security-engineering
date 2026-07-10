from __future__ import annotations

import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from secops_lab.api.config import get_settings
from secops_lab.api.routers import audit, auth, uploads, users

settings = get_settings()
app = FastAPI(
    title="Security Capabilities Secure-SDLC Lab",
    version="1.0.0",
    description=(
        "A deliberately small, defensive sample API with authentication, RBAC, uploads, "
        "background processing and audit logging."
    ),
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url=None,
)


@app.middleware("http")
async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        if settings.environment == "test":
            raise
        response = JSONResponse(status_code=500, content={"detail": "Internal server error"})
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Server-Timing"] = f"app;dur={(time.perf_counter() - started) * 1000:.2f}"
    return response


@app.get("/health", tags=["operations"])
def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.environment}


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(uploads.router)
app.include_router(audit.router)
