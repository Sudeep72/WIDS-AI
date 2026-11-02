"""Read-only FastAPI service and dashboard hosting."""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from wids_ai.storage.db import Database

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DASHBOARD_ROOT = PROJECT_ROOT / "dashboard"
CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
MAX_TEXT = 256


def sanitize_text(value: Any) -> Any:
    """Remove control characters and truncate attacker-controlled display text."""
    if not isinstance(value, str):
        return value
    cleaned = CONTROL_CHARS.sub("", unicodedata.normalize("NFC", value))
    return cleaned[:MAX_TEXT]


def sanitize_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {sanitize_text(key): sanitize_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize_payload(item) for item in value]
    return sanitize_text(value)


class HealthResponse(BaseModel):
    status: Literal["ok"]
    schema_version: int


class StatsResponse(BaseModel):
    frames_processed: int
    windows: int
    alerts_by_severity: dict[str, int]
    alerts_by_family: dict[str, int]
    latest_ml_scores: list[dict[str, Any]]


class APResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    bssid: str
    ssid: str | None
    oui: str | None
    channels: list[int]
    rssi: float | None
    security: list[str]
    trust_score: int
    flagged: bool


class AlertResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str
    timestamp: datetime | str
    family: str
    severity: str
    risk_score: int
    bssids: list[str] | tuple[str, ...] = []
    ssids: list[str] | tuple[str, ...] = []
    clients: list[str] | tuple[str, ...] = []
    evidence: list[dict[str, Any]] = []
    indicators_found: list[dict[str, Any]] = []
    indicators_not_found: list[dict[str, Any]] = []
    why: str = ""
    mitre_attack: dict[str, Any] | None = None


def get_database(request: Request) -> Database:
    return request.app.state.database


def create_app(database: Database | None = None) -> FastAPI:
    app = FastAPI(title="WIDS-AI", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.database = database or Database()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/api/health", response_model=HealthResponse)
    def health(db: Annotated[Database, Depends(get_database)]) -> HealthResponse:
        return HealthResponse(status="ok", schema_version=1)

    @app.get("/api/stats", response_model=StatsResponse)
    def stats(db: Annotated[Database, Depends(get_database)]) -> dict[str, Any]:
        return sanitize_payload(db.get_stats())

    @app.get("/api/aps", response_model=list[APResponse])
    def aps(db: Annotated[Database, Depends(get_database)]) -> list[dict[str, Any]]:
        return sanitize_payload(db.list_aps())

    @app.get("/api/alerts", response_model=list[AlertResponse])
    def alerts(
        db: Annotated[Database, Depends(get_database)],
        severity: Annotated[
            str | None, Query(pattern="^(informational|low|medium|high|critical)$")
        ] = None,
        family: Annotated[str | None, Query(max_length=128, pattern="^[A-Za-z0-9_.-]+$")] = None,
        since: Annotated[str | None, Query(max_length=64)] = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 50,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> list[dict[str, Any]]:
        if since is not None:
            try:
                datetime.fromisoformat(since.replace("Z", "+00:00"))
            except ValueError as exc:
                raise HTTPException(status_code=422, detail="since must be ISO-8601") from exc
        return sanitize_payload(
            db.list_alerts(
                severity=severity, family=family, since=since, limit=limit, offset=offset
            )
        )

    @app.get("/api/alerts/{alert_id}", response_model=AlertResponse)
    def alert_detail(
        alert_id: str,
        db: Annotated[Database, Depends(get_database)],
    ) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", alert_id):
            raise HTTPException(status_code=422, detail="invalid alert id")
        alert = db.get_alert(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")
        return sanitize_payload(alert)

    app.mount("/static", StaticFiles(directory=DASHBOARD_ROOT), name="static")

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(DASHBOARD_ROOT / "index.html")

    return app


app = create_app()
