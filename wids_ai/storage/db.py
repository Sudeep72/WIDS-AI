"""SQLite persistence for runs, AP inventory, incidents, and alerts."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from wids_ai.correlation.schema import Alert
from wids_ai.inventory import APInventory

SCHEMA_VERSION = 3
DDL = (
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        finished_at TEXT,
        source TEXT NOT NULL,
        frame_count INTEGER NOT NULL DEFAULT 0,
        window_count INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'running'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS aps (
        bssid TEXT PRIMARY KEY,
        ssid TEXT,
        oui TEXT,
        channels TEXT NOT NULL DEFAULT '[]',
        rssi REAL,
        security TEXT NOT NULL DEFAULT '[]',
        trust_score INTEGER NOT NULL DEFAULT 0,
        flagged INTEGER NOT NULL DEFAULT 0,
        flag_reason TEXT,
        status TEXT NOT NULL DEFAULT 'Trusted',
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        run_id INTEGER,
        timestamp TEXT NOT NULL,
        family TEXT NOT NULL,
        severity TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        bssids TEXT NOT NULL DEFAULT '[]',
        ssids TEXT NOT NULL DEFAULT '[]',
        clients TEXT NOT NULL DEFAULT '[]',
        payload_json TEXT NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_family ON alerts(family)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_risk ON alerts(risk_score)",
    """
    CREATE TABLE IF NOT EXISTS ml_scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER,
        window_start TEXT NOT NULL,
        window_end TEXT NOT NULL,
        score REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        alert_id TEXT,
        rule_id TEXT NOT NULL,
        family TEXT NOT NULL,
        severity TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        hit_count INTEGER NOT NULL,
        payload_json TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS frame_summaries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER,
        timestamp TEXT NOT NULL,
        frame_type TEXT NOT NULL,
        subtype TEXT NOT NULL,
        bssid TEXT,
        ssid TEXT,
        channel INTEGER,
        rssi INTEGER
    )
    """,
)


def _security_value(raw: str) -> str:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return "unknown"
    if isinstance(value, str):
        return value or "unknown"
    if isinstance(value, list):
        modes = [str(item) for item in value if item and item != "unknown"]
        return modes[-1] if modes else "unknown"
    return "unknown"


class Database:
    """Thread-safe SQLite access with one connection per thread."""

    def __init__(self, path: str | Path = "data/wids.db") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_lock = threading.Lock()
        with self.connection() as connection:
            self._migrate(connection)

    def connection(self) -> sqlite3.Connection:
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = sqlite3.connect(self.path, check_same_thread=False)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            self._local.connection = connection
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connection()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _migrate(self, connection: sqlite3.Connection) -> None:
        with self._init_lock:
            connection.execute(DDL[0])
            row = connection.execute(
                "SELECT MAX(version) AS version FROM schema_version"
            ).fetchone()
            current = int(row["version"] or 0)
            if current > SCHEMA_VERSION:
                raise RuntimeError("Database schema is newer than this application")
            if current < SCHEMA_VERSION:
                for statement in DDL[1:]:
                    connection.execute(statement)
                columns = {
                    row["name"] for row in connection.execute("PRAGMA table_info(aps)").fetchall()
                }
                if "flag_reason" not in columns:
                    connection.execute("ALTER TABLE aps ADD COLUMN flag_reason TEXT")
                if "status" not in columns:
                    connection.execute(
                        "ALTER TABLE aps ADD COLUMN status TEXT NOT NULL DEFAULT 'Trusted'"
                    )
                connection.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, datetime.now(tz=UTC).isoformat()),
                )
                connection.commit()

    def start_run(self, source: str, fresh: bool = False) -> int:
        with self.transaction() as connection:
            if fresh:
                connection.execute("DELETE FROM ml_scores")
                connection.execute("DELETE FROM alerts")
                connection.execute("DELETE FROM incidents")
                connection.execute("DELETE FROM frame_summaries")
                connection.execute("DELETE FROM aps")
            cursor = connection.execute(
                "INSERT INTO runs(started_at, source, status) VALUES (?, ?, 'running')",
                (datetime.now(tz=UTC).isoformat(), source),
            )
            return int(cursor.lastrowid)

    def finish_run(self, run_id: int, frame_count: int, window_count: int) -> None:
        with self.transaction() as connection:
            connection.execute(
                "UPDATE runs SET finished_at = ?, frame_count = ?, window_count = ?, status = 'complete' WHERE id = ?",
                (datetime.now(tz=UTC).isoformat(), frame_count, window_count, run_id),
            )

    def save_inventory(
        self,
        inventory: APInventory,
        flagged: set[str] | None = None,
        flag_reasons: dict[str, str] | None = None,
    ) -> None:
        flagged = flagged or set()
        flag_reasons = flag_reasons or {}
        statuses = {
            bssid: (
                "Flagged"
                if bssid in flagged
                else ("Watch" if flag_reasons.get(bssid) else "Trusted")
            )
            for bssid in inventory.aps
        }
        now = datetime.now(tz=UTC).isoformat()
        with self.transaction() as connection:
            for bssid, ap in inventory.aps.items():
                connection.execute(
                    """
                    INSERT INTO aps(bssid, ssid, oui, channels, rssi, security, trust_score, flagged, flag_reason, status, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        ssid = excluded.ssid,
                        oui = excluded.oui,
                        channels = excluded.channels,
                        rssi = excluded.rssi,
                        security = excluded.security,
                        trust_score = excluded.trust_score,
                        flagged = excluded.flagged,
                        flag_reason = excluded.flag_reason,
                        status = excluded.status,
                        updated_at = excluded.updated_at
                    """,
                    (
                        bssid,
                        ap.ssid,
                        ap.oui,
                        json.dumps(list(ap.channels)),
                        round(float(ap.mean_rssi), 1) if ap.mean_rssi is not None else None,
                        json.dumps(ap.security),
                        ap.trust_score,
                        1 if bssid in flagged else 0,
                        flag_reasons.get(bssid),
                        statuses[bssid],
                        now,
                    ),
                )

    def save_alert(self, alert: Alert, run_id: int | None = None) -> None:
        payload = alert.model_dump(mode="json")
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO alerts(
                    id, run_id, timestamp, family, severity, risk_score,
                    bssids, ssids, clients, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.id,
                    run_id,
                    alert.timestamp.isoformat(),
                    alert.family,
                    alert.severity,
                    alert.risk_score,
                    json.dumps(list(alert.bssids)),
                    json.dumps(list(alert.ssids)),
                    json.dumps(list(alert.clients)),
                    json.dumps(payload),
                ),
            )

    def save_ml_scores(self, run_id: int, scores: list[dict[str, Any]]) -> None:
        with self.transaction() as connection:
            connection.executemany(
                "INSERT INTO ml_scores(run_id, window_start, window_end, score) VALUES (?, ?, ?, ?)",
                [
                    (run_id, item["window_start"], item["window_end"], item["score"])
                    for item in scores
                ],
            )

    def save_frame_summaries(self, run_id: int, summaries: list[dict[str, Any]]) -> None:
        with self.transaction() as connection:
            connection.executemany(
                """
                INSERT INTO frame_summaries(run_id, timestamp, frame_type, subtype, bssid, ssid, channel, rssi)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        run_id,
                        item["timestamp"],
                        item["frame_type"],
                        item["subtype"],
                        item.get("bssid"),
                        item.get("ssid"),
                        item.get("channel"),
                        item.get("rssi"),
                    )
                    for item in summaries
                ],
            )

    def incident_count(self) -> int:
        row = self.connection().execute("SELECT COUNT(*) AS count FROM incidents").fetchone()
        return int(row["count"])

    def frame_count(self) -> int:
        row = self.connection().execute("SELECT COUNT(*) AS count FROM frame_summaries").fetchone()
        return int(row["count"])

    def latest_run(self) -> dict[str, Any] | None:
        row = (
            self.connection()
            .execute(
                "SELECT id, started_at, finished_at, source, frame_count, window_count, status "
                "FROM runs ORDER BY id DESC LIMIT 1"
            )
            .fetchone()
        )
        return dict(row) if row else None

    def get_stats(self, run: str = "latest") -> dict[str, Any]:
        connection = self.connection()
        latest = self.latest_run()
        run_id = int(latest["id"]) if latest is not None else None
        if run == "all":
            frame_row = connection.execute(
                "SELECT COALESCE(SUM(frame_count), 0) AS frames FROM runs"
            ).fetchone()
            window_row = connection.execute(
                "SELECT COALESCE(SUM(window_count), 0) AS windows FROM runs"
            ).fetchone()
            severity = connection.execute(
                "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity ORDER BY severity"
            ).fetchall()
            family = connection.execute(
                "SELECT family, COUNT(*) AS count FROM alerts GROUP BY family ORDER BY family"
            ).fetchall()
            ml_rows = connection.execute(
                "SELECT window_start, score FROM ml_scores ORDER BY window_start"
            ).fetchall()
        elif run_id is None:
            frame_row = {"frames": 0}
            window_row = {"windows": 0}
            severity = []
            family = []
            ml_rows = []
        else:
            frame_row = connection.execute(
                "SELECT frame_count AS frames FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
            window_row = connection.execute(
                "SELECT window_count AS windows FROM runs WHERE id = ?", (run_id,)
            ).fetchone()
            severity = connection.execute(
                "SELECT severity, COUNT(*) AS count FROM alerts WHERE run_id = ? "
                "GROUP BY severity ORDER BY severity",
                (run_id,),
            ).fetchall()
            family = connection.execute(
                "SELECT family, COUNT(*) AS count FROM alerts WHERE run_id = ? "
                "GROUP BY family ORDER BY family",
                (run_id,),
            ).fetchall()
            ml_rows = connection.execute(
                "SELECT window_start, score FROM ml_scores WHERE run_id = ? ORDER BY window_start",
                (run_id,),
            ).fetchall()
        ml_points = [
            {"timestamp": row["window_start"], "score": float(row["score"] or 0.0)}
            for row in ml_rows
        ]
        if len(ml_points) > 200:
            stride = (len(ml_points) + 199) // 200
            ml_points = ml_points[::stride][:200]
        return {
            "frames_processed": int(frame_row["frames"] or 0),
            "windows": int(window_row["windows"] or 0),
            "alerts_by_severity": {row["severity"]: row["count"] for row in severity},
            "alerts_by_family": {row["family"]: row["count"] for row in family},
            "latest_ml_scores": ml_points,
            "run_id": run_id,
            "run_started_at": latest["started_at"] if latest and run != "all" else None,
        }

    def list_alerts(
        self,
        *,
        severity: str | None = None,
        family: str | None = None,
        since: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        clauses = []
        params: list[Any] = []
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity)
        if family is not None:
            clauses.append("family = ?")
            params.append(family)
        if since is not None:
            clauses.append("timestamp >= ?")
            params.append(since)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([limit, offset])
        rows = (
            self.connection()
            .execute(
                f"SELECT payload_json FROM alerts{where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                params,
            )
            .fetchall()
        )
        return [json.loads(row["payload_json"]) for row in rows]

    def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        row = (
            self.connection()
            .execute(
                "SELECT payload_json FROM alerts WHERE id = ?",
                (alert_id,),
            )
            .fetchone()
        )
        return json.loads(row["payload_json"]) if row else None

    def list_aps(self) -> list[dict[str, Any]]:
        rows = (
            self.connection()
            .execute(
                "SELECT bssid, ssid, oui, channels, rssi, security, trust_score, flagged, flag_reason, status FROM aps ORDER BY bssid"
            )
            .fetchall()
        )
        return [
            {
                "bssid": row["bssid"],
                "ssid": row["ssid"],
                "oui": row["oui"],
                "channels": json.loads(row["channels"]),
                "rssi": round(float(row["rssi"]), 1) if row["rssi"] is not None else None,
                "security": _security_value(row["security"]),
                "trust_score": row["trust_score"],
                "flagged": bool(row["flagged"]),
                "flag_reason": row["flag_reason"],
                "status": row["status"],
            }
            for row in rows
        ]
