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

SCHEMA_VERSION = 1
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
                connection.execute(
                    "INSERT OR REPLACE INTO schema_version(version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, datetime.now(tz=UTC).isoformat()),
                )
                connection.commit()

    def start_run(self, source: str) -> int:
        with self.transaction() as connection:
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

    def save_inventory(self, inventory: APInventory, flagged: set[str] | None = None) -> None:
        flagged = flagged or set()
        now = datetime.now(tz=UTC).isoformat()
        with self.transaction() as connection:
            for bssid, ap in inventory.aps.items():
                connection.execute(
                    """
                    INSERT INTO aps(bssid, ssid, oui, channels, rssi, security, trust_score, flagged, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(bssid) DO UPDATE SET
                        ssid = excluded.ssid,
                        oui = excluded.oui,
                        channels = excluded.channels,
                        rssi = excluded.rssi,
                        security = excluded.security,
                        trust_score = excluded.trust_score,
                        flagged = excluded.flagged,
                        updated_at = excluded.updated_at
                    """,
                    (
                        bssid,
                        ap.ssid,
                        ap.oui,
                        json.dumps(list(ap.channels)),
                        ap.mean_rssi,
                        json.dumps(list(ap.security)),
                        ap.trust_score,
                        1 if bssid in flagged else 0,
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

    def get_stats(self) -> dict[str, Any]:
        connection = self.connection()
        frame_count = connection.execute(
            "SELECT COUNT(*) AS count FROM frame_summaries"
        ).fetchone()["count"]
        run_rows = connection.execute(
            "SELECT COALESCE(SUM(window_count), 0) AS windows FROM runs"
        ).fetchone()
        severity = connection.execute(
            "SELECT severity, COUNT(*) AS count FROM alerts GROUP BY severity ORDER BY severity"
        ).fetchall()
        family = connection.execute(
            "SELECT family, COUNT(*) AS count FROM alerts GROUP BY family ORDER BY family"
        ).fetchall()
        ml = connection.execute(
            """
            SELECT timestamp, json_extract(payload_json, '$.ml_anomaly_score') AS score
            FROM alerts ORDER BY timestamp DESC LIMIT 30
            """
        ).fetchall()
        return {
            "frames_processed": int(frame_count),
            "windows": int(run_rows["windows"] or 0),
            "alerts_by_severity": {row["severity"]: row["count"] for row in severity},
            "alerts_by_family": {row["family"]: row["count"] for row in family},
            "latest_ml_scores": [
                {"timestamp": row["timestamp"], "score": float(row["score"] or 0.0)}
                for row in reversed(ml)
            ],
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
                "SELECT bssid, ssid, oui, channels, rssi, security, trust_score, flagged FROM aps ORDER BY bssid"
            )
            .fetchall()
        )
        return [
            {
                "bssid": row["bssid"],
                "ssid": row["ssid"],
                "oui": row["oui"],
                "channels": json.loads(row["channels"]),
                "rssi": row["rssi"],
                "security": json.loads(row["security"]),
                "trust_score": row["trust_score"],
                "flagged": bool(row["flagged"]),
            }
            for row in rows
        ]
