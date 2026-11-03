"""Pluggable NanoSIEM exporters with idempotent delivery."""

from __future__ import annotations

import json
import logging
import os
import queue
import ssl
import threading
import time
import urllib.parse
import urllib.request
from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path
from typing import Any

from wids_ai.correlation.schema import Alert
from wids_ai.siem.mapping import alert_to_event
from wids_ai.siem.schema import NormalizedEvent
from wids_ai.storage.db import Database

LOGGER = logging.getLogger(__name__)


class Sink(ABC):
    @abstractmethod
    def deliver(self, event: NormalizedEvent, payload: dict[str, Any]) -> bool | None:
        """Deliver one event. Return False when a bounded queue drops it."""

    def close(self) -> None:
        return None


class FileSink(Sink):
    """Append NDJSON with bounded file rotation."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_bytes: int = 5 * 1024 * 1024,
        backup_count: int = 3,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self._lock = threading.Lock()

    def _rotate(self) -> None:
        if not self.path.exists() or self.path.stat().st_size < self.max_bytes:
            return
        if self.backup_count <= 0:
            self.path.unlink(missing_ok=True)
            return
        oldest = self.path.with_name(f"{self.path.name}.{self.backup_count}")
        oldest.unlink(missing_ok=True)
        for index in range(self.backup_count - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            target = self.path.with_name(f"{self.path.name}.{index + 1}")
            if source.exists():
                source.replace(target)
        self.path.replace(self.path.with_name(f"{self.path.name}.1"))

    def deliver(self, event: NormalizedEvent, payload: dict[str, Any]) -> bool:
        line = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            self._rotate()
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(f"{line}\n")
                handle.flush()
        return True

    def close(self) -> None:
        return None


class HttpSink(Sink):
    """Asynchronous HTTPS sink with bounded queue, retries, and timeout."""

    def __init__(
        self,
        url: str,
        *,
        token_env: str | None = None,
        timeout: float = 5.0,
        queue_size: int = 100,
        retries: int = 3,
        backoff: float = 0.25,
        failure_callback: Callable[[str], None] | None = None,
    ) -> None:
        parsed = urllib.parse.urlsplit(url)
        local_http = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1"}
        if not parsed.hostname or (parsed.scheme != "https" and not local_http):
            raise ValueError("SIEM HTTP endpoint must use HTTPS unless localhost")
        self.url = url
        self._token_env = token_env
        self._token = os.environ.get(token_env, "") if token_env else ""
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self._failure_callback = failure_callback
        self.queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=queue_size)
        self.thread = threading.Thread(target=self._worker, daemon=True, name="wids-siem")
        self.thread.start()

    def _report_failure(self, message: str) -> None:
        LOGGER.warning(message)
        if self._failure_callback is not None:
            self._failure_callback(f"SIEM export failed: {message}")

    def deliver(self, event: NormalizedEvent, payload: dict[str, Any]) -> bool:
        try:
            self.queue.put_nowait(payload)
            return True
        except queue.Full:
            self._report_failure(f"queue full; dropped event {event.event_id}")
            return False

    def _worker(self) -> None:
        while True:
            payload = self.queue.get()
            try:
                if payload is None:
                    return
                self._post(payload)
            finally:
                self.queue.task_done()

    def _post(self, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": "wids-ai"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        context = ssl.create_default_context() if self.url.startswith("https://") else None
        for attempt in range(self.retries + 1):
            try:
                request = urllib.request.Request(
                    self.url,
                    data=body,
                    headers=headers,
                    method="POST",
                )
                with urllib.request.urlopen(
                    request,
                    timeout=self.timeout,
                    context=context,
                ) as response:
                    if 200 <= response.status < 300:
                        return
                    raise RuntimeError(f"SIEM HTTP {response.status}")
            except Exception as exc:
                if attempt >= self.retries:
                    self._report_failure(f"after {self.retries + 1} attempts: {type(exc).__name__}")
                    return
                time.sleep(min(self.backoff * (2**attempt), 4.0))

    def close(self) -> None:
        try:
            self.queue.put(None, timeout=1.0)
        except queue.Full:
            LOGGER.warning("SIEM queue still full during shutdown")
        self.thread.join(timeout=self.timeout + 1.0)


class NanoSIEMExporter:
    """Export alerts once per alert id and hit count state."""

    def __init__(
        self,
        db: Database,
        sinks: list[Sink],
        sensor_name: str | None = None,
        failure_callback: Callable[[str], None] | None = None,
    ) -> None:
        self.db = db
        self.sinks = sinks
        self.sensor_name = sensor_name
        self._failure_callback = failure_callback
        self.failed: list[Alert] = []

    def export(self, alerts: list[Alert]) -> int:
        sent = 0
        self.failed = []
        for alert in alerts:
            key = f"{alert.id}:{alert.hit_count}"
            if self.db.was_exported(key):
                continue
            event = alert_to_event(alert, host=self.sensor_name)
            payload = event.model_dump(mode="json")
            success = False
            for sink in self.sinks:
                try:
                    accepted = sink.deliver(event, payload)
                    if accepted is not False:
                        success = True
                except Exception as exc:
                    message = f"sink failure for {alert.id}: {type(exc).__name__}"
                    LOGGER.warning("SIEM %s", message)
                    if self._failure_callback is not None:
                        self._failure_callback(f"SIEM export failed: {message}")
            if success:
                self.db.mark_exported(key)
                sent += 1
            else:
                self.failed.append(alert)
        return sent

    def close(self) -> None:
        for sink in self.sinks:
            try:
                sink.close()
            except Exception as exc:
                LOGGER.warning("SIEM sink shutdown failed: %s", type(exc).__name__)
