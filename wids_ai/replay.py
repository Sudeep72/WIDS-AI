"""Accelerated PCAP replay through the real detection pipeline."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

from wids_ai.correlation.scorer import CorrelationConfig
from wids_ai.inventory import APInventory
from wids_ai.pipeline import analyze_frames, parse_pcap
from wids_ai.rules.engine import load_rules
from wids_ai.storage.db import Database

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class ReplayResult:
    frames: int
    windows: int
    alerts: int


def replay_pcap(
    pcap: str | Path,
    database: Database,
    *,
    inventory_path: str | Path | None = None,
    model_root: str | Path = "models",
    rules_dir: str | Path = "wids_ai/rules/rules",
    trusted_model_root: str | Path | None = None,
    window_seconds: float = 10.0,
    step_seconds: float = 5.0,
    speed: float = 20.0,
    loop: bool = False,
    fresh: bool = True,
    sleep: bool = True,
    on_alerts=None,
) -> ReplayResult:
    """Replay a PCAP and persist alerts as each simulated window closes."""
    source = Path(pcap)
    frame_rows = parse_pcap(source)
    if not frame_rows:
        return ReplayResult(frames=0, windows=0, alerts=0)
    inventory = (
        APInventory.load(inventory_path)
        if inventory_path is not None
        else APInventory.from_frames(frame_rows)
    )
    load_rules(rules_dir)
    trusted_root = Path(trusted_model_root) if trusted_model_root is not None else Path(model_root)
    result = analyze_frames(
        frame_rows,
        inventory,
        rules_dir=rules_dir,
        model_root=model_root,
        trusted_model_root=trusted_root,
        window_seconds=window_seconds,
        step_seconds=step_seconds,
        correlation_config=CorrelationConfig(),
    )
    alerts = list(result.alerts)
    ml_scores = list(result.ml_scores)
    inventory.observe_frames(frame_rows)
    flagged: set[str] = set()
    flag_reasons: dict[str, str] = {}
    trusted_bssids = {bssid for bssid, ap in inventory.aps.items() if ap.trust_score >= 50}
    ssids_by_bssid: dict[str, str] = {}
    for frame in frame_rows:
        if frame.bssid and frame.ssid:
            ssids_by_bssid.setdefault(frame.bssid, frame.ssid)
    for bssid, ssid in ssids_by_bssid.items():
        duplicate = any(
            other != bssid and other_ssid == ssid for other, other_ssid in ssids_by_bssid.items()
        )
        if bssid not in trusted_bssids:
            flagged.add(bssid)
            flag_reasons[bssid] = "not in trusted inventory"
            inventory.adjust_trust(bssid, -10)
        elif duplicate:
            flag_reasons[bssid] = "SSID shared with untrusted AP"
    run_id = database.start_run(str(source), fresh=fresh)
    database.save_inventory(inventory, flagged, flag_reasons)
    if sleep and speed > 0:
        simulated = (frame_rows[-1].timestamp - frame_rows[0].timestamp).total_seconds()
        time.sleep(min(simulated / speed, 1.0))
    for alert in alerts:
        database.save_alert(alert, run_id)
    score_windows = {}
    for score in ml_scores:
        score_windows.setdefault(score.window_start, []).append(
            (score.window_end, score.anomaly_score)
        )
    database.save_ml_scores(
        run_id,
        [
            {
                "window_start": start.isoformat(),
                "window_end": max(end for end, _score in values).isoformat(),
                "score": max(score for _end, score in values),
            }
            for start, values in sorted(score_windows.items())
        ],
    )
    if on_alerts is not None:
        try:
            on_alerts(alerts)
        except Exception as exc:
            LOGGER.warning("Downstream alert handler failed: %s", type(exc).__name__)
    database.finish_run(run_id, len(frame_rows), result.window_count)
    LOGGER.info("Replay wrote %d alerts from %d frames", len(alerts), len(frame_rows))
    return ReplayResult(frames=len(frame_rows), windows=result.window_count, alerts=len(alerts))
