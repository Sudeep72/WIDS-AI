"""Accelerated PCAP replay through the real detection pipeline."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

from wids_ai.capture.base import PcapSource
from wids_ai.correlation.scorer import CorrelationConfig, correlate
from wids_ai.features.extractors import FeatureRow, extract_features
from wids_ai.features.windowing import WindowConfig
from wids_ai.inventory import APInventory
from wids_ai.ml.isolation_forest import aggregate_window_scores, load_model, score_rows
from wids_ai.parser.dot11 import parse_frame
from wids_ai.rules.engine import deduplicate, evaluate_rules, load_rules
from wids_ai.storage.db import Database

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class ReplayResult:
    frames: int
    windows: int
    alerts: int


def _score_alerts(
    incidents,
    feature_rows: list[FeatureRow],
    model_root: Path,
    inventory: APInventory,
    trusted_model_root: Path,
    correlation_config: CorrelationConfig,
):
    ml_scores = []
    for scope in ("bssid", "client", "ssid"):
        model_dir = model_root / scope
        if not (model_dir / "isolation_forest.joblib").is_file():
            continue
        model = load_model(model_dir, trusted_base=trusted_model_root)
        scope_rows = [row for row in feature_rows if row.scope == scope]
        if not scope_rows:
            continue
        scope_scores = score_rows(model, scope_rows)
        ml_scores.extend(aggregate_window_scores(scope_scores, method="max"))
    alerts = correlate(
        incidents,
        [item.anomaly_score for item in ml_scores],
        inventory,
        correlation_config,
    )
    return alerts, ml_scores


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
    sleep: bool = True,
) -> ReplayResult:
    """Replay a PCAP and persist alerts as each simulated window closes."""
    source = Path(pcap)
    inventory = (
        APInventory.load(inventory_path)
        if inventory_path is not None
        else APInventory.from_frames(
            frame
            for packet in PcapSource(source).packets()
            if (frame := parse_frame(packet)) is not None
        )
    )
    rules = load_rules(rules_dir)
    trusted_root = Path(trusted_model_root) if trusted_model_root is not None else Path(model_root)
    correlation_config = CorrelationConfig()
    frame_rows = [
        frame
        for packet in PcapSource(source).packets()
        if (frame := parse_frame(packet)) is not None
    ]
    if not frame_rows:
        return ReplayResult(frames=0, windows=0, alerts=0)
    feature_frame = extract_features(frame_rows, WindowConfig(window_seconds, step_seconds))
    feature_rows = [
        FeatureRow.model_validate(item.to_dict()) for _, item in feature_frame.iterrows()
    ]
    incidents = deduplicate(evaluate_rules(feature_rows, rules, frame_rows, inventory))
    alerts, ml_scores = _score_alerts(
        incidents,
        feature_rows,
        Path(model_root),
        inventory,
        trusted_root,
        correlation_config,
    )
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
            flagged.add(bssid)
            flag_reasons[bssid] = "duplicate SSID"
    run_id = database.start_run(str(source))
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
    database.finish_run(run_id, len(frame_rows), len(feature_rows))
    LOGGER.info("Replay wrote %d alerts from %d frames", len(alerts), len(frame_rows))
    return ReplayResult(frames=len(frame_rows), windows=len(feature_rows), alerts=len(alerts))
