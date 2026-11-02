"""Benign-only feature matrix construction for anomaly training."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final

import numpy as np
import pandas as pd

from wids_ai.capture.base import PcapSource
from wids_ai.features.extractors import FeatureRow, batch_extract
from wids_ai.features.windowing import WindowConfig
from wids_ai.parser.dot11 import parse_frame

NUMERIC_FEATURES: Final[tuple[str, ...]] = (
    "frame_count",
    "beacon_count",
    "beacon_interval_mean",
    "beacon_interval_std",
    "beacon_interval_jitter",
    "seq_gap_count",
    "seq_duplicate_count",
    "probe_response_count",
    "distinct_ssids_answered",
    "deauth_count",
    "disassoc_count",
    "rssi_mean",
    "rssi_std",
    "channel_change_count",
    "deauth_received_rate",
    "probe_request_count",
    "distinct_ssids_probed",
    "distinct_bssids",
    "distinct_ouis",
    "distinct_channels",
    "rsn_mismatch",
    "rssi_spread",
    "beacon_ratio",
    "probe_request_ratio",
    "probe_response_ratio",
    "deauth_ratio",
    "disassoc_ratio",
    "authentication_ratio",
    "association_ratio",
    "action_ratio",
    "broadcast_deauth_count",
    "deauth_reason_distinct",
    "deauth_reason_skew",
    "seq_backward_count",
)
IDENTIFIER_COLUMNS: Final[tuple[str, ...]] = (
    "window_start",
    "window_end",
    "scope",
    "group",
    "observed_bssids",
    "observed_ssids",
    "observed_clients",
    "observed_beacon_channels",
    "observed_security_modes",
    "rssi_by_bssid",
)


SCOPE_FEATURES: Final[dict[str, tuple[str, ...]]] = {
    "bssid": (
        "frame_count",
        "beacon_count",
        "beacon_interval_mean",
        "beacon_interval_std",
        "beacon_interval_jitter",
        "seq_gap_count",
        "seq_duplicate_count",
        "probe_response_count",
        "distinct_ssids_answered",
        "deauth_count",
        "disassoc_count",
        "rssi_mean",
        "rssi_std",
        "channel_change_count",
        "deauth_received_rate",
        "broadcast_deauth_count",
        "deauth_reason_skew",
        "seq_backward_count",
        "beacon_ratio",
        "probe_response_ratio",
        "deauth_ratio",
    ),
    "client": (
        "frame_count",
        "probe_request_count",
        "distinct_ssids_probed",
        "deauth_count",
        "deauth_received_rate",
        "rssi_mean",
        "rssi_std",
        "deauth_ratio",
        "probe_request_ratio",
    ),
    "ssid": (
        "frame_count",
        "beacon_count",
        "beacon_interval_mean",
        "beacon_interval_std",
        "beacon_interval_jitter",
        "distinct_bssids",
        "distinct_ouis",
        "distinct_channels",
        "rsn_mismatch",
        "rssi_spread",
        "probe_response_count",
        "distinct_ssids_answered",
        "beacon_ratio",
        "probe_response_ratio",
    ),
}


@dataclass(frozen=True)
class TrainingMatrix:
    """Finite numeric matrix with stable column order and imputation values."""

    values: np.ndarray
    feature_names: tuple[str, ...]
    imputation_medians: MappingProxyType[str, float]
    row_count: int


def _as_frame(rows: Iterable[FeatureRow] | pd.DataFrame) -> pd.DataFrame:
    if isinstance(rows, pd.DataFrame):
        return rows.copy()
    return pd.DataFrame([row.model_dump() for row in rows])


def build_training_matrix(
    rows: Iterable[FeatureRow] | pd.DataFrame,
    feature_names: tuple[str, ...] = NUMERIC_FEATURES,
    imputation_medians: dict[str, float] | None = None,
) -> TrainingMatrix:
    """Select numeric features, replace non-finite values, and preserve column order."""
    frame = _as_frame(rows)
    missing = [name for name in feature_names if name not in frame.columns]
    if missing:
        raise ValueError(f"Missing feature columns: {missing}")
    numeric = frame.loc[:, list(feature_names)].apply(pd.to_numeric, errors="coerce")
    numeric = numeric.replace([np.inf, -np.inf], np.nan)
    medians = (
        dict(imputation_medians)
        if imputation_medians is not None
        else {
            name: (float(numeric[name].median(skipna=True)) if numeric[name].notna().any() else 0.0)
            for name in feature_names
        }
    )
    for name in feature_names:
        median = float(medians.get(name, 0.0))
        if not np.isfinite(median):
            median = 0.0
        numeric[name] = numeric[name].fillna(median)
    values = numeric.to_numpy(dtype=np.float64, copy=True)
    if not np.isfinite(values).all():
        raise ValueError("Feature matrix contains non-finite values after cleaning")
    return TrainingMatrix(
        values=values,
        feature_names=feature_names,
        imputation_medians=MappingProxyType({name: float(medians[name]) for name in feature_names}),
        row_count=len(numeric),
    )


ML_SCOPES: Final[tuple[str, ...]] = ("bssid", "client", "ssid")


def filter_ml_rows(rows: list[FeatureRow], scopes: tuple[str, ...] = ML_SCOPES) -> list[FeatureRow]:
    """Keep rows for the requested scopes."""
    return [row for row in rows if row.scope in scopes]


def load_benign_rows(
    pcap: str | Path,
    config: WindowConfig | None = None,
) -> list[FeatureRow]:
    """Parse one PCAP and extract all feature rows without reading labels."""
    frames = [
        frame for packet in PcapSource(pcap).packets() if (frame := parse_frame(packet)) is not None
    ]
    feature_frame = batch_extract(frames, config or WindowConfig())
    rows = [FeatureRow.model_validate(item.to_dict()) for _, item in feature_frame.iterrows()]
    return filter_ml_rows(rows)


def chronological_split(
    rows: list[FeatureRow],
    train_fraction: float = 0.7,
) -> tuple[list[FeatureRow], list[FeatureRow]]:
    """Split rows by window time, with the earliest fraction used for training."""
    if not 0.0 < train_fraction < 1.0:
        raise ValueError("train_fraction must be between 0 and 1")
    ordered = sorted(rows, key=lambda row: (row.window_start, row.scope, row.group))
    if not ordered:
        return [], []
    first = ordered[0].window_start
    last = ordered[-1].window_start
    cut = first + (last - first) * train_fraction
    training = [row for row in ordered if row.window_start <= cut]
    held_out = [row for row in ordered if row.window_start > cut]
    return training, held_out
