"""Evaluate the benign-trained anomaly model on synthetic mixed captures.

Training uses only the first 70 percent of benign windows by time. Evaluation
uses the held-out benign tail and labeled synthetic attack captures.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np

from wids_ai.capture.base import PcapSource
from wids_ai.features.extractors import FeatureRow, batch_extract
from wids_ai.features.windowing import WindowConfig
from wids_ai.ml.baseline import ML_SCOPES, chronological_split, load_benign_rows
from wids_ai.ml.isolation_forest import (
    aggregate_window_scores,
    score_rows,
    train_isolation_forest,
    write_scores,
)
from wids_ai.parser.dot11 import parse_frame

MODEL_NAMES = (
    "mixed_evil_twin",
    "mixed_deauth_burst",
    "mixed_karma_probe_responses",
    "mixed_beacon_sequence_anomaly",
)


def _features(path: Path) -> list[FeatureRow]:
    frames = [
        frame for packet in PcapSource(path).packets() if (frame := parse_frame(packet)) is not None
    ]
    frame = batch_extract(frames, WindowConfig(10, 5))
    frame = frame[frame["scope"].isin(ML_SCOPES)]
    return [FeatureRow.model_validate(item.to_dict()) for _, item in frame.iterrows()]


def _window_scores(model: Any, rows: list[FeatureRow]) -> dict[tuple[datetime, datetime], float]:
    scores = aggregate_window_scores(score_rows(model, rows))
    return {(item.window_start, item.window_end): item.anomaly_score for item in scores}


def roc_auc(labels: np.ndarray, scores: np.ndarray) -> float:
    """Compute ROC-AUC from pairwise ranking."""
    positives = scores[labels == 1]
    negatives = scores[labels == 0]
    if len(positives) == 0 or len(negatives) == 0:
        return float("nan")
    comparisons = (positives[:, None] > negatives[None, :]).mean()
    ties = (positives[:, None] == negatives[None, :]).mean() * 0.5
    return float(comparisons + ties)


def pr_auc(labels: np.ndarray, scores: np.ndarray) -> float:
    """Compute average precision from descending-score ranking."""
    positives = int(labels.sum())
    if positives == 0:
        return float("nan")
    order = np.argsort(-scores, kind="stable")
    sorted_labels = labels[order]
    cumulative = np.cumsum(sorted_labels)
    precision = cumulative / np.arange(1, len(sorted_labels) + 1)
    recall = cumulative / positives
    precision = np.concatenate(([1.0], precision))
    recall = np.concatenate(([0.0], recall))
    return float(np.sum(np.diff(recall) * precision[1:]))


def _window_label(
    window: tuple[datetime, datetime],
    start: datetime,
    end: datetime,
) -> int:
    window_start, window_end = window
    return int(window_end >= start and window_start <= end)


def evaluate(dataset: Path, output: Path) -> dict[str, object]:
    labels_payload = json.loads((dataset / "labels.json").read_text(encoding="utf-8"))
    metadata = {item["scenario"]: item for item in labels_payload["scenarios"]}
    benign = load_benign_rows(dataset / "benign_baseline.pcap")
    training, held_out = chronological_split(benign, 0.7)
    model = train_isolation_forest(training, output / "model", seed=42, contamination=0.05)
    held_out_scores = _window_scores(model, held_out)
    held_out_values = list(held_out_scores.values())
    threshold = float(np.quantile(held_out_values, 0.95)) if held_out_values else 1.0
    false_positives = sum(value > threshold for value in held_out_values)
    benign_fpr = false_positives / len(held_out_values) if held_out_values else 0.0

    results: dict[str, object] = {}
    for name in MODEL_NAMES:
        attack_rows = _features(dataset / f"{name}.pcap")
        scores = _window_scores(model, attack_rows)
        attack_start = datetime.fromisoformat(metadata[name]["details"]["attack_start"])
        attack_end = datetime.fromisoformat(metadata[name]["details"]["attack_end"])
        inside = [
            value
            for window, value in scores.items()
            if _window_label(window, attack_start, attack_end)
        ]
        outside = [
            value
            for window, value in scores.items()
            if not _window_label(window, attack_start, attack_end)
        ]
        labels = np.array([_window_label(window, attack_start, attack_end) for window in scores])
        score_values = np.array(list(scores.values()))
        result = {
            "mean_inside": float(np.mean(inside)) if inside else float("nan"),
            "mean_outside": float(np.mean(outside)) if outside else float("nan"),
            "roc_auc": roc_auc(labels, score_values),
            "pr_auc": pr_auc(labels, score_values),
            "windows_inside": len(inside),
            "windows_outside": len(outside),
            "attack_start": attack_start.isoformat(),
            "attack_end": attack_end.isoformat(),
        }
        results[name] = result
        write_scores(
            score_rows(model, attack_rows),
            output / f"{name}_scores.json",
        )
    evaluation = {
        "synthetic_data": True,
        "notes": (
            "Synthetic fixtures only. Metrics are not evidence of field accuracy. "
            "The model is trained only on the first 70 percent of benign windows; "
            "held-out benign windows define the 95th-percentile false positive rate."
        ),
        "training_windows": len(training),
        "held_out_windows": len(held_out),
        "held_out_fpr_at_95th_percentile": benign_fpr,
        "held_out_threshold": threshold,
        "model_sha256": model.metadata.model_sha256,
        "scenarios": results,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "evaluation.json").write_text(
        json.dumps(evaluation, indent=2) + "\n",
        encoding="utf-8",
    )
    return evaluation


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate WIDS-AI anomaly model on synthetic data")
    parser.add_argument("--dataset", type=Path, default=Path("data/synthetic"))
    parser.add_argument("--out", type=Path, default=Path("eval/ml"))
    args = parser.parse_args()
    evaluation = evaluate(args.dataset, args.out)
    print(
        f"Synthetic evaluation: {evaluation['training_windows']} training windows, "
        f"{evaluation['held_out_windows']} held-out benign windows"
    )
    print(f"held-out FPR at 95th percentile: {evaluation['held_out_fpr_at_95th_percentile']:.4f}")
    for name, result in evaluation["scenarios"].items():
        print(
            f"{name}: inside={result['mean_inside']:.4f} "
            f"outside={result['mean_outside']:.4f} "
            f"ROC-AUC={result['roc_auc']:.4f} PR-AUC={result['pr_auc']:.4f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
