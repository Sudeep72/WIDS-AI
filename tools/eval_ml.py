"""Evaluate benign-trained scope anomaly models on synthetic mixed captures."""

from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime
from pathlib import Path

import numpy as np

from wids_ai.capture.base import PcapSource
from wids_ai.features.extractors import FeatureRow, batch_extract
from wids_ai.features.windowing import WindowConfig
from wids_ai.ml.baseline import ML_SCOPES, chronological_split, load_benign_rows
from wids_ai.ml.isolation_forest import (
    aggregate_window_scores,
    score_rows,
    train_isolation_forest,
)
from wids_ai.parser.dot11 import parse_frame
from wids_ai.synthetic.generator import generate_dataset

MODEL_NAMES = (
    "mixed_evil_twin",
    "mixed_deauth_burst",
    "mixed_karma_probe_responses",
    "mixed_beacon_sequence_anomaly",
    "mixed_low_slow_deauth",
    "mixed_evil_twin_matching_oui",
)
SEEDS = (1, 2, 3, 42, 99)


def _features(path: Path) -> list[FeatureRow]:
    frames = [
        frame for packet in PcapSource(path).packets() if (frame := parse_frame(packet)) is not None
    ]
    frame = batch_extract(frames, WindowConfig(10, 5))
    frame = frame[frame["scope"].isin(ML_SCOPES)]
    return [FeatureRow.model_validate(item.to_dict()) for _, item in frame.iterrows()]


def roc_auc(labels: np.ndarray, scores: np.ndarray) -> float:
    positives = scores[labels == 1]
    negatives = scores[labels == 0]
    if len(positives) == 0 or len(negatives) == 0:
        return float("nan")
    comparisons = (positives[:, None] > negatives[None, :]).mean()
    ties = (positives[:, None] == negatives[None, :]).mean() * 0.5
    return float(comparisons + ties)


def pr_auc(labels: np.ndarray, scores: np.ndarray) -> float:
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


def _window_label(window: tuple[datetime, datetime], start: datetime, end: datetime) -> int:
    window_start, window_end = window
    return int(window_end >= start and window_start <= end)


def _score_dataset(dataset: Path, output: Path) -> dict[str, object]:
    labels_payload = json.loads((dataset / "labels.json").read_text(encoding="utf-8"))
    metadata = {item["scenario"]: item for item in labels_payload["scenarios"]}
    benign_rows = load_benign_rows(dataset / "benign_baseline.pcap")
    models = {}
    for scope in ML_SCOPES:
        scope_rows = [row for row in benign_rows if row.scope == scope]
        training, held_out = chronological_split(scope_rows, 0.7)
        model = train_isolation_forest(
            training,
            output / f"model-{scope}",
            seed=42,
            contamination=0.05,
        )
        models[scope] = (model, held_out)

    held_out_scores: dict[str, list[float]] = {"max": [], "top2_mean": []}
    for _scope, (model, held_out) in models.items():
        if not held_out:
            continue
        held_out_scores["max"].extend(
            item.anomaly_score
            for item in aggregate_window_scores(score_rows(model, held_out), method="max")
        )
        held_out_scores["top2_mean"].extend(
            item.anomaly_score
            for item in aggregate_window_scores(
                score_rows(model, held_out), method="top_k_mean", top_k=2
            )
        )
    thresholds = {
        method: float(np.quantile(values, 0.95)) if values else 1.0
        for method, values in held_out_scores.items()
    }
    fp_rates = {
        method: (
            sum(value > thresholds[method] for value in values) / len(values) if values else 0.0
        )
        for method, values in held_out_scores.items()
    }

    results: dict[str, object] = {}
    for name in MODEL_NAMES:
        rows = _features(dataset / f"{name}.pcap")
        per_window: dict[tuple[datetime, datetime], list[float]] = {}
        for scope, (model, _) in models.items():
            scope_rows = [row for row in rows if row.scope == scope]
            if not scope_rows:
                continue
            for item in score_rows(model, scope_rows):
                per_window.setdefault((item.row.window_start, item.row.window_end), []).append(
                    item.anomaly_score
                )
        aggregated: dict[str, dict[tuple[datetime, datetime], float]] = {
            "max": {},
            "top2_mean": {},
        }
        for window, values in per_window.items():
            ordered = sorted(values, reverse=True)
            aggregated["max"][window] = ordered[0]
            aggregated["top2_mean"][window] = float(np.mean(ordered[:2]))
        attack_start = datetime.fromisoformat(metadata[name]["details"]["attack_start"])
        attack_end = datetime.fromisoformat(metadata[name]["details"]["attack_end"])
        result: dict[str, object] = {
            "attack_start": attack_start.isoformat(),
            "attack_end": attack_end.isoformat(),
        }
        for method, scores in aggregated.items():
            labels = np.array(
                [_window_label(window, attack_start, attack_end) for window in scores]
            )
            values = np.array(list(scores.values()))
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
            result[method] = {
                "mean_inside": float(np.mean(inside)) if inside else float("nan"),
                "mean_outside": float(np.mean(outside)) if outside else float("nan"),
                "roc_auc": roc_auc(labels, values),
                "pr_auc": pr_auc(labels, values),
                "windows_inside": len(inside),
                "windows_outside": len(outside),
            }
        results[name] = result
    return {
        "synthetic_data": True,
        "seed": labels_payload["seed"],
        "scopes": list(ML_SCOPES),
        "thresholds": thresholds,
        "held_out_fpr_at_95th_percentile": fp_rates,
        "scenarios": results,
    }


def evaluate_all(dataset_root: Path, output: Path) -> dict[str, object]:
    seed_results: dict[str, object] = {}
    for seed in SEEDS:
        dataset = Path(tempfile.mkdtemp()) / f"synthetic-{seed}"
        generate_dataset(dataset, seed=seed)
        seed_results[str(seed)] = _score_dataset(dataset, output / f"seed-{seed}")
    summary: dict[str, object] = {}
    for name in MODEL_NAMES:
        summary[name] = {}
        for method in ("max", "top2_mean"):
            roc_values = [
                seed_results[str(seed)]["scenarios"][name][method]["roc_auc"] for seed in SEEDS
            ]
            pr_values = [
                seed_results[str(seed)]["scenarios"][name][method]["pr_auc"] for seed in SEEDS
            ]
            summary[name][method] = {
                "roc_auc_mean": float(np.mean(roc_values)),
                "roc_auc_std": float(np.std(roc_values)),
                "pr_auc_mean": float(np.mean(pr_values)),
                "pr_auc_std": float(np.std(pr_values)),
            }
    report = {
        "synthetic_data": True,
        "notes": (
            "Synthetic fixtures only. Metrics are not field accuracy claims. "
            "Each scope model is trained on the first 70 percent of that scope's benign windows. "
            "Held-out benign windows set the 95th-percentile threshold."
        ),
        "seeds": list(SEEDS),
        "scopes": list(ML_SCOPES),
        "summary": summary,
        "per_seed": seed_results,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "evaluation.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate WIDS-AI anomaly models on synthetic data"
    )
    parser.add_argument("--dataset", type=Path, default=Path("data/synthetic"))
    parser.add_argument("--out", type=Path, default=Path("eval/ml"))
    args = parser.parse_args()
    report = evaluate_all(args.dataset, args.out)
    for name, methods in report["summary"].items():
        for method, metrics in methods.items():
            print(
                f"{name} [{method}] ROC-AUC {metrics['roc_auc_mean']:.4f} "
                f"+/- {metrics['roc_auc_std']:.4f}, PR-AUC {metrics['pr_auc_mean']:.4f} "
                f"+/- {metrics['pr_auc_std']:.4f}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
