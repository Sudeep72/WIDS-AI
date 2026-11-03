"""Deterministic evaluation helpers for synthetic end-to-end runs."""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from wids_ai.correlation.scorer import CorrelationConfig, correlate
from wids_ai.ml.baseline import load_benign_rows
from wids_ai.ml.isolation_forest import train_isolation_forest
from wids_ai.pipeline import AnalysisResult, analyze_pcap, build_inventory
from wids_ai.rules.engine import load_rules
from wids_ai.synthetic.generator import ATTACK_WINDOW_TOLERANCE_SECONDS, generate_dataset

SEEDS = (1, 2, 3, 42, 99)
FAMILIES = (
    "evil_twin_rogue_ap",
    "deauth_disassoc_anomaly",
    "probe_response_karma",
    "beacon_management_anomaly",
)
BENIGN_SCENARIOS = ("benign_baseline", "benign_noisy")
POSITIVE_SCENARIOS = (
    "mixed_evil_twin",
    "mixed_deauth_burst",
    "mixed_karma_probe_responses",
    "mixed_beacon_sequence_anomaly",
    "mixed_low_slow_deauth",
    "mixed_evil_twin_matching_oui",
)
SCENARIO_FAMILIES = {
    "mixed_evil_twin": "evil_twin_rogue_ap",
    "mixed_deauth_burst": "deauth_disassoc_anomaly",
    "mixed_karma_probe_responses": "probe_response_karma",
    "mixed_beacon_sequence_anomaly": "beacon_management_anomaly",
    "mixed_low_slow_deauth": "deauth_disassoc_anomaly",
    "mixed_evil_twin_matching_oui": "evil_twin_rogue_ap",
}
EXPECTED_MISSES = {"mixed_low_slow_deauth"}
TOLERANCE = timedelta(seconds=ATTACK_WINDOW_TOLERANCE_SECONDS)


@dataclass(frozen=True)
class SeedArtifacts:
    seed: int
    dataset: Path
    work_root: Path
    inventory: Any
    model_root: Path
    labels: dict[str, dict[str, Any]]
    results: dict[str, AnalysisResult]
    rules_only: dict[str, list[Any]]


def _load_labels(dataset: Path) -> dict[str, dict[str, Any]]:
    payload = json.loads((dataset / "labels.json").read_text(encoding="utf-8"))
    return {item["scenario"]: item for item in payload["scenarios"]}


def train_models_for_seed(benign_pcap: Path, model_root: Path, seed: int) -> None:
    rows = load_benign_rows(benign_pcap)
    for scope in ("bssid", "client", "ssid"):
        train_isolation_forest(
            [row for row in rows if row.scope == scope],
            model_root,
            seed=seed,
        )


def build_seed_artifacts(
    seed: int,
    dataset: Path,
    work_root: Path,
    *,
    use_ml: bool = True,
) -> SeedArtifacts:
    inventory = build_inventory(dataset / "benign_baseline.pcap")
    model_root = work_root / f"models-{seed}"
    labels = _load_labels(dataset)
    results: dict[str, AnalysisResult] = {}
    rules_only: dict[str, list[Any]] = {}
    if use_ml:
        train_models_for_seed(dataset / "benign_baseline.pcap", model_root, seed)
    for name in sorted(labels):
        results[name] = analyze_pcap(
            dataset / f"{name}.pcap",
            inventory=inventory,
            model_root=model_root if use_ml else None,
            trusted_model_root=work_root,
            use_ml=use_ml,
        )
        rules_only[name] = correlate(
            results[name].incidents,
            [],
            inventory,
            CorrelationConfig(),
        )
    return SeedArtifacts(
        seed=seed,
        dataset=dataset,
        work_root=work_root,
        inventory=inventory,
        model_root=model_root,
        labels=labels,
        results=results,
        rules_only=rules_only,
    )


def actionable(alerts: list[Any]) -> list[Any]:
    return [alert for alert in alerts if alert.severity != "informational"]


def attack_bounds(metadata: dict[str, Any]) -> tuple[datetime, datetime]:
    details = metadata.get("details") or {}
    if details.get("mixed"):
        return (
            datetime.fromisoformat(details["attack_start"]),
            datetime.fromisoformat(details["attack_end"]),
        )
    if metadata.get("start") and metadata.get("end"):
        return datetime.fromisoformat(metadata["start"]), datetime.fromisoformat(metadata["end"])
    raise ValueError("Scenario has no labeled attack window")


def scenario_hit(alerts: list[Any], family: str, start: datetime, end: datetime):
    candidates = [
        alert
        for alert in alerts
        if alert.severity != "informational"
        and alert.family == family
        and start - TOLERANCE <= (alert.first_seen or alert.timestamp) <= end + TOLERANCE
    ]
    return (
        min(candidates, key=lambda item: item.first_seen or item.timestamp) if candidates else None
    )


def cross_family_hits(alerts: list[Any], expected: str) -> list[str]:
    return sorted(
        {
            alert.family
            for alert in alerts
            if alert.severity != "informational" and alert.family not in {expected, "ml_anomaly"}
        }
    )


def scenario_rows(artifacts: SeedArtifacts) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in sorted(artifacts.results):
        metadata = artifacts.labels[name]
        expected = SCENARIO_FAMILIES.get(name)
        result = artifacts.results[name]
        row: dict[str, Any] = {
            "seed": artifacts.seed,
            "scenario": name,
            "family": expected or metadata["attack_family"],
            "frames": result.frame_count,
            "windows": result.window_count,
            "alerts": len(result.alerts),
            "actionable": len(actionable(list(result.alerts))),
            "rule_ids": sorted({rule for alert in result.alerts for rule in alert.rule_ids}),
            "detected": False,
            "delay_seconds": None,
            "cross_family": [],
            "clear_false_positive": False,
            "first_seen": None,
        }
        if expected is not None:
            start, end = attack_bounds(metadata)
            hit = scenario_hit(list(result.alerts), expected, start, end)
            row["attack_start"] = start.isoformat()
            row["attack_end"] = end.isoformat()
            row["detected"] = hit is not None
            if hit is not None:
                first_seen = hit.first_seen or hit.timestamp
                row["first_seen"] = first_seen.isoformat()
                row["delay_seconds"] = max(0.0, (first_seen - start).total_seconds())
            cross = cross_family_hits(list(result.alerts), expected)
            row["cross_family"] = cross
            if cross:
                sources = set()
                for current_alert in result.alerts:
                    if current_alert.family in cross:
                        sources.update(current_alert.bssids)
                expected_entities = set(metadata.get("bssids", []))
                row["clear_false_positive"] = not bool(sources & expected_entities)
        rows.append(row)
    return rows


def _mean_std(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    return float(statistics.fmean(values)), float(statistics.pstdev(values))


def family_metrics(all_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    metrics: dict[str, dict[str, Any]] = {}
    for family in FAMILIES:
        cases = [
            row
            for row in all_rows
            if row["scenario"] in SCENARIO_FAMILIES and SCENARIO_FAMILIES[row["scenario"]] == family
        ]
        tp = sum(bool(row["detected"]) for row in cases)
        fn = len(cases) - tp
        fp = sum(
            1
            for row in all_rows
            if row["scenario"] in BENIGN_SCENARIOS
            and family in row.get("false_positive_families", [])
        )
        attacker_tp = sum(
            1
            for row in all_rows
            if row["scenario"] in POSITIVE_SCENARIOS and family in row.get("cross_family", [])
        )
        fp += attacker_tp
        delays = [row["delay_seconds"] for row in cases if row["delay_seconds"] is not None]
        delay_mean, delay_std = _mean_std([float(value) for value in delays])
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        metrics[family] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "delay_mean": delay_mean,
            "delay_std": delay_std,
            "detected_scenarios": [row["scenario"] for row in cases if row["detected"]],
            "missed_scenarios": [row["scenario"] for row in cases if not row["detected"]],
        }
    return metrics


def annotate_false_positives(artifacts: SeedArtifacts, rows: list[dict[str, Any]]) -> None:
    for row in rows:
        if row["scenario"] not in BENIGN_SCENARIOS:
            continue
        alerts = actionable(list(artifacts.results[row["scenario"]].alerts))
        row["false_positive_families"] = sorted({alert.family for alert in alerts})
        row["false_positive_rules"] = sorted({rule for alert in alerts for rule in alert.rule_ids})
        duration = artifacts.labels[row["scenario"]].get("details", {}).get("duration_seconds", 0)
        row["duration_hours"] = float(duration) / 3600.0 if duration else 0.0
        row["alerts_per_hour"] = (
            len(alerts) / row["duration_hours"] if row["duration_hours"] else 0.0
        )


def benign_false_positives(artifacts: SeedArtifacts) -> tuple[int, float]:
    total_alerts = 0
    total_hours = 0.0
    for name in BENIGN_SCENARIOS:
        alerts = actionable(list(artifacts.results[name].alerts))
        total_alerts += len(alerts)
        total_hours += float(artifacts.labels[name]["details"]["duration_seconds"]) / 3600.0
    return total_alerts, total_alerts / total_hours if total_hours else 0.0


def family_seed_metrics(seed: int, all_rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Calculate one family's counts for one seed."""
    metrics: dict[str, dict[str, Any]] = {}
    seed_rows = [row for row in all_rows if row["seed"] == seed]
    for family in FAMILIES:
        cases = [
            row
            for row in seed_rows
            if row["scenario"] in SCENARIO_FAMILIES and SCENARIO_FAMILIES[row["scenario"]] == family
        ]
        tp = sum(bool(row["detected"]) for row in cases)
        fn = len(cases) - tp
        benign_fp = sum(
            1
            for row in seed_rows
            if row["scenario"] in BENIGN_SCENARIOS
            and family in row.get("false_positive_families", [])
        )
        attacker_fp = sum(
            1
            for row in seed_rows
            if row["scenario"] in POSITIVE_SCENARIOS
            and family in row.get("cross_family", [])
            and row.get("clear_false_positive")
        )
        cross_family_count = sum(
            1
            for row in seed_rows
            if row["scenario"] in POSITIVE_SCENARIOS and family in row.get("cross_family", [])
        )
        fp = benign_fp + attacker_fp
        delays = [row["delay_seconds"] for row in cases if row["delay_seconds"] is not None]
        delay_mean, delay_std = _mean_std([float(value) for value in delays])
        metrics[family] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "cross_family_hits": cross_family_count,
            "precision": tp / (tp + fp) if tp + fp else 0.0,
            "recall": tp / (tp + fn) if tp + fn else 0.0,
            "delay_mean": delay_mean if delays else None,
            "delay_std": delay_std if delays else None,
            "detected_scenarios": [row["scenario"] for row in cases if row["detected"]],
            "missed_scenarios": [row["scenario"] for row in cases if not row["detected"]],
        }
    return metrics


def summarize_family_metrics(
    seeds: list[int], all_rows: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    per_seed = {seed: family_seed_metrics(seed, all_rows) for seed in seeds}
    summary: dict[str, dict[str, Any]] = {}
    for family in FAMILIES:
        fields = ("tp", "fp", "fn", "cross_family_hits", "precision", "recall")
        entry: dict[str, Any] = {}
        for field in fields:
            values = [float(per_seed[seed][family][field]) for seed in seeds]
            mean, std = _mean_std(values)
            entry[f"{field}_mean"] = mean
            entry[f"{field}_std"] = std
        for field in ("delay_mean", "delay_std"):
            values = [
                float(per_seed[seed][family][field])
                for seed in seeds
                if per_seed[seed][family][field] is not None
            ]
            mean, std = _mean_std(values)
            entry[field] = mean if values else None
            entry[f"{field}_spread"] = std if values else None
        entry["per_seed"] = {str(seed): per_seed[seed][family] for seed in seeds}
        summary[family] = entry
    return summary


def comparison_summary(
    seeds: list[int], all_rows: list[dict[str, Any]], rules_rows: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Compare actionable family detection with and without ML."""
    summary: dict[str, Any] = {}
    for family in FAMILIES:
        cases = [
            row
            for row in all_rows
            if row["scenario"] in SCENARIO_FAMILIES and SCENARIO_FAMILIES[row["scenario"]] == family
        ]
        combined = sum(bool(row["detected"]) for row in cases)
        rule_total = sum(1 for row in rules_rows if row["family"] == family and row["detected"])
        ml_only = sum(
            1
            for row in cases
            if not row["detected"] and row["actionable"] == 0 and row["alerts"] > 0
        )
        mean_risk = (
            sum(
                next(
                    (
                        value["risk"]
                        for value in rules_rows
                        if value["seed"] == row["seed"] and value["scenario"] == row["scenario"]
                    ),
                    0,
                )
                for row in cases
            )
            / len(cases)
            if cases
            else 0.0
        )
        summary[family] = {
            "cases": len(cases),
            "rules_only_detected": rule_total,
            "rules_plus_ml_detected": combined,
            "ml_only_actionable_added": max(0, combined - rule_total),
            "ml_informational_only_cases": ml_only,
            "mean_risk": mean_risk,
        }
    return summary


def per_rule_hits(artifacts: SeedArtifacts) -> list[dict[str, Any]]:
    counts: dict[str, dict[str, Any]] = {}
    for name, result in artifacts.results.items():
        for incident in result.incidents:
            record = counts.setdefault(
                incident.rule_id,
                {"rule_id": incident.rule_id, "incidents": 0, "scenarios": set(), "benign": 0},
            )
            record["incidents"] += 1
            record["scenarios"].add(name)
            if name in BENIGN_SCENARIOS:
                record["benign"] += 1
    return [
        {
            "rule_id": value["rule_id"],
            "incidents": value["incidents"],
            "scenarios": sorted(value["scenarios"]),
            "benign_incidents": value["benign"],
        }
        for value in sorted(counts.values(), key=lambda item: item["rule_id"])
    ]


def run_seed(seed: int, work_root: Path) -> SeedArtifacts:
    dataset = work_root / f"synthetic-{seed}"
    generate_dataset(dataset, seed=seed)
    return build_seed_artifacts(seed, dataset, work_root)


def build_evaluation(work_root: Path, seeds: tuple[int, ...] = SEEDS) -> dict[str, Any]:
    from concurrent.futures import ProcessPoolExecutor

    if len(seeds) > 1:
        with ProcessPoolExecutor(max_workers=min(5, len(seeds))) as pool:
            artifacts = list(pool.map(run_seed, seeds, [work_root] * len(seeds)))
    else:
        artifacts = [run_seed(seed, work_root) for seed in seeds]
    rows: list[dict[str, Any]] = []
    for item in artifacts:
        seed_rows = scenario_rows(item)
        annotate_false_positives(item, seed_rows)
        for row in seed_rows:
            alerts, rate = None, None
            if row["scenario"] in BENIGN_SCENARIOS:
                alerts, rate = benign_false_positives(item)
            row["seed_benign_fp_alerts"] = alerts
            row["seed_benign_alerts_per_hour"] = rate
        rows.extend(seed_rows)
    metrics = family_metrics(rows)
    rules_only_rows = []
    for item in artifacts:
        for name, alerts in item.rules_only.items():
            metadata = item.labels[name]
            expected = SCENARIO_FAMILIES.get(name)
            hit = None
            if expected is not None:
                start, end = attack_bounds(metadata)
                hit = scenario_hit(alerts, expected, start, end)
            rules_only_rows.append(
                {
                    "seed": item.seed,
                    "scenario": name,
                    "family": expected or metadata["attack_family"],
                    "detected": hit is not None,
                    "risk": max((alert.risk_score for alert in alerts), default=0),
                }
            )
    fpr_by_seed = {str(item.seed): benign_false_positives(item)[1] for item in artifacts}
    family_summary = summarize_family_metrics(list(seeds), rows)
    comparison = comparison_summary(list(seeds), rows, rules_only_rows)
    ml_attack_rows = [
        {
            "seed": row["seed"],
            "scenario": row["scenario"],
            "family": row["family"],
            "detected_rule_plus_ml": row["detected"],
            "detected_rules_only": next(
                (
                    value["detected"]
                    for value in rules_only_rows
                    if value["seed"] == row["seed"] and value["scenario"] == row["scenario"]
                ),
                False,
            ),
            "ml_contributed": bool(
                row["detected"]
                and not next(
                    (
                        value["detected"]
                        for value in rules_only_rows
                        if value["seed"] == row["seed"] and value["scenario"] == row["scenario"]
                    ),
                    False,
                )
            ),
        }
        for row in rows
        if row["scenario"] in POSITIVE_SCENARIOS
    ]
    per_rule: dict[str, dict[str, Any]] = {}
    for item in artifacts:
        for record in per_rule_hits(item):
            target = per_rule.setdefault(
                record["rule_id"],
                {
                    "rule_id": record["rule_id"],
                    "incidents": 0,
                    "benign_incidents": 0,
                    "scenarios": set(),
                },
            )
            target["incidents"] += record["incidents"]
            target["benign_incidents"] += record["benign_incidents"]
            target["scenarios"].update(record["scenarios"])
    return {
        "synthetic_data": True,
        "seeds": list(seeds),
        "tolerance_seconds": ATTACK_WINDOW_TOLERANCE_SECONDS,
        "scenarios": rows,
        "families": metrics,
        "family_summary": family_summary,
        "comparison": comparison,
        "fpr_alerts_per_hour_by_seed": fpr_by_seed,
        "rules_only": rules_only_rows,
        "rules_vs_ml": ml_attack_rows,
        "per_rule": [
            {
                "rule_id": rule_id,
                "incidents": per_rule.get(rule_id, {"incidents": 0})["incidents"],
                "benign_incidents": per_rule.get(rule_id, {"benign_incidents": 0})[
                    "benign_incidents"
                ],
                "scenarios": sorted(per_rule.get(rule_id, {"scenarios": set()})["scenarios"]),
            }
            for rule_id in sorted(rule.id for rule in load_rules("wids_ai/rules/rules"))
        ],
    }
