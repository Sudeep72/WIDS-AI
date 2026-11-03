"""Generate docs/EVALUATION.md from synthetic end-to-end runs."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.eval_ml import evaluate_all  # noqa: E402
from wids_ai.evaluation import SEEDS, build_evaluation  # noqa: E402
from wids_ai.synthetic.generator import BENIGN_DURATION_SECONDS, generate_dataset  # noqa: E402


def num(value: Any, digits: int = 3) -> str:
    return "n/a" if value is None else f"{float(value):.{digits}f}"


def pct(value: float) -> str:
    return f"{value:.3f}"


def family_table(report):
    lines = [
        "| Family | TP mean | FP mean | FN mean | Precision | Recall | Delay mean (s) | Delay std (s) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for family, m in report["family_summary"].items():
        lines.append(
            f"| {family} | {num(m['tp_mean'], 2)} | {num(m['fp_mean'], 2)} | {num(m['fn_mean'], 2)} | {pct(m['precision_mean'])} | {pct(m['recall_mean'])} | {num(m['delay_mean'])} | {num(m['delay_std'])} |"
        )
    return lines


def seed_table(report):
    lines = [
        "| Seed | Family | TP | FP | FN | Precision | Recall | Delay mean (s) |",
        "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for family, m in report["family_summary"].items():
        for seed, v in m["per_seed"].items():
            lines.append(
                f"| {seed} | {family} | {v['tp']} | {v['fp']} | {v['fn']} | {pct(v['precision'])} | {pct(v['recall'])} | {num(v['delay_mean'])} |"
            )
    return lines


def scenario_table(report):
    lines = [
        "| Seed | Scenario | Expected | Detected | Delay (s) | Rules | Cross-family |",
        "| ---: | --- | --- | --- | ---: | --- | --- |",
    ]
    for r in report["scenarios"]:
        if not r["scenario"].startswith("mixed_"):
            continue
        lines.append(
            f"| {r['seed']} | {r['scenario']} | {r['family']} | {'yes' if r['detected'] else 'no'} | {num(r['delay_seconds'])} | {', '.join(r['rule_ids']) or 'none'} | {', '.join(r['cross_family']) or 'none'} |"
        )
    return lines


def rule_table(report):
    lines = ["| Rule | Incidents | Benign incidents | Scenarios |", "| --- | ---: | ---: | --- |"]
    for r in report["per_rule"]:
        lines.append(
            f"| {r['rule_id']} | {r['incidents']} | {r['benign_incidents']} | {', '.join(r['scenarios']) or '-'} |"
        )
    return lines


def benign_table(report):
    lines = ["| Seed | Benign alerts per hour |", "| ---: | ---: |"]
    for seed, rate in report["fpr_alerts_per_hour_by_seed"].items():
        lines.append(f"| {seed} | {num(rate)} |")
    return lines


def ml_table(report):
    lines = [
        "| Scenario | Aggregation | ROC-AUC mean | ROC-AUC std | PR-AUC mean | PR-AUC std |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
    ]
    for scenario, methods in report["summary"].items():
        for method in ("max", "top2_mean"):
            m = methods[method]
            lines.append(
                f"| {scenario} | {method} | {num(m['roc_auc_mean'], 4)} | {num(m['roc_auc_std'], 4)} | {num(m['pr_auc_mean'], 4)} | {num(m['pr_auc_std'], 4)} |"
            )
    return lines


def comparison_table(report):
    lines = [
        "| Family | Cases | Rules only | Rules plus ML | ML-only actionable added | ML informational cases |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for family, v in report["comparison"].items():
        lines.append(
            f"| {family} | {v['cases']} | {v['rules_only_detected']} | {v['rules_plus_ml_detected']} | {v['ml_only_actionable_added']} | {v['ml_informational_only_cases']} |"
        )
    return lines


def benchmark(pcap, repeats):
    import subprocess

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "tools" / "benchmark.py"),
            "--pcap",
            str(pcap),
            "--repeat",
            str(repeats),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    values = {}
    for line in completed.stdout.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            values[key] = value
    return {
        "pcap": values.get("PCAP", str(pcap)),
        "frames": int(values.get("Frames", "0")),
        "repeat": repeats,
        "best_seconds": float(values.get("Best seconds", "0")),
        "frames_per_second": float(values.get("Frames per second", "0")),
        "peak_memory_mb": (
            float(values["Peak memory MB"])
            if values.get("Peak memory MB", "unavailable") != "unavailable"
            else None
        ),
    }


BEFORE_2026_11 = {
    "fpr_alerts_per_hour_by_seed": {
        "1": 2.5,
        "2": 5.0,
        "3": 0.0,
        "42": 0.0,
        "99": 2.5,
    },
    "deauth_recall": 0.500,
    "deauth_missed": "mixed_low_slow_deauth",
    "beacon_precision": 0.700,
    "beacon_fp_mean": 0.60,
}


def comparison_summary(old: dict, new: dict) -> list[str]:
    before = old["fpr_alerts_per_hour_by_seed"]
    after = new["fpr_alerts_per_hour_by_seed"]
    return [
        "| Metric | Before M11 | After M11 |",
        "| --- | ---: | ---: |",
        "| Benign/noisy false positives per hour, seed 1 | {} | {} |".format(
            num(before["1"]), num(after["1"])
        ),
        "| Benign/noisy false positives per hour, seed 2 | {} | {} |".format(
            num(before["2"]), num(after["2"])
        ),
        "| Benign/noisy false positives per hour, seed 99 | {} | {} |".format(
            num(before["99"]), num(after["99"])
        ),
        "| Deauth recall | {} | {} |".format(
            num(old["deauth_recall"]),
            num(new["family_summary"]["deauth_disassoc_anomaly"]["recall_mean"]),
        ),
        "| Beacon precision | {} | {} |".format(
            num(old["beacon_precision"]),
            num(new["family_summary"]["beacon_management_anomaly"]["precision_mean"]),
        ),
        "| Beacon false positives per seed | {} | {} |".format(
            num(old["beacon_fp_mean"]),
            num(new["family_summary"]["beacon_management_anomaly"]["fp_mean"]),
        ),
    ]


def render(report, ml_report, bench):
    limitations = [
        "All data is synthetic; no field accuracy is claimed.",
        "Thresholds were tuned on the same general synthetic generator family.",
        "No real RF noise, multipath, hidden-node effects, or capture loss is represented.",
        "No encrypted traffic or WPA3-specific attack behavior is evaluated.",
        "Captures are single-channel snapshots; multi-channel hopping gaps are not modeled.",
        "ATT&CK mappings are best-fit indicators and must be verified before publication.",
    ]
    lines = [
        "# WIDS-AI Synthetic Evaluation",
        "",
        "## SYNTHETIC DATA",
        "",
        "This report is generated by `tools/evaluate.py` from synthetic PCAP fixtures.",
        "It is not field validation, does not establish real-world accuracy, and must not",
        "be presented as a production benchmark. The evaluation uses seeds 1, 2, 3, 42,",
        "and 99. Training uses only each seed's benign PCAP. The labeled attack window",
        f"tolerance is {report['tolerance_seconds']} seconds.",
        "",
        "## Before and after M11 fixes",
        "",
        "The before column is copied from the measured M10 report. The after column",
        "is generated from the current rules and does not reuse old labels.",
        "",
        *comparison_summary(BEFORE_2026_11, report),
        "",
        "## Family metrics",
        "",
        "Counts are means across the five seeds. Precision and recall use per-seed counts.",
        "Detection delay is from labeled attack start to the first expected-family alert.",
        "",
        *family_table(report),
        "",
        "## Per-seed metrics",
        "",
        *seed_table(report),
        "",
        "## Scenario outcomes",
        "",
        "Every challenge outcome is shown, including misses and cross-family hits.",
        "",
        *scenario_table(report),
        "",
        "## Benign false-positive rate",
        "",
        f"Each benign scenario is {BENIGN_DURATION_SECONDS // 60} minutes long. "
        "Informational ML-only alerts are excluded.",
        "",
        *benign_table(report),
        "",
        "## Rules versus rules plus ML",
        "",
        "ML is a low-weight supporting signal. Informational-only ML output is reported separately.",
        "",
        *comparison_table(report),
        "",
        "## ML ranking metrics",
        "",
        "Values come from `tools/eval_ml.py`.",
        "",
        *ml_table(ml_report),
        "",
        "ML is a low-weight supporting signal. It never supplies a standalone verdict.",
        "",
        "## Per-rule hits",
        "",
        *rule_table(report),
        "",
        "## Performance",
        "",
        f"Full rules pipeline, best of {bench['repeat']} runs, "
        f"with the {BENIGN_DURATION_SECONDS // 60}-minute benign PCAP.",
        "",
        "| Frames | Best seconds | Frames per second | Peak memory MB |",
        "| ---: | ---: | ---: | ---: |",
        f"| {bench['frames']} | {num(bench['best_seconds'])} | {num(bench['frames_per_second'], 2)} | {num(bench['peak_memory_mb'], 1)} |",
        "",
        "Peak memory is measured with the Windows process working-set API or the",
        "Unix `resource` module. ML scoring is evaluated separately by",
        "`tools/eval_ml.py`; the throughput table covers parsing, windowing,",
        "feature extraction, rules, and correlation.",
        "",
        "The direct benchmark command used for validation:",
        "",
        "```powershell",
        ".\\.venv\\Scripts\\python.exe tools\\benchmark.py --repeat 3",
        "```",
        "",
        "## Challenge findings",
        "",
        "- `benign_noisy` includes legitimate roaming, an AP restart, and a new AP. Actionable",
        "  alerts are reported above and are not hidden.",
        "- `mixed_low_slow_deauth` contains 12 deauth frames over 132 seconds.",
        "  The cumulative 300-second BSSID and client rules are evaluated without",
        "  changing the generator to make them pass. Their exact outcome is shown",
        "  in the scenario table.",
        "- `mixed_evil_twin_matching_oui` uses the trusted OUI and channel. Remaining",
        "  duplicate-SSID or RSSI evidence is reported per scenario.",
        "",
        "## Limitations",
        "",
        *[f"- {x}" for x in limitations],
        "",
    ]
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("docs/EVALUATION.md"))
    parser.add_argument("--work-root", type=Path, default=None)
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args(argv)
    work = args.work_root or Path(tempfile.mkdtemp(prefix="wids-eval-"))
    generate_dataset(work / "artifacts", seed=42)
    report = build_evaluation(work, SEEDS)
    ml_report = evaluate_all(work / "ml-data", work / "ml")
    bench = benchmark(work / "artifacts" / "benign_baseline.pcap", args.repeat)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(report, ml_report, bench), encoding="utf-8", newline="\n")
    (work / "evaluation.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"Generated {args.out}")
    print(f"Generated {work / 'evaluation.json'}")
    print(f"Scenarios: {len(report['scenarios'])}")
    print(f"Benchmark frames per second: {bench['frames_per_second']:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
