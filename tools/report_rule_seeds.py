"""Report per-rule incidents across synthetic seeds."""

from __future__ import annotations

import argparse
import json
import tempfile
from collections import Counter
from pathlib import Path

from wids_ai.capture.base import PcapSource
from wids_ai.features.extractors import FeatureRow, batch_extract
from wids_ai.features.windowing import WindowConfig
from wids_ai.inventory import APInventory
from wids_ai.parser.dot11 import parse_frame
from wids_ai.rules.engine import deduplicate, evaluate_rules, load_rules
from wids_ai.synthetic.generator import generate_dataset

MIXED = (
    "mixed_evil_twin",
    "mixed_deauth_burst",
    "mixed_karma_probe_responses",
    "mixed_beacon_sequence_anomaly",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Report synthetic rule incidents by seed")
    parser.add_argument("--rules", type=Path, default=Path("wids_ai/rules/rules"))
    parser.add_argument("--out", type=Path, default=Path("eval/rule_seed_report.json"))
    args = parser.parse_args()
    rules = load_rules(args.rules)
    report: dict[str, object] = {}
    for seed in (1, 2, 3, 42, 99):
        dataset = Path(tempfile.mkdtemp()) / f"synthetic-{seed}"
        generate_dataset(dataset, seed=seed)

        def frames(name: str, root: Path = dataset):
            return [
                frame
                for packet in PcapSource(root / f"{name}.pcap").packets()
                if (frame := parse_frame(packet)) is not None
            ]

        benign = frames("benign_baseline")
        inventory = APInventory.from_frames(benign)
        benign_features = batch_extract(benign, WindowConfig(10, 5))
        benign_rows = [
            FeatureRow.model_validate(item.to_dict()) for _, item in benign_features.iterrows()
        ]
        benign_incidents = deduplicate(evaluate_rules(benign_rows, rules, benign, inventory))
        seed_report: dict[str, object] = {"benign_incidents": len(benign_incidents), "mixed": {}}
        for name in MIXED:
            mixed_frames = frames(name)
            features = batch_extract(mixed_frames, WindowConfig(10, 5))
            rows = [FeatureRow.model_validate(item.to_dict()) for _, item in features.iterrows()]
            incidents = deduplicate(evaluate_rules(rows, rules, mixed_frames, inventory))
            seed_report["mixed"][name] = dict(Counter(item.rule_id for item in incidents))
        report[str(seed)] = seed_report
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
