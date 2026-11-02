"""WIDS-AI command line entry point."""

from __future__ import annotations

import argparse
import logging
from collections.abc import Sequence
from pathlib import Path

from wids_ai import __version__
from wids_ai.capture.base import PcapSource
from wids_ai.capture.live_source import LiveSource
from wids_ai.config import load_config
from wids_ai.features.extractors import FeatureRow, batch_extract
from wids_ai.features.windowing import WindowConfig
from wids_ai.inventory import APInventory
from wids_ai.logging_config import configure_logging
from wids_ai.parser.dot11 import parse_frame
from wids_ai.rules.engine import deduplicate, evaluate_rules, load_rules, write_detections

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wids-ai", description="Wireless intrusion detection")
    parser.add_argument("--config", type=Path, default=None, help="Path to YAML configuration")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    for name, help_text in (
        ("analyze", "Analyze offline PCAP files"),
        ("features", "Extract window features from an offline PCAP"),
        ("baseline", "Build a trusted AP inventory from PCAP"),
        ("train", "Train the baseline anomaly model"),
        ("serve", "Serve the API and dashboard"),
        ("live", "Capture on a Linux monitor-mode interface"),
    ):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("--config", dest="command_config", type=Path, default=None)
        if name in {"analyze"}:
            command.add_argument("pcap", type=Path)
            command.add_argument("--inventory", type=Path)
            command.add_argument("--rules", type=Path, default=Path("wids_ai/rules/rules"))
            command.add_argument("--out", type=Path, default=Path("data/detections.json"))
            command.add_argument("--window-seconds", type=float, default=10.0)
            command.add_argument("--step-seconds", type=float, default=5.0)
        if name == "train":
            command.add_argument("paths", nargs="+", type=Path)
        if name == "baseline":
            command.add_argument("pcap", type=Path)
            command.add_argument("--out", type=Path, required=True)
        if name == "features":
            command.add_argument("pcap", type=Path)
            command.add_argument("--out", type=Path, required=True)
            command.add_argument("--window-seconds", type=float, default=10.0)
            command.add_argument("--step-seconds", type=float, default=5.0)
        if name == "live":
            command.add_argument("--iface", default="wlan0mon")
            command.add_argument("--channel", type=int, default=6)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0

    config_path = args.command_config or args.config
    settings = load_config(config_path)
    configure_logging(settings)

    if args.command == "baseline":
        frame_rows = list(parse_frames(PcapSource(args.pcap)))
        inventory = APInventory.from_frames(frame_rows)
        inventory.save(args.out)
        print(f"Learned {len(inventory.aps)} trusted APs -> {args.out}")
        for bssid, ap in sorted(inventory.aps.items()):
            print(f"{bssid}  {ap.ssid or '-'}  trust={ap.trust_score}  frames={ap.observations}")
        return 0
    if args.command == "analyze":
        frame_rows = list(parse_frames(PcapSource(args.pcap)))
        config = WindowConfig(args.window_seconds, args.step_seconds)
        feature_frame = batch_extract(frame_rows, config)
        rows = [FeatureRow.model_validate(item.to_dict()) for _, item in feature_frame.iterrows()]
        rules = load_rules(args.rules)
        inventory = (
            APInventory.load(args.inventory)
            if args.inventory is not None
            else APInventory.from_frames(frame_rows)
        )
        detections = evaluate_rules(rows, rules, frame_rows, inventory)
        incidents = deduplicate(detections)
        write_detections(incidents, args.out)
        print(f"Frames: {len(frame_rows)}  Feature rows: {len(rows)}  Incidents: {len(incidents)}")
        print(f"{'SEVERITY':<10} {'RULE':<20} {'FIRST SEEN':<30} HITS")
        for incident in incidents:
            print(
                f"{incident.severity:<10} {incident.rule_id:<20} "
                f"{incident.first_seen.isoformat():<30} {incident.hit_count}"
            )
        print(f"Detections -> {args.out}")
        return 0
    if args.command == "features":
        frame_rows = list(parse_frames(PcapSource(args.pcap)))
        config = WindowConfig(args.window_seconds, args.step_seconds)
        features = batch_extract(frame_rows, config)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        features.to_csv(args.out, index=False)
        LOGGER.info("Wrote %d feature rows to %s", len(features), args.out)
        return 0
    if args.command == "live":
        source = LiveSource(args.iface, args.channel)
        frames = parse_source(source)
        LOGGER.info("Parsed %d live frames", frames)
        return 0
    LOGGER.info("Command %s is scaffolded; implementation lands in later milestones", args.command)
    return 0


def parse_frames(source: PcapSource | LiveSource):
    for packet in source.packets():
        frame = parse_frame(packet)
        if frame is not None:
            yield frame


def parse_source(source: PcapSource | LiveSource) -> int:
    return sum(1 for _ in parse_frames(source))


def analyze_paths(paths: Sequence[Path]) -> int:
    total = 0
    for path in paths:
        LOGGER.info("Analyzing %s", path)
        count = parse_source(PcapSource(path))
        LOGGER.info("Parsed %d frames from %s", count, path)
        total += count
    return total


if __name__ == "__main__":
    raise SystemExit(main())
