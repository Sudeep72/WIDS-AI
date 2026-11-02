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
from wids_ai.logging_config import configure_logging
from wids_ai.parser.dot11 import parse_frame

LOGGER = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wids-ai", description="Wireless intrusion detection")
    parser.add_argument("--config", type=Path, default=None, help="Path to YAML configuration")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    for name, help_text in (
        ("analyze", "Analyze offline PCAP files"),
        ("train", "Train the baseline anomaly model"),
        ("serve", "Serve the API and dashboard"),
        ("live", "Capture on a Linux monitor-mode interface"),
    ):
        command = subparsers.add_parser(name, help=help_text)
        command.add_argument("--config", dest="command_config", type=Path, default=None)
        if name in {"analyze", "train"}:
            command.add_argument("paths", nargs="+", type=Path)
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

    if args.command == "analyze":
        frames = analyze_paths(args.paths)
        LOGGER.info("Parsed %d frames", frames)
        return 0
    if args.command == "live":
        source = LiveSource(args.iface, args.channel)
        frames = parse_source(source)
        LOGGER.info("Parsed %d live frames", frames)
        return 0
    LOGGER.info("Command %s is scaffolded; implementation lands in later milestones", args.command)
    return 0


def parse_source(source: PcapSource | LiveSource) -> int:
    count = 0
    for packet in source.packets():
        if parse_frame(packet) is not None:
            count += 1
    return count


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
