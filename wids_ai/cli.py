"""WIDS-AI command line entry point."""

from __future__ import annotations

import argparse
import json
import logging
from collections.abc import Sequence
from pathlib import Path

from wids_ai import __version__
from wids_ai.capture.base import PcapSource
from wids_ai.capture.live_source import LiveSource
from wids_ai.config import PROJECT_ROOT, Settings, load_config
from wids_ai.correlation.scorer import CorrelationConfig, correlate
from wids_ai.features.extractors import FeatureRow, batch_extract
from wids_ai.features.windowing import WindowConfig
from wids_ai.inventory import APInventory
from wids_ai.logging_config import configure_logging
from wids_ai.ml.baseline import load_benign_rows
from wids_ai.ml.isolation_forest import (
    aggregate_window_scores,
    load_model,
    score_rows,
    train_isolation_forest,
    write_scores,
)
from wids_ai.parser.dot11 import parse_frame
from wids_ai.replay import replay_pcap
from wids_ai.rules.engine import deduplicate, evaluate_rules, load_rules
from wids_ai.siem.exporter import FileSink, HttpSink, NanoSIEMExporter
from wids_ai.storage.db import Database

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
        ("score", "Score windows with a persisted anomaly model"),
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
            command.add_argument("--out", type=Path, default=Path("data/alerts.json"))
            command.add_argument("--model", type=Path, default=Path("models"))
            command.add_argument("--trusted-model-root", type=Path, default=PROJECT_ROOT / "models")
            command.add_argument("--window-seconds", type=float, default=10.0)
            command.add_argument("--step-seconds", type=float, default=5.0)
            command.add_argument("--siem-file", type=Path)
            command.add_argument("--siem-url")
            command.add_argument("--siem-token-env")
            command.add_argument("--siem-sensor-name")
        if name == "train":
            command.add_argument("pcap", type=Path)
            command.add_argument("--out", type=Path, default=Path("models"))
            command.add_argument("--seed", type=int, default=42)
            command.add_argument("--contamination", type=float, default=0.05)
        if name == "serve":
            command.add_argument("--siem-file", type=Path)
            command.add_argument("--siem-url")
            command.add_argument("--siem-token-env")
            command.add_argument("--siem-sensor-name")
            command.add_argument("--replay", type=Path)
            command.add_argument("--speed", type=float, default=20.0)
            command.add_argument("--inventory", type=Path)
            command.add_argument("--model", type=Path, default=Path("models"))
            command.add_argument("--trusted-model-root", type=Path, default=PROJECT_ROOT / "models")
            command.add_argument("--rules", type=Path, default=Path("wids_ai/rules/rules"))
            command.add_argument("--db", type=Path, default=Path("data/wids.db"))
            command.add_argument("--loop", action="store_true")
            command.add_argument("--fresh", dest="fresh", action="store_true", default=True)
            command.add_argument("--keep", dest="fresh", action="store_false")
        if name == "score":
            command.add_argument("pcap", type=Path)
            command.add_argument("--model", type=Path, required=True)
            command.add_argument("--trusted-model-root", type=Path, default=PROJECT_ROOT / "models")
            command.add_argument("--out", type=Path, required=True)
            command.add_argument("--window-seconds", type=float, default=10.0)
            command.add_argument("--step-seconds", type=float, default=5.0)
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
        ml_scores = []
        for scope in ("bssid", "client", "ssid"):
            model_dir = args.model / scope
            if not (model_dir / "isolation_forest.joblib").is_file():
                continue
            model = load_model(model_dir, trusted_base=args.trusted_model_root)
            scope_rows = feature_frame[feature_frame["scope"] == scope]
            scope_scored = score_rows(model, scope_rows)
            ml_scores.extend(
                item.anomaly_score for item in aggregate_window_scores(scope_scored, method="max")
            )
        correlation_config = CorrelationConfig(**settings.correlation.model_dump())
        alerts = correlate(incidents, ml_scores, inventory, correlation_config)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps([item.model_dump(mode="json") for item in alerts], indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Frames: {len(frame_rows)}  Feature rows: {len(rows)}  Alerts: {len(alerts)}")
        print(f"{'RISK':<5} {'FAMILY':<32} {'ATT&CK':<8} {'SEVERITY':<14} BSSIDS")
        for alert in alerts:
            technique = alert.mitre_attack.technique if alert.mitre_attack else "-"
            print(
                f"{alert.risk_score:<5} {alert.family:<32} {technique:<8} "
                f"{alert.severity:<14} {','.join(alert.bssids)}"
            )
        if settings.siem.enabled or args.siem_file is not None or args.siem_url is not None:
            with Database(settings.storage.database_path) as export_db:
                export_alerts(
                    alerts,
                    export_db,
                    settings,
                    file_path=args.siem_file,
                    url=args.siem_url,
                    token_env=args.siem_token_env,
                    sensor_name=args.siem_sensor_name,
                )
        print(f"Alerts -> {args.out}")
        return 0
    if args.command == "features":
        frame_rows = list(parse_frames(PcapSource(args.pcap)))
        config = WindowConfig(args.window_seconds, args.step_seconds)
        features = batch_extract(frame_rows, config)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        features.to_csv(args.out, index=False)
        LOGGER.info("Wrote %d feature rows to %s", len(features), args.out)
        return 0
    if args.command == "train":
        rows = load_benign_rows(args.pcap)
        trained_models = []
        for scope in ("bssid", "client", "ssid"):
            scope_rows = [row for row in rows if row.scope == scope]
            trained_models.append(
                train_isolation_forest(
                    scope_rows,
                    args.out,
                    seed=args.seed,
                    contamination=args.contamination,
                )
            )
        print(f"Trained {len(trained_models)} scope models -> {args.out}")
        for trained in trained_models:
            print(
                f"{trained.metadata.scope}: {trained.metadata.training_window_count} "
                f"windows -> {trained.model_path}"
            )
        return 0
    if args.command == "score":
        frame_rows = list(parse_frames(PcapSource(args.pcap)))
        config = WindowConfig(args.window_seconds, args.step_seconds)
        feature_frame = batch_extract(frame_rows, config)
        scored = []
        for scope in ("bssid", "client", "ssid"):
            model_dir = args.model / scope
            if not (model_dir / "isolation_forest.joblib").is_file():
                continue
            model = load_model(model_dir, trusted_base=args.trusted_model_root)
            scope_rows = feature_frame[feature_frame["scope"] == scope]
            scored.extend(score_rows(model, scope_rows))
        write_scores(scored, args.out)
        values = [item.anomaly_score for item in scored]
        print(
            f"Scored {len(values)} rows: mean={sum(values) / len(values):.4f} "
            f"max={max(values):.4f} -> {args.out}"
        )
        return 0
    if args.command == "serve":
        database = Database(args.db)
        if args.replay is not None:
            inventory_path = args.inventory
            if inventory_path is None:
                inventory_path = Path(args.db).parent / "replay-inventory.json"
                if not inventory_path.exists():
                    LOGGER.info(
                        "No inventory supplied; building one from benign frames is required"
                    )
            exporter = build_siem_exporter(
                database,
                settings,
                file_path=args.siem_file,
                url=args.siem_url,
                token_env=args.siem_token_env,
                sensor_name=args.siem_sensor_name,
            )

            failed_alerts = []

            def export_replay_alerts(replay_alerts):
                if exporter is not None:
                    try:
                        exporter.export(replay_alerts)
                        failed_alerts.extend(exporter.failed)
                    except Exception as exc:
                        LOGGER.warning("SIEM export failed: %s", type(exc).__name__)
                        print(f"SIEM export failed: {type(exc).__name__}")
                        failed_alerts.extend(replay_alerts)

            try:
                result = replay_pcap(
                    args.replay,
                    database,
                    inventory_path=inventory_path if inventory_path.exists() else None,
                    model_root=args.model,
                    rules_dir=args.rules,
                    trusted_model_root=args.trusted_model_root,
                    speed=args.speed,
                    loop=args.loop,
                    fresh=args.fresh,
                    on_alerts=export_replay_alerts,
                )
            finally:
                if exporter is not None:
                    exporter.close()
            print(
                f"Replay: {result.frames} frames, {result.windows} feature rows, {result.alerts} alerts"
            )
            if failed_alerts:
                print(f"SIEM export failed: {len(failed_alerts)} alert states not exported")
            print(f"Inventory: {inventory_path}")
        import uvicorn

        from wids_ai.api.main import create_app

        uvicorn.run(create_app(database), host=settings.api.host, port=settings.api.port)
        return 0
    if args.command == "live":
        source = LiveSource(args.iface, args.channel)
        frames = parse_source(source)
        LOGGER.info("Parsed %d live frames", frames)
        return 0
    LOGGER.info("Command %s is scaffolded; implementation lands in later milestones", args.command)
    return 0


def build_siem_exporter(
    database: Database,
    settings: Settings,
    *,
    file_path: Path | None = None,
    url: str | None = None,
    token_env: str | None = None,
    sensor_name: str | None = None,
) -> NanoSIEMExporter | None:
    """Build enabled sinks without allowing exporter setup to stop analysis."""
    config = settings.siem
    configured = file_path is None and url is None and config.enabled
    selected_file = (
        file_path if file_path is not None else (config.file_path if configured else None)
    )
    selected_url = url if url is not None else (config.http_endpoint if configured else None)
    if selected_file is None and selected_url is None:
        return None
    sinks = []
    if selected_file is not None:
        try:
            sinks.append(FileSink(selected_file))
        except Exception as exc:
            LOGGER.warning("SIEM file sink unavailable: %s", type(exc).__name__)
            print(f"SIEM export failed: file sink unavailable: {type(exc).__name__}")
    if selected_url is not None:
        try:
            sinks.append(
                HttpSink(
                    selected_url,
                    token_env=token_env or config.token_env,
                    timeout=float(config.timeout_seconds),
                    failure_callback=print,
                )
            )
        except Exception as exc:
            LOGGER.warning("SIEM HTTP sink unavailable: %s", type(exc).__name__)
            print(f"SIEM export failed: HTTP sink unavailable: {type(exc).__name__}")
    if not sinks:
        LOGGER.warning("SIEM export disabled because no sink could be started")
        print("SIEM export failed: no sink could be started")
        return None
    return NanoSIEMExporter(
        database,
        sinks,
        sensor_name=sensor_name or config.sensor_name,
        failure_callback=print,
    )


def export_alerts(
    alerts,
    database: Database,
    settings: Settings,
    *,
    file_path: Path | None = None,
    url: str | None = None,
    token_env: str | None = None,
    sensor_name: str | None = None,
) -> int:
    exporter = build_siem_exporter(
        database,
        settings,
        file_path=file_path,
        url=url,
        token_env=token_env,
        sensor_name=sensor_name,
    )
    if exporter is None:
        return 0
    try:
        return exporter.export(alerts)
    except Exception as exc:
        LOGGER.warning("SIEM export failed: %s", type(exc).__name__)
        print(f"SIEM export failed: {type(exc).__name__}")
        return 0
    finally:
        exporter.close()


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
