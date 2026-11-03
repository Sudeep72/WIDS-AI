"""Incremental live detection engine and capture orchestration."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

from wids_ai.capture.live_source import LivePacketSink, LiveSource, set_channel
from wids_ai.inventory import APInventory
from wids_ai.parser.models import Frame
from wids_ai.pipeline import AnalysisResult, analyze_frames, parse_live_packet
from wids_ai.storage.db import Database

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class LiveRunResult:
    frames: int
    parse_errors: int
    dropped: int
    windows: int
    alerts: int
    duration_seconds: float
    run_id: int | None = None


def capture_frames(
    source: LiveSource,
    *,
    duration: float | None = None,
    write_pcap: str | Path | None = None,
    channel_hop: tuple[int, ...] = (),
    hop_interval: float = 0.5,
    analysis_interval: float = 5.0,
    on_frames=None,
) -> tuple[list[Frame], int, LivePacketSink]:
    """Capture and parse frames using arrival time, never RadioTap wall clock."""
    frames: list[Frame] = []
    errors = 0
    sink = LivePacketSink(write_pcap)
    started = time.monotonic()
    next_hop = started
    hop_index = 0
    next_analysis = started + analysis_interval
    try:
        for packet in source.packets():
            arrival = time.time()
            sink.append(packet)
            try:
                frame = parse_live_packet(packet, arrival)
            except Exception:
                errors += 1
                continue
            if frame is not None:
                frames.append(frame)
            if channel_hop and time.monotonic() >= next_hop:
                set_channel(source.interface, channel_hop[hop_index % len(channel_hop)])
                hop_index += 1
                next_hop = time.monotonic() + hop_interval
            if on_frames is not None and time.monotonic() >= next_analysis:
                on_frames(list(frames), errors)
                next_analysis = time.monotonic() + analysis_interval
            if duration is not None and time.monotonic() - started >= duration:
                break
    except KeyboardInterrupt:
        LOGGER.info("Capture interrupted; flushing buffered frames and PCAP")
    finally:
        sink.close()
    return frames, errors, sink


def run_live(
    source: LiveSource,
    *,
    database: Database,
    inventory: APInventory,
    rules_dir: str | Path = "wids_ai/rules/rules",
    model_root: str | Path = "models",
    trusted_model_root: str | Path | None = None,
    duration: float | None = None,
    write_pcap: str | Path | None = None,
    channel_hop: tuple[int, ...] = (),
    hop_interval: float = 0.5,
    export=None,
) -> LiveRunResult:
    """Capture, analyze, persist, and return one live session."""
    started = time.monotonic()
    run_id = database.start_run(f"live:{source.interface}", fresh=True)
    database.save_inventory(inventory)

    def save_progress(progress_frames: list[Frame], _errors: int) -> None:
        if not progress_frames:
            return
        progress = analyze_frames(
            progress_frames,
            inventory,
            rules_dir=rules_dir,
            model_root=model_root,
            trusted_model_root=trusted_model_root or model_root,
        )
        for alert in progress.alerts:
            database.save_alert(alert, run_id)

    frames, errors, _sink = capture_frames(
        source,
        duration=duration,
        write_pcap=write_pcap,
        channel_hop=channel_hop,
        hop_interval=hop_interval,
        on_frames=save_progress,
    )
    if not frames:
        database.finish_run(run_id, 0, 0)
        return LiveRunResult(
            frames=0,
            parse_errors=errors,
            dropped=source.dropped,
            windows=0,
            alerts=0,
            duration_seconds=time.monotonic() - started,
            run_id=run_id,
        )
    result: AnalysisResult = analyze_frames(
        frames,
        inventory,
        rules_dir=rules_dir,
        model_root=model_root,
        trusted_model_root=trusted_model_root or model_root,
    )
    for alert in result.alerts:
        database.save_alert(alert, run_id)
    database.finish_run(run_id, result.frame_count, result.window_count)
    database.record_capture_stats(
        run_id,
        frames_per_second=result.frame_count / max(time.monotonic() - started, 1e-9),
        parse_errors=errors,
        dropped=source.dropped,
    )
    if export is not None:
        export(list(result.alerts))
    return LiveRunResult(
        frames=result.frame_count,
        parse_errors=errors,
        dropped=source.dropped,
        windows=result.window_count,
        alerts=len(result.alerts),
        duration_seconds=time.monotonic() - started,
        run_id=run_id,
    )


def build_live_inventory(
    source: LiveSource,
    *,
    duration: float,
    yes: bool = False,
    prompt=input,
) -> APInventory:
    """Learn a live baseline and require confirmation before trusting each AP."""
    frames, _errors, _sink = capture_frames(source, duration=duration)
    learned = APInventory.from_frames(frames)
    trusted: dict[str, object] = {}
    for bssid, ap in sorted(learned.aps.items()):
        answer = (
            "y"
            if yes
            else prompt(f"Trust {bssid} {ap.ssid or '-'} on channels {ap.channels or '-'}? [y/N] ")
            .strip()
            .lower()
        )
        if answer in {"y", "yes"}:
            trusted[bssid] = ap
        else:
            print(f"Skipped {bssid}")
    return learned.model_copy(update={"aps": trusted})
