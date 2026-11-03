"""Shared full detection pipeline used by CLI, replay, tests, and evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from wids_ai.capture.base import PcapSource
from wids_ai.correlation.schema import Alert
from wids_ai.correlation.scorer import CorrelationConfig, correlate
from wids_ai.features.extractors import FeatureRow, batch_extract
from wids_ai.features.windowing import WindowConfig
from wids_ai.inventory import APInventory
from wids_ai.ml.isolation_forest import (
    WindowScore,
    aggregate_window_scores,
    load_model,
    score_rows,
)
from wids_ai.parser.dot11 import parse_frame
from wids_ai.parser.models import Frame
from wids_ai.rules.engine import deduplicate, evaluate_rules, load_rules
from wids_ai.rules.schema import Incident, RuleDefinition

MODEL_SCOPES = ("bssid", "client", "ssid")


@dataclass(frozen=True)
class AnalysisResult:
    """All intermediate and final outputs from one PCAP analysis."""

    frames: tuple[Frame, ...]
    feature_rows: tuple[FeatureRow, ...]
    incidents: tuple[Incident, ...]
    alerts: tuple[Alert, ...]
    ml_scores: tuple[WindowScore, ...]

    @property
    def frame_count(self) -> int:
        return len(self.frames)

    @property
    def window_count(self) -> int:
        return len(self.feature_rows)


def parse_pcap(pcap: str | Path) -> list[Frame]:
    """Parse one PCAP without reading any labels."""
    return [
        frame for packet in PcapSource(pcap).packets() if (frame := parse_frame(packet)) is not None
    ]


def build_inventory(pcap: str | Path) -> APInventory:
    """Learn trusted APs from one benign PCAP."""
    return APInventory.from_frames(parse_pcap(pcap))


def _ml_window_scores(
    rows: list[FeatureRow],
    model_root: Path,
    trusted_model_root: Path,
) -> list[WindowScore]:
    scores: list[WindowScore] = []
    for scope in MODEL_SCOPES:
        model_dir = model_root / scope
        if not (model_dir / "isolation_forest.joblib").is_file():
            continue
        model = load_model(model_dir, trusted_base=trusted_model_root)
        scope_rows = [row for row in rows if row.scope == scope]
        if not scope_rows:
            continue
        scores.extend(aggregate_window_scores(score_rows(model, scope_rows), method="max"))
    return scores


def analyze_frames(
    frames: list[Frame],
    inventory: APInventory,
    *,
    rules: list[RuleDefinition] | None = None,
    rules_dir: str | Path = "wids_ai/rules/rules",
    model_root: str | Path | None = None,
    trusted_model_root: str | Path | None = None,
    window_seconds: float = 10.0,
    step_seconds: float = 5.0,
    correlation_config: CorrelationConfig | None = None,
    use_ml: bool = True,
) -> AnalysisResult:
    """Run windows, features, rules, ML, correlation, and grouping."""
    if not frames:
        return AnalysisResult((), (), (), (), ())
    loaded_rules = rules if rules is not None else load_rules(rules_dir)
    feature_frame = batch_extract(frames, WindowConfig(window_seconds, step_seconds))
    rows = [FeatureRow.model_validate(item.to_dict()) for _, item in feature_frame.iterrows()]
    incidents = deduplicate(evaluate_rules(rows, loaded_rules, frames, inventory))
    ml_scores: list[WindowScore] = []
    if use_ml and model_root is not None:
        root = Path(model_root)
        trust_root = Path(trusted_model_root) if trusted_model_root is not None else root
        ml_scores = _ml_window_scores(rows, root, trust_root)
    alerts = correlate(
        incidents,
        [item.anomaly_score for item in ml_scores],
        inventory,
        correlation_config or CorrelationConfig(),
    )
    return AnalysisResult(
        frames=tuple(frames),
        feature_rows=tuple(rows),
        incidents=tuple(incidents),
        alerts=tuple(alerts),
        ml_scores=tuple(ml_scores),
    )


def analyze_pcap(
    pcap: str | Path,
    *,
    inventory: APInventory | None = None,
    rules_dir: str | Path = "wids_ai/rules/rules",
    model_root: str | Path | None = None,
    trusted_model_root: str | Path | None = None,
    window_seconds: float = 10.0,
    step_seconds: float = 5.0,
    correlation_config: CorrelationConfig | None = None,
    use_ml: bool = True,
) -> AnalysisResult:
    """Parse and analyze one PCAP through the shared pipeline."""
    frames = parse_pcap(pcap)
    selected_inventory = inventory or APInventory.from_frames(frames)
    return analyze_frames(
        frames,
        selected_inventory,
        rules_dir=rules_dir,
        model_root=model_root,
        trusted_model_root=trusted_model_root,
        window_seconds=window_seconds,
        step_seconds=step_seconds,
        correlation_config=correlation_config,
        use_ml=use_ml,
    )
