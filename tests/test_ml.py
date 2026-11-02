from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from wids_ai.capture.base import PcapSource
from wids_ai.features.extractors import FeatureRow, batch_extract
from wids_ai.features.windowing import WindowConfig
from wids_ai.ml.baseline import (
    ML_SCOPES,
    NUMERIC_FEATURES,
    build_training_matrix,
    chronological_split,
    load_benign_rows,
)

pytest.importorskip(
    "sklearn", reason="scikit-learn native extensions are blocked by local code integrity policy"
)

from wids_ai.ml.isolation_forest import (
    ModelIntegrityError,
    aggregate_window_scores,
    load_model,
    normalized_score,
    score_rows,
    train_isolation_forest,
)
from wids_ai.parser.dot11 import parse_frame
from wids_ai.synthetic.generator import generate_dataset

BASE = datetime(2025, 1, 1, tzinfo=UTC)
LABELS_NAME = "labels.json"
ATTACK_MARKER = "attack_start"


def _row(index: int, **updates: object) -> FeatureRow:
    values: dict[str, object] = {
        "window_start": BASE + timedelta(seconds=index * 5),
        "window_end": BASE + timedelta(seconds=index * 5 + 10),
        "scope": "bssid",
        "group": "00:11:22:33:44:55",
    }
    for name in NUMERIC_FEATURES:
        values[name] = float(index % 3)
    values.update(updates)
    return FeatureRow.model_validate(values)


@pytest.fixture(scope="session")
def synthetic(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("ml-synthetic") / "synthetic"
    generate_dataset(out, seed=42)
    return out


@pytest.fixture(scope="session")
def benign_rows(synthetic: Path) -> list[FeatureRow]:
    return load_benign_rows(synthetic / "benign_baseline.pcap")


@pytest.fixture(scope="session")
def trained(tmp_path_factory: pytest.TempPathFactory, benign_rows: list[FeatureRow]):
    out = tmp_path_factory.mktemp("ml-model")
    return train_isolation_forest(benign_rows, out, seed=42, contamination=0.05)


def test_training_matrix_is_numeric_finite_and_stable() -> None:
    frame = pd.DataFrame([row.model_dump() for row in [_row(0), _row(1)]])
    frame["frame_count"] = [float("nan"), float("inf")]
    matrix = build_training_matrix(frame)
    assert matrix.feature_names == NUMERIC_FEATURES
    assert matrix.values.shape == (2, len(NUMERIC_FEATURES))
    assert all(value == value for value in matrix.values.ravel())
    assert set(matrix.imputation_medians) == set(NUMERIC_FEATURES)


def test_training_matrix_rejects_missing_columns() -> None:
    with pytest.raises(ValueError, match="Missing feature columns"):
        build_training_matrix(pd.DataFrame([{"frame_count": 1}]))


def test_determinism_with_fixed_seed(
    tmp_path: Path,
    benign_rows: list[FeatureRow],
) -> None:
    first = train_isolation_forest(benign_rows, tmp_path / "first", seed=7)
    second = train_isolation_forest(benign_rows, tmp_path / "second", seed=7)
    assert first.metadata.model_sha256 == second.metadata.model_sha256
    assert first.metadata.feature_names == second.metadata.feature_names


def test_save_load_round_trip_and_hash(trained) -> None:
    loaded = load_model(trained.model_path.parent, trusted_base=trained.model_path.parent.parent)
    assert loaded.metadata.model_sha256 == trained.metadata.model_sha256
    rows = [_row(0), _row(1)]
    first = score_rows(trained, rows)
    second = score_rows(loaded, rows)
    assert [item.anomaly_score for item in first] == [item.anomaly_score for item in second]


def test_hash_mismatch_is_rejected(trained, tmp_path: Path) -> None:
    model_dir = tmp_path / "tampered"
    model_dir.mkdir()
    (model_dir / "isolation_forest.joblib").write_bytes(b"tampered")
    (model_dir / "isolation_forest.metadata.json").write_text(
        trained.metadata.model_dump_json(),
        encoding="utf-8",
    )
    with pytest.raises(ModelIntegrityError, match="SHA-256"):
        load_model(model_dir, trusted_base=tmp_path)


def test_untrusted_model_path_is_rejected(trained, tmp_path: Path) -> None:
    with pytest.raises(ModelIntegrityError, match="trusted directory"):
        load_model(trained.model_path.parent, trusted_base=tmp_path / "other")


def test_score_mapping_is_bounded() -> None:
    assert 0.0 <= normalized_score(-10.0) <= 1.0
    assert 0.0 <= normalized_score(10.0) <= 1.0
    assert normalized_score(-1.0) > normalized_score(1.0)


def test_attack_windows_score_higher_on_every_mixed_pcap(
    synthetic: Path,
    trained,
) -> None:
    labels = json.loads((synthetic / LABELS_NAME).read_text(encoding="utf-8"))
    by_name = {item["scenario"]: item for item in labels["scenarios"]}
    for name in (
        "mixed_evil_twin",
        "mixed_deauth_burst",
        "mixed_karma_probe_responses",
        "mixed_beacon_sequence_anomaly",
    ):
        frames = [
            frame
            for packet in PcapSource(synthetic / f"{name}.pcap").packets()
            if (frame := parse_frame(packet)) is not None
        ]
        features = batch_extract(frames, WindowConfig(10, 5))
        features = features[features["scope"].isin(ML_SCOPES)]
        scored = aggregate_window_scores(score_rows(trained, features))
        start = datetime.fromisoformat(by_name[name]["details"]["attack_start"])
        end = datetime.fromisoformat(by_name[name]["details"]["attack_end"])
        inside = [
            item.anomaly_score
            for item in scored
            if item.window_end >= start and item.window_start <= end
        ]
        outside = [
            item.anomaly_score
            for item in scored
            if item.window_end < start or item.window_start > end
        ]
        assert inside
        assert sum(inside) / len(inside) > sum(outside) / len(outside)


def test_chronological_split_is_time_ordered(benign_rows: list[FeatureRow]) -> None:
    train, test = chronological_split(benign_rows, 0.7)
    assert train
    assert test
    assert len(train) > len(test)
    assert max(row.window_start for row in train) <= min(row.window_start for row in test)


def test_training_code_does_not_read_labels(
    monkeypatch: pytest.MonkeyPatch, synthetic: Path
) -> None:
    import wids_ai.ml.baseline as baseline_module
    import wids_ai.ml.isolation_forest as model_module

    source = Path(baseline_module.__file__).read_text(encoding="utf-8") + Path(
        model_module.__file__
    ).read_text(encoding="utf-8")
    assert LABELS_NAME not in source
    assert ATTACK_MARKER not in source


def test_cli_score_writes_scores(
    tmp_path: Path, synthetic: Path, benign_rows: list[FeatureRow]
) -> None:
    from wids_ai.cli import main

    model_dir = tmp_path / "models"
    train_isolation_forest(benign_rows, model_dir, seed=42)
    output = tmp_path / "scores.json"
    assert (
        main(
            [
                "score",
                str(synthetic / "mixed_evil_twin.pcap"),
                "--model",
                str(model_dir),
                "--trusted-model-root",
                str(tmp_path),
                "--out",
                str(output),
            ]
        )
        == 0
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload
    assert all(0.0 <= item["anomaly_score"] <= 1.0 for item in payload)
