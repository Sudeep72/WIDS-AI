from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from wids_ai.features.extractors import FeatureRow
from wids_ai.ml.baseline import (
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
def synthetic(synthetic_dataset) -> Path:
    return synthetic_dataset(42)


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


@pytest.mark.slow
def test_scope_models_and_aggregation_produce_scores(synthetic: Path) -> None:
    rows = load_benign_rows(synthetic / "benign_baseline.pcap")
    for scope in ("bssid", "client", "ssid"):
        scope_rows = [row for row in rows if row.scope == scope]
        model = train_isolation_forest(
            scope_rows,
            synthetic.parent / f"model-{scope}",
            seed=42,
        )
        assert model.metadata.scope == scope
        scores = score_rows(model, scope_rows)
        assert scores
        assert all(0.0 <= item.anomaly_score <= 1.0 for item in scores)
        assert aggregate_window_scores(scores, method="max")
        assert aggregate_window_scores(scores, method="top_k_mean", top_k=2)


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


@pytest.mark.slow
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


@pytest.mark.slow
def test_benign_alert_is_not_above_informational(trained, synthetic: Path, tmp_path: Path) -> None:
    from wids_ai.cli import main

    model_root = tmp_path / "models"
    for scope in ("bssid", "client", "ssid"):
        scope_rows = [
            row
            for row in load_benign_rows(synthetic / "benign_baseline.pcap")
            if row.scope == scope
        ]
        train_isolation_forest(scope_rows, model_root, seed=42)
    output = tmp_path / "alerts.json"
    inventory = tmp_path / "inventory.json"
    assert main(["baseline", str(synthetic / "benign_baseline.pcap"), "--out", str(inventory)]) == 0
    assert (
        main(
            [
                "analyze",
                str(synthetic / "benign_baseline.pcap"),
                "--inventory",
                str(inventory),
                "--rules",
                str(Path(__file__).resolve().parent.parent / "wids_ai" / "rules" / "rules"),
                "--model",
                str(model_root),
                "--trusted-model-root",
                str(tmp_path),
                "--out",
                str(output),
            ]
        )
        == 0
    )
    alerts = json.loads(output.read_text(encoding="utf-8"))
    assert all(alert["severity"] == "informational" for alert in alerts)
    assert all(alert["risk_score"] <= 25 for alert in alerts)
