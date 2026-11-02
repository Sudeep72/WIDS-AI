"""IsolationForest pipeline training, scoring, and trusted persistence."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from pydantic import BaseModel, ConfigDict

from wids_ai.features.extractors import FeatureRow
from wids_ai.ml.baseline import NUMERIC_FEATURES, build_training_matrix

MODEL_FILENAME = "isolation_forest.joblib"
METADATA_FILENAME = "isolation_forest.metadata.json"
MODEL_KIND = "wids-ai-isolation-forest-robust-scaler"
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_MODELS_DIR = PROJECT_ROOT / "models"


class ModelDependencyError(RuntimeError):
    """Raised when the sklearn runtime cannot load native extensions."""


class ModelIntegrityError(ValueError):
    """Raised when a model or its metadata fails integrity checks."""


class ModelMetadata(BaseModel):
    """Persisted model provenance and preprocessing information."""

    model_config = ConfigDict(extra="forbid")

    model_kind: str = MODEL_KIND
    feature_names: tuple[str, ...]
    imputation_medians: dict[str, float]
    training_window_count: int
    sklearn_version: str
    seed: int
    contamination: float
    trained_at: str
    model_sha256: str
    score_mapping: str = (
        "raw decision_function values are mapped to 0..1 with "
        "score=1/(1+exp(raw_score*8)); lower raw IsolationForest decision scores map closer to 1; higher means more anomalous"
    )


@dataclass(frozen=True)
class TrainedModel:
    pipeline: object
    metadata: ModelMetadata
    model_path: Path
    metadata_path: Path


@dataclass(frozen=True)
class ScoredRow:
    row: FeatureRow
    anomaly_score: float


@dataclass(frozen=True)
class WindowScore:
    window_start: datetime
    window_end: datetime
    anomaly_score: float
    row_count: int


def _sklearn_version() -> str:
    try:
        import sklearn
    except ImportError as exc:
        raise ModelDependencyError(
            "scikit-learn native extensions are unavailable. "
            "Check code integrity policy or use an approved runtime."
        ) from exc
    return sklearn.__version__


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _trusted_model_path(path: str | Path, base: str | Path | None = None) -> Path:
    candidate = Path(path).expanduser().resolve()
    root = Path(base).expanduser().resolve() if base is not None else None
    if root is not None and root not in candidate.parents and candidate != root:
        raise ModelIntegrityError(f"Model path must remain under trusted directory: {root}")
    if candidate.suffix != ".joblib":
        raise ModelIntegrityError("Model file must use the .joblib extension")
    return candidate


def normalized_score(raw_score: float) -> float:
    """Map an IsolationForest decision score to a stable 0..1 anomaly score."""
    value = 1.0 / (1.0 + math.exp(8.0 * float(raw_score)))
    return float(min(1.0, max(0.0, value)))


def _matrix(
    rows: Iterable[FeatureRow] | pd.DataFrame,
    metadata: ModelMetadata,
) -> np.ndarray:
    return build_training_matrix(
        rows,
        feature_names=metadata.feature_names,
        imputation_medians=metadata.imputation_medians,
    ).values


def train_isolation_forest(
    rows: Iterable[FeatureRow] | pd.DataFrame,
    out_dir: str | Path,
    *,
    seed: int = 42,
    contamination: float = 0.05,
) -> TrainedModel:
    """Train a seeded IsolationForest pipeline on benign-only feature rows."""
    if not 0.0 < contamination <= 0.5:
        raise ValueError("contamination must be in (0, 0.5]")
    matrix = build_training_matrix(rows)
    if matrix.row_count < 2:
        raise ValueError("At least two benign training windows are required")
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import RobustScaler
    except ImportError as exc:
        raise ModelDependencyError(
            "scikit-learn native extensions are unavailable. "
            "Check code integrity policy or use an approved runtime."
        ) from exc

    pipeline = Pipeline(
        steps=[
            ("scaler", RobustScaler()),
            (
                "isolation_forest",
                IsolationForest(
                    n_estimators=200,
                    contamination=contamination,
                    random_state=seed,
                    n_jobs=1,
                ),
            ),
        ]
    )
    pipeline.fit(matrix.values)
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    model_path = destination / MODEL_FILENAME
    metadata_path = destination / METADATA_FILENAME
    joblib.dump(pipeline, model_path)
    metadata = ModelMetadata(
        feature_names=matrix.feature_names,
        imputation_medians=dict(matrix.imputation_medians),
        training_window_count=matrix.row_count,
        sklearn_version=_sklearn_version(),
        seed=seed,
        contamination=contamination,
        trained_at=datetime.now(tz=UTC).isoformat(),
        model_sha256=_sha256(model_path),
    )
    metadata_path.write_text(metadata.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return TrainedModel(
        pipeline=pipeline,
        metadata=metadata,
        model_path=model_path,
        metadata_path=metadata_path,
    )


def load_model(
    model_dir: str | Path,
    *,
    trusted_base: str | Path | None = None,
) -> TrainedModel:
    """Load a model only after validating its trusted location and SHA-256."""
    directory = Path(model_dir)
    trust_root = Path(trusted_base) if trusted_base is not None else DEFAULT_MODELS_DIR
    model_path = _trusted_model_path(directory / MODEL_FILENAME, trust_root)
    metadata_path = directory / METADATA_FILENAME
    if not model_path.is_file() or not metadata_path.is_file():
        raise FileNotFoundError("Model file and metadata are required")
    metadata = ModelMetadata.model_validate_json(metadata_path.read_text(encoding="utf-8"))
    if metadata.model_kind != MODEL_KIND:
        raise ModelIntegrityError("Unsupported model kind")
    if metadata.feature_names != NUMERIC_FEATURES:
        raise ModelIntegrityError("Model feature list does not match current schema")
    actual_hash = _sha256(model_path)
    if actual_hash != metadata.model_sha256:
        raise ModelIntegrityError("Model SHA-256 does not match metadata")
    from sklearn.pipeline import Pipeline

    pipeline = joblib.load(model_path)
    if not isinstance(pipeline, Pipeline):
        raise ModelIntegrityError("Persisted model is not a sklearn Pipeline")
    return TrainedModel(
        pipeline=pipeline,
        metadata=metadata,
        model_path=model_path,
        metadata_path=metadata_path,
    )


def score_rows(model: TrainedModel, rows: Iterable[FeatureRow] | pd.DataFrame) -> list[ScoredRow]:
    """Score feature rows and return normalized 0..1 anomaly scores."""
    row_list = list(rows) if not isinstance(rows, pd.DataFrame) else rows
    matrix = _matrix(row_list, model.metadata)
    raw = model.pipeline.decision_function(matrix)
    scores = [normalized_score(value) for value in np.asarray(raw, dtype=float)]
    if isinstance(row_list, pd.DataFrame):
        materialized = [
            FeatureRow.model_validate(item.to_dict()) for _, item in row_list.iterrows()
        ]
    else:
        materialized = row_list
    return [
        ScoredRow(row=row, anomaly_score=score)
        for row, score in zip(materialized, scores, strict=True)
    ]


def aggregate_window_scores(rows: Iterable[ScoredRow]) -> list[WindowScore]:
    """Aggregate scope rows into one maximum anomaly score per time window."""
    grouped: dict[tuple[datetime, datetime], list[ScoredRow]] = {}
    for item in rows:
        grouped.setdefault((item.row.window_start, item.row.window_end), []).append(item)
    return [
        WindowScore(
            window_start=start,
            window_end=end,
            anomaly_score=max(item.anomaly_score for item in items),
            row_count=len(items),
        )
        for (start, end), items in sorted(grouped.items())
    ]


def write_scores(rows: Iterable[ScoredRow], path: str | Path) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        {
            **item.row.model_dump(mode="json"),
            "anomaly_score": item.anomaly_score,
        }
        for item in rows
    ]
    destination.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
