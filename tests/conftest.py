from __future__ import annotations

import os
import shutil
import time
from pathlib import Path

import pytest

from wids_ai.synthetic.generator import generate_dataset


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    """Use unique per-run temp and cache paths on Windows."""
    root = Path(__file__).resolve().parent.parent / ".tmp"
    run_id = f"{os.getpid()}-{time.time_ns()}"
    base = root / f"pytest-{run_id}"
    cache = root / f"pytest-cache-{run_id}"
    for path in (base, cache):
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
    config.option.basetemp = str(base)
    config.option.cache_dir = str(cache)


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def synthetic_dataset(tmp_path_factory: pytest.TempPathFactory):
    cache: dict[int, Path] = {}

    def build(seed: int = 42) -> Path:
        if seed not in cache:
            root = tmp_path_factory.mktemp(f"synthetic-seed-{seed}")
            destination = root / "synthetic"
            generate_dataset(destination, seed=seed)
            cache[seed] = destination
        return cache[seed]

    return build


@pytest.fixture(scope="session")
def parsed_synthetic(synthetic_dataset):
    from wids_ai.capture.base import PcapSource
    from wids_ai.features.extractors import FeatureRow, batch_extract
    from wids_ai.features.windowing import WindowConfig
    from wids_ai.parser.dot11 import parse_frame

    dataset = synthetic_dataset(42)
    result = {}
    for name in (
        "benign_baseline",
        "benign_noisy",
        "mixed_evil_twin",
        "mixed_deauth_burst",
        "mixed_karma_probe_responses",
        "mixed_beacon_sequence_anomaly",
        "mixed_low_slow_deauth",
        "mixed_evil_twin_matching_oui",
    ):
        frames = [
            frame
            for packet in PcapSource(dataset / f"{name}.pcap").packets()
            if (frame := parse_frame(packet)) is not None
        ]
        feature_frame = batch_extract(frames, WindowConfig(10, 5))
        rows = [FeatureRow.model_validate(item.to_dict()) for _, item in feature_frame.iterrows()]
        result[name] = (frames, rows)
    return dataset, result


@pytest.fixture(scope="session")
def evaluated_seed(tmp_path_factory, synthetic_dataset):
    from wids_ai.evaluation import build_seed_artifacts

    cache = {}

    def build(seed: int = 42):
        if seed not in cache:
            work_root = tmp_path_factory.mktemp(f"evaluation-seed-{seed}")
            dataset = synthetic_dataset(seed)
            cache[seed] = build_seed_artifacts(seed, dataset, work_root)
        return cache[seed]

    return build
