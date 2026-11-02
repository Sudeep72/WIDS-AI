from __future__ import annotations

from pathlib import Path

import pytest

from wids_ai.synthetic.generator import generate_dataset


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
        "mixed_evil_twin",
        "mixed_deauth_burst",
        "mixed_karma_probe_responses",
        "mixed_beacon_sequence_anomaly",
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
