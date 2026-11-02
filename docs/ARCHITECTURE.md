# Architecture

WIDS-AI processes 802.11 management and control frames from offline PCAP files on all
supported platforms. Live capture is isolated behind a Linux-only source.

## Milestone M1 components

- `wids_ai.config` loads and validates `config/wids.yml`.
- `wids_ai.logging_config` configures deterministic console and optional file logging.
- `wids_ai.cli` exposes analyze, train, serve, and live command namespaces.
- `wids_ai.capture` defines the source contract and the live Linux guard.

## Planned data flow

1. Capture yields packets from PCAP or a Linux monitor-mode interface.
2. Parser converts packets into typed frame records.
3. Windowing groups events by BSSID, client, and channel.
4. Feature extraction creates bounded numeric vectors.
5. Rules and the anomaly model generate independent evidence.
6. Correlation produces a risk score and deterministic explanation.
7. SQLite and the API expose alerts, access points, and statistics.

## Anomaly model design

M6 uses one shared IsolationForest over a fixed BSSID-scope feature set. This design
was selected over per-scope models for three reasons:

1. The benign training sample is small. Splitting it into three models would reduce
   each model's training evidence further.
2. A shared scaler and feature order makes scores comparable across windows.
3. Rules retain client and SSID semantics. The ML model supplies one supporting
   anomaly signal for BSSID behavior, not the sole verdict.

Training uses only feature rows extracted from a benign PCAP. It does not read
`labels.json` and does not read attack PCAPs. The persisted model contains a
RobustScaler plus a seeded IsolationForest. The operational score is the maximum
row score within each timestamp window, mapped from the IsolationForest decision
function with `1 / (1 + exp(raw_score * 8))`. Lower raw decision values mean more
anomalous behavior and map toward 1.0.

The model directory contains a joblib pipeline and metadata JSON with feature names,
median imputation values, training count, sklearn version, seed, contamination,
training time, and the SHA-256 digest of the model file. Loading verifies the digest
and defaults to the project `models/` trust root. A mismatched digest or a model
outside the trust root is refused.

## Windows testing environment

Windows Application Control can block the unsigned native extension in the installed
scikit-learn wheel. The ML tests skip only when that import is unavailable. This is
an environment policy issue, not a model result. If scikit-learn is blocked, run the
training and scoring tests in an approved Python environment where scikit-learn loads.