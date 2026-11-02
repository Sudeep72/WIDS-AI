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

FIX B uses one model per scope: BSSID, client, and SSID. Each model receives only
features that have meaning for that scope. This replaces the single shared model
because the shared model diluted client and SSID evidence and the ML evaluation
showed weak attack separation.

Training uses only feature rows extracted from a benign PCAP. It does not read
`labels.json` and does not read attack PCAPs. Each persisted model contains a
RobustScaler, a seeded IsolationForest, and scope-specific metadata. The model
directory contains a joblib pipeline and metadata JSON with feature names, median
imputation values, training count, sklearn version, seed, contamination, training
time, scope, and the SHA-256 digest of the model file.

Operational scores use the maximum of the per-scope scores for a timestamp window.
The evaluation tool also reports top-2 mean. The raw IsolationForest decision score
is mapped with `1 / (1 + exp(raw_score * 8))`. Lower raw decision values mean more
anomalous behavior and map toward 1.0.

Loading verifies the digest and requires each scope directory to match its metadata.
The default trust root is the project `models/` directory. A mismatched digest or a
model outside the trust root is refused.

## Windows testing environment

Windows Application Control can block the unsigned native extension in the installed
scikit-learn wheel. The ML tests skip only when that import is unavailable. This is
an environment policy issue, not a model result. If scikit-learn is blocked, run the
training and scoring tests in an approved Python environment where scikit-learn loads.
## Correlation and alerts

The correlation scorer is rule-first. Default weights are configured as rule 55,
ML 15, AP trust 10, repeat hits 10, and multiple families 10. The final risk is
clamped to 0 through 100. ML-only observations are capped at 25 and are labeled
informational. Rule-backed alert severity is derived from the final risk score.

Related incidents are grouped by family, overlapping BSSID entities, and a
30-second time gap. ATT&CK mappings are looked up from `attack/mapping.yml`; no
mapping is duplicated in alert code. Explanations are deterministic templates built
only from rule evidence fields and the ML score. The alert never claims that ML or
a best-fit ATT&CK mapping establishes certainty.
