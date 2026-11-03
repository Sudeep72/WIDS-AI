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
## M8 data flow

```text
PCAP / guarded live capture
          |
          v
     802.11 parser
          |
          v
 timestamp windows -> feature extraction
          |                    |
          v                    v
    YAML rules          scope ML models
          \                    /
           +------ correlation ------+
                      |
                      v
              rule evidence + ML + trust
                      |
                      v
                 SQLite database
                      |
                      v
               read-only FastAPI
                      |
                      v
              offline dashboard
```

## API reference

All endpoints are read-only and bind to `127.0.0.1` by default. Every response
carries CSP `default-src 'self'`, `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, and `Referrer-Policy: no-referrer`.

- `GET /api/health` returns `{"status":"ok","schema_version":1}`.
- `GET /api/stats?run=latest` returns latest-run frame and window counts, alerts by
  severity and family, run id and start time, and up to 200 time-ordered ML score
  samples. Use `run=all` for cumulative totals.
- `GET /api/aps` returns SSID, BSSID, vendor OUI, channels, RSSI, security, trust
  score, and flagged state.
- `GET /api/alerts?severity=&family=&since=&limit=50&offset=0` returns alert JSON.
  Limit is capped at 500. Invalid severity, family, since, limit, or offset returns
  HTTP 422.
- `GET /api/alerts/{id}` returns full evidence, indicators found and not found,
  why text, and the ATT&CK mapping.

Alert evidence and indicator objects use the same contract: `field`, `observed`,
`threshold`, `operator`, `text`, and `rule_ids`. The dashboard reads those fields
from the Pydantic response model. `serve --replay` uses `--fresh` by default to
clear previous alerts, APs and ML scores; `--keep` retains those records.

SSIDs and other frame-derived strings are control-character stripped and truncated
in the API and rendered with `textContent` in the dashboard.


## Run-scoped replay

Replay statistics default to the latest run. Cumulative statistics are available
with `/api/stats?run=all`. A fresh replay clears alerts, APs, incidents, frame
summaries, and the ML score series before creating a new run, preventing double
counting when the same PCAP is replayed.


## M10 evaluation pipeline

`wids_ai.pipeline.analyze_frames` is the shared path used by offline analysis, replay, tests, and evaluation. It parses frames, builds timestamp windows, extracts features, evaluates rules and AP inventory context, optionally scores scope models, deduplicates incidents, and correlates alerts. This keeps CLI and replay alert IDs comparable.

`tools/evaluate.py` runs seeds 1, 2, 3, 42, and 99. It trains only from each seed benign PCAP and writes `docs/EVALUATION.md` from measured results. The report is synthetic-only. Challenge scenarios are intentionally reported without forcing them to pass.

`tools/benchmark.py` measures offline full-pipeline throughput. Peak memory is reported when the platform provides `resource`; it is unavailable on this Windows runtime.


## M11 live path

Live capture preflights Linux, privileges, the interface, monitor mode, and RadioTap.
Packets are timestamped with `time.time()` at arrival because RadioTap has no wall
clock. The same parser, windowing, features, rules, ML, correlation, and persistence
path used for replay handles the resulting frames. Ctrl+C stops capture, flushes the
window state, writes the PCAP, closes the database, and returns cleanly.

`/api/stats` reports latest-run frames per second, parse errors, and queue drops.
Channel hopping is off by default and uses a fixed `iw dev <iface> set channel N`
argument list when requested.
