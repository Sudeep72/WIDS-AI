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
