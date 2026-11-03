# WIDS-AI

WIDS-AI is an explainable, ATT&CK-mapped wireless intrusion detection system for
802.11 management and control frames. It analyzes PCAPs offline on Windows and can
capture on a Linux monitor-mode adapter without embedding any transmit or attack code.

## Architecture

```text
Linux monitor adapter or offline PCAP
                  |
                  v
            802.11 parser
                  |
                  v
      timestamp windows and features
             /              \
            v                v
      YAML rule engine    scoped IsolationForest
            \                /
             +-- correlation --+
                    |
                    v
          SQLite + REST API
                    |
                    v
             offline dashboard
```

## Features

- Four defensive families: evil twin, deauth/disassociation, KARMA-style probe
  responses, and beacon/management anomalies.
- Scope-specific IsolationForest models for BSSID, client, and SSID context.
- Deterministic, evidence-based alert explanations and ATT&CK best-fit mappings.
- NanoSIEM NDJSON and secure HTTP export.
- Replay dashboard with AP inventory, trust scores, alert details, and ML trend.
- Linux live capture with pre-flight checks, arrival-time timestamps, optional
  PCAP writing, manual channel control, and graceful shutdown.
- No frame injection, deauthentication sending, or transmit APIs.

## Quickstart on Windows

```powershell
.\scripts\setup.ps1
.\scripts\run_demo.ps1
```

Open `http://127.0.0.1:8000`. The demo builds synthetic fixtures, a benign
inventory, and models before replaying `mixed_evil_twin.pcap`.

## Results

Synthetic evaluation, seeds 1, 2, 3, 42, and 99. These are not field accuracy claims.
See `docs/EVALUATION.md` for the complete generated report and limitations.

| Family | Precision | Recall | Detection delay mean |
| --- | ---: | ---: | ---: |
| Evil twin | 1.000 | 1.000 | 0.000 s |
| Deauthentication | 1.000 | 1.000 | 0.000 s |
| KARMA probe response | 1.000 | 1.000 | 0.030 s |
| Beacon anomaly | 1.000 | 1.000 | 0.000 s |

Synthetic benign/noisy false positives were zero for all five seeds in the M11
evaluation. The low-and-slow deauth was detected on all five seeds. These numbers
come from the same synthetic generator family and are not real-radio accuracy.

The low-and-slow deauth is now covered by cumulative 300-second BSSID and client
rules. The noisy benign beacon false positives from the M10 baseline were removed
by suppressing trusted-BSSID gap-only resets. Updated measurements are in
`docs/EVALUATION.md`.

## Detections

| Family | Rule IDs | ATT&CK best fit | Verification |
| --- | --- | --- | --- |
| Evil twin | WIDS-EVIL-001 to 004 | T1557 Adversary-in-the-Middle | Verify at attack.mitre.org |
| Deauth | WIDS-DEAUTH-001 to 006 | T1498 Network Denial of Service | Verify at attack.mitre.org |
| KARMA | WIDS-KARMA-001, 002 | T1557 Adversary-in-the-Middle | Verify at attack.mitre.org |
| Beacon anomaly | WIDS-BEACON-001 to 003 | None, spoofing or evasion indicator | No forced technique |

Thresholds and false-positive notes are in `docs/DETECTIONS.md`.

## Live capture

Live capture is Linux-only. Run `scripts/kali_preflight.sh`, then:

```bash
.venv/bin/python -m wids_ai baseline --live --iface wlan0mon --duration 300   --out data/inventory.json --yes
.venv/bin/python -m wids_ai train --live --iface wlan0mon --duration 600   --out models/live
.venv/bin/python -m wids_ai live --iface wlan0mon   --write-pcap data/live.pcap --serve
```

See `docs/KALI_LIVE_TESTING.md` for adapter passthrough, monitor mode, channel
selection, capture validation, replay, and troubleshooting.

## NanoSIEM

Export is off by default. Use `--siem-file` or `--siem-url` with `analyze`,
`serve --replay`, or `live`. The event contract, secure HTTP behavior, validator,
and Sigma examples are in `docs/NANOSIEM_INTEGRATION.md`.

## Screenshots

- [Dashboard placeholder](https://github.com/Sudeep72/WIDS-AI/blob/main/docs/img/dashboard.png)
- [Alert detail placeholder](docs/img/alert-detail.png)

## Roadmap

- Real-radio validation on authorized isolated labs.
- Multi-channel capture planning and loss accounting.
- WPA3-specific management behavior and richer 802.11 control-frame coverage.
- Analyst workflow and evidence export improvements.

## Responsible use

Use WIDS-AI only on networks you own or are explicitly authorized to monitor.
The project contains no transmit or injection code. See `docs/RESPONSIBLE_USE.md`.

## Development

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\check.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\check_full.ps1
node --check dashboard\app.js
```
