# Detections and Features

The MVP implements four defensive detection families:

1. Evil twin or rogue access point evidence.
2. Deauthentication and disassociation anomalies.
3. Probe-response or KARMA-style behavior.
4. Beacon and management behavior anomalies.

Detection rule sets and ATT&CK mappings are added in later milestones. The anomaly
model is one ensemble input and is never treated as a standalone verdict.

## Window contract

`wids_ai.features.windowing` uses frame timestamps only. It does not read the wall
clock. Windows are half-open: `start <= frame.timestamp < end`.

- Sliding windows default to 10 seconds with a 5 second step.
- Tumbling windows require the step to equal the size.
- Frames are grouped by BSSID, client (`addr2`), channel, and SSID.
- `WindowAggregator` is the incremental interface for live capture.
- `batch_extract` is the offline helper for parsed PCAP frames.
- Empty feature input returns an empty DataFrame with the full stable schema.

`WindowAggregator.flush_ready(final=True)` emits the same windows as the batch helper.
When `retain_seconds` is set, older buffered frames are discarded after emission.

## Stable feature columns

The CSV and DataFrame use this order from `FeatureRow`:

1. `window_start`
2. `window_end`
3. `scope`
4. `group`
5. `frame_count`
6. `beacon_count`
7. `beacon_interval_mean`
8. `beacon_interval_std`
9. `beacon_interval_jitter`
10. `seq_gap_count`
11. `seq_duplicate_count`
12. `probe_response_count`
13. `distinct_ssids_answered`
14. `deauth_count`
15. `disassoc_count`
16. `rssi_mean`
17. `rssi_std`
18. `channel_change_count`
19. `deauth_received_rate`
20. `probe_request_count`
21. `distinct_ssids_probed`
22. `distinct_bssids`
23. `distinct_ouis`
24. `distinct_channels`
25. `rsn_mismatch`
26. `rssi_spread`
27. `beacon_ratio`
28. `probe_request_ratio`
29. `probe_response_ratio`
30. `deauth_ratio`
31. `disassoc_ratio`
32. `authentication_ratio`
33. `association_ratio`
34. `action_ratio`

All columns except the timestamp, scope, and group identifiers are numeric.
Broadcast and multicast addresses are excluded from BSSID and OUI counts.

## Scope behavior

- BSSID rows summarize beacon stability, sequence gaps, probe responses, deauth and
  disassociation volume, RSSI, channels, and management subtype ratios.
- Client rows emphasize received deauth rate, probe-request volume, and distinct SSIDs
  probed.
- SSID rows expose distinct BSSIDs, OUIs, channels, RSN mismatch, and RSSI spread.
- Channel rows summarize activity, RSSI, and management subtype ratios per channel.

## CLI

```powershell
.\.venv\Scripts\python.exe -m wids_ai.cli features data\synthetic\benign_baseline.pcap --out .tmp\features.csv
```
## Rule catalog

Rules are loaded from `wids_ai/rules/rules/*.yml`. Each document is one rule and
uses pydantic validation. Attack mappings live only in
`wids_ai/attack/mapping.yml`. The mappings below are best-fit ATT&CK mappings and
must be verified at attack.mitre.org.

### Evil twin and rogue AP

- `WIDS-EVIL-001`: duplicate SSID with at least 2 distinct BSSIDs. Severity high.
  False positives include legitimate roaming and mesh deployments.
- `WIDS-EVIL-002`: unknown BSSID with an OUI mismatch against the inventory.
  Severity critical. False positives include newly deployed hardware.
- `WIDS-EVIL-003`: channel, security, or RSN mismatch for a known SSID. Severity
  high. False positives include intentional band steering or a security migration.
- `WIDS-EVIL-004`: RSSI spread of at least 40 dB across BSSIDs for one SSID.
  Severity medium. False positives include APs at very different distances.

### Deauthentication and disassociation

- `WIDS-DEAUTH-001`: at least 6 deauth frames and 0.6 deauth frames per second
  from one BSSID. Severity high. False positives include AP reboots.
- `WIDS-DEAUTH-002`: at least 2 broadcast deauth frames. Severity critical.
  False positives include rare network-wide resets.
- `WIDS-DEAUTH-003`: a client receives at least 5 deauth frames. Severity high.
  False positives include repeated association failures.
- `WIDS-DEAUTH-004`: at least 6 deauth frames with a dominant reason code and at
  least 2 reason codes. Severity medium. False positives include normal client
  disconnect patterns.

### Probe response and KARMA style

- `WIDS-KARMA-001`: one BSSID answers probe requests for at least 3 distinct
  SSIDs. Severity critical. False positives include multi-SSID access points.
- `WIDS-KARMA-002`: at least 5 probe responses and 5 distinct answered SSIDs from
  one BSSID. Severity high. False positives include busy public hotspots.

### Beacon and management behavior

- `WIDS-BEACON-001`: beacon interval standard deviation of at least 50 ms with at
  least 3 beacons. Severity high. False positives include packet loss.
- `WIDS-BEACON-002`: at least 2 duplicate sequence numbers or 3 sequence gaps.
  Severity high. False positives include retransmissions and firmware resets.
- `WIDS-BEACON-003`: beacon interval jitter of at least 20 ms with at least
  3 beacons. Severity medium. False positives include channel changes and packet
  loss in short windows.

## Deduplication

Rule hits with the same rule and entity identities are merged when overlapping or
within the configured merge gap. The incident keeps the first and last window
bounds, a hit count, merged evidence, maximum confidence, and the rule false
positive notes.

## Baseline inventory and CLI

```powershell
.\.venv\Scripts\python.exe -m wids_ai.cli baseline data\synthetic\benign_baseline.pcap --out .tmp\inventory.json
.\.venv\Scripts\python.exe -m wids_ai.cli analyze data\synthetic\mixed_deauth_burst.pcap --inventory .tmp\inventory.json --rules wids_ai\rules\rules --out .tmp\detections.json
```

The inventory is in-memory and JSON-backed. Trust scores start at 90 and are
clamped to the 0 to 100 range when rules adjust them.
## Threshold justification

Thresholds were checked against benign BSSID, client, and SSID windows from the
synthetic benign baseline. The benign 99th percentiles were: beacon interval
standard deviation 7.713 ms, interval jitter 6.985 ms, sequence gaps 1, duplicate
sequence numbers 0, deauth count 0, broadcast deauth count 0, answered SSIDs per
BSSID 1, probe responses per BSSID 1, and BSSID count per SSID 1.

- `WIDS-BEACON-001` uses 50 ms interval standard deviation, over six times the
  benign 99th percentile.
- `WIDS-BEACON-002` uses 2 duplicate sequence numbers or 2 gaps, above the benign
  99th percentile for both fields.
- `WIDS-BEACON-003` uses 20 ms interval jitter, nearly three times the benign
  99th percentile.
- Deauth rules use nonzero counts above the benign 99th percentile of zero.
- KARMA rules use 3 or 5 distinct answered SSIDs, above the benign 99th
  percentile of one.
- `WIDS-EVIL-003` now checks inventory channel or security mismatch. Generic RSN
  inconsistency was removed from this rule because it mislabeled a beacon
  anomaly as an evil-twin event.
## ATT&CK mapping review

Verified against attack.mitre.org on 2026-11-02:

- T1557 Adversary-in-the-Middle, Enterprise. Used for evil twin and KARMA style
  evidence. Verified at https://attack.mitre.org/techniques/T1557/.
- T1498 Network Denial of Service, Enterprise. Used as the best fit for deauth and
  disassociation bursts. Verified at https://attack.mitre.org/techniques/T1498/.
- T1464 Network Denial of Service is a Mobile technique. It was removed from beacon
  anomaly mappings because the project processes Enterprise 802.11 infrastructure.
- Beacon and sequence anomalies have no forced technique. Their mapping is
  `none, spoofing or evasion indicator` and is marked unverified by design.

These are best-fit mappings, not certainty claims. Verify before publishing or using
operationally.

## Correlated alert evidence

Alert evidence is merged by field in the correlation layer. Each merged item lists
the rule IDs that produced it. The explanation is built from that deduplicated
evidence, so a field appears once even when several evil-twin rules observe it.

`indicators_not_found` contains only conditions that were actually evaluated and
did not fire, with their observed and expected values. Placeholder indicators are
not emitted. If no additional condition was evaluated, the list is empty.

The API returns complete evidence and explanation text. The dashboard applies
sentence-boundary truncation only for display.

## AP status semantics

- Unknown BSSIDs are `Flagged` with reason `not in trusted inventory` and trust 0
  after evidence-based replay adjustment.
- Trusted APs that share an SSID with an unknown BSSID are `Watch` with reason
  `SSID shared with untrusted AP`. Their trust remains unchanged unless separate
  evidence justifies a reduction.
- Trusted APs with no such evidence are `Trusted`.
