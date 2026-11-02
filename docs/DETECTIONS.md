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