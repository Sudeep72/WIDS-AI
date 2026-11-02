# WIDS-AI

WIDS-AI is a defensive wireless intrusion detection project for 802.11 management and
control frames. It is being built milestone by milestone. Development and offline analysis
run on Windows without a wireless adapter. Live monitor-mode capture is Linux-only.

## Current status

Milestone M1 provides the project scaffold, pinned environment, configuration, logging,
CLI entry point, and test and lint checks.

## Setup on Windows

```powershell
.\scripts\setup.ps1
.\scripts\check.ps1
```

## Setup on Linux or macOS

```bash
./scripts/setup.sh
./scripts/check.sh
```

## Manual validation

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m pytest
```

Expected result is a clean Ruff run and all tests passing. The scaffold has no
wireless transmission code. Live capture is refused on non-Linux systems.

## Safety boundary

This project is defensive only. It does not contain frame injection, deauthentication
sending, or any transmit function. Synthetic fixtures are written to PCAP files only.
