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

## Python compatibility

The project requires Python 3.11 or newer. The pinned runtime and development
requirements resolve on CPython 3.11, 3.12, 3.13, and 3.14. Linux wheels were
validated against the manylinux 2.17 and 2.28 x86_64 targets, and Windows wheels
were validated for the local runtime. NumPy 2.3.5, SciPy 1.17.1, and pandas 2.3.3
are the common pins that preserve Python 3.11 support without version-specific
requirements files.

## NanoSIEM export

NanoSIEM export is disabled by default. Use `--siem-file` or `--siem-url` with
`analyze` or `serve --replay`. See `docs/NANOSIEM_INTEGRATION.md` for the event
contract, secure HTTP behavior, validation tool, and Sigma examples.

## Safety boundary
This project is defensive only. It does not contain frame injection, deauthentication
sending, or any transmit function. Synthetic fixtures are written to PCAP files only.
