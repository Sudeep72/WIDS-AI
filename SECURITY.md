# Security Policy

## Reporting

Report vulnerabilities privately to the repository owner. Include the affected
version, a minimal reproduction, operating system, Python version, and whether
live capture or replay was involved. Do not include secrets, capture files from
networks you do not own, or personal data in a public issue.

## Scope

WIDS-AI is a defensive 802.11 management and control frame monitor. Reports about
parser crashes, resource exhaustion, arbitrary file access, unsafe model loading,
SQL injection, dashboard injection, or secret exposure are in scope.

The project contains no frame injection, deauthentication sending, association
flooding, or transmit API. Live capture requires Linux monitor mode with root or
CAP_NET_RAW. Use it only on networks you own or are explicitly authorized to
monitor.

## Supported versions

The current 0.1.x line is supported during active development. Revalidate
dependencies and ATT&CK mappings before operational use.
