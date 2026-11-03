#!/usr/bin/env bash
set -u
fail=0
check() { if eval "$2" >/dev/null 2>&1; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }
check "python3 3.11+" 'python3 -c "import sys; raise SystemExit(sys.version_info < (3,11))"'
check "virtualenv" 'test -x .venv/bin/python'
check "pip dependencies" '.venv/bin/python -m pip check'
check "iw" 'command -v iw'
check "aircrack-ng" 'command -v airmon-ng'
check "tshark" 'command -v tshark || command -v wireshark'
check "wireless adapter" 'iw dev | grep -q Interface'
check "USB adapter" 'lsusb | grep -Ei "alfa|atheros|ralink|mediatek|realtek"'
if [[ ${fail} -eq 0 ]]; then echo "PASS Kali preflight"; else echo "FAIL Kali preflight"; fi
exit ${fail}
