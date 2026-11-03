# Kali Live Capture Testing

This guide is for an isolated lab network and equipment you own or are explicitly
authorized to monitor. WIDS-AI contains no transmit, injection, or attack code.
Any validation traffic must be produced separately with tools you already know and
control.

## 1. Copy the project and create a venv

For a private repository, authenticate with your own SSH key or a scoped token.

```bash
cd ~
git clone <your-private-repository-url> WIDS-AI
cd WIDS-AI
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
chmod +x scripts/kali_preflight.sh
./scripts/kali_preflight.sh
```

The preflight must print PASS for Python, the venv, dependencies, iw, aircrack-ng,
tshark or Wireshark, the adapter, and USB detection.

## 2. Pass the Alfa adapter into the VM

In VirtualBox, attach the USB adapter through Devices, USB, then select the adapter.
In VMware, add a USB controller and connect the adapter to the VM. Confirm it is
visible in Kali:

```bash
lsusb
iw dev
```

If the adapter is visible in the host only, disconnect it from the host OS and
reconnect it to the VM. USB 3 controllers may need USB 3 support enabled.

## 3. Prepare monitor mode

NetworkManager and wpa_supplicant can interfere with monitor mode. The following
command can drop normal Wi-Fi connectivity:

```bash
sudo airmon-ng check kill
sudo airmon-ng start wlan0
iw dev
```

Use the monitor interface name reported by `iw dev`, commonly `wlan0mon`.
Set the channel manually:

```bash
sudo iw dev wlan0mon set channel 6
iw dev wlan0mon info
```

The output must include `type monitor` and channel 6.

## 4. Confirm management frames and RadioTap

Use a passive one-frame sanity capture. Stop it with Ctrl+C after seeing 802.11
management traffic:

```bash
sudo tshark -i wlan0mon -c 1 -V
```

You should see a `radiotap` header and an 802.11 frame. Wireshark can open the same
capture from the GUI. No wireless transmission is performed by these commands.

## 5. Build trusted inventory and models

Run this while the isolated lab AP is present:

```bash
.venv/bin/python -m wids_ai baseline --live --iface wlan0mon   --duration 300 --out data/inventory.json
```

Review every AP prompt and answer only for equipment you own. For a non-interactive
lab run where every observed AP is known, use `--yes`.

```bash
.venv/bin/python -m wids_ai train --live --iface wlan0mon   --duration 600 --out models/live
```

## 6. Run live detection

```bash
.venv/bin/python -m wids_ai live --iface wlan0mon   --write-pcap data/live-session.pcap   --db data/wids.db --serve
```

Open `http://127.0.0.1:8000`. The live session uses capture arrival time for frame
timestamps and periodic manual channel changes only if `--hop-channels` is supplied.
Channel hopping uses a fixed `iw` argument list, never a shell.

For manual channel hopping:

```bash
.venv/bin/python -m wids_ai live --iface wlan0mon   --hop-channels 1,6,11 --hop-interval 0.5
```

## 7. Validate on your own isolated AP

Generate the validation events yourself with the standard tools you already use.
This repository does not include or document attack commands. Watch the dashboard
for evidence and alerts, then stop the live session with Ctrl+C. Buffered windows
are flushed, the database is closed, and the PCAP is finalized.

Replay the saved capture:

```bash
.venv/bin/python -m wids_ai serve --replay data/live-session.pcap   --inventory data/inventory.json --model models/live --db data/replay.db
```

Confirm the same alert IDs and families appear. Open the capture in Wireshark:

```bash
wireshark data/live-session.pcap
```

## Troubleshooting

| Symptom | Check | Fix |
| --- | --- | --- |
| No frames | `iw dev wlan0mon info` | Confirm `type monitor` and the intended channel. |
| Wrong channel | `sudo iw dev wlan0mon set channel 6` | Set the channel manually or use `--hop-channels`. |
| No RadioTap | `sudo tshark -i wlan0mon -c 1 -V` | Use a monitor-mode adapter; managed-mode captures do not provide RadioTap. |
| Permission denied | `id` and `capsh --print` | Run as root or grant `CAP_NET_RAW`. |
| Adapter not in monitor mode | `iw dev` | Re-run `sudo airmon-ng start wlan0`. |
| VM USB issue | `lsusb` in Kali | Disconnect from host and attach the USB device to the VM. |
| Interface missing | `ip link` | Verify the adapter and driver inside the VM. |

## Results template

| Scenario | Expected | Detected | Delay | False positives |
| --- | --- | --- | --- | --- |
| Evil twin | | | | |
| Deauth burst | | | | |
| KARMA probe responses | | | | |
| Beacon anomaly | | | | |
| Low and slow deauth | | | | |
| Noisy benign | | | | |
