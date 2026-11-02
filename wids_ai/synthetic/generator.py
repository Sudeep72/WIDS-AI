"""Generate deterministic, labeled 802.11 PCAP fixtures.

The generator only writes capture files with Scapy's wrpcap function.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from scapy.all import (
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    Dot11ProbeReq,
    Dot11ProbeResp,
    RadioTap,
    wrpcap,
)

SEED = 42
BENIGN_DURATION_SECONDS = 12 * 60
BENIGN_BEACON_JITTER_MS = 10
BASE_TIME = 1_735_689_600.0
CHANNEL_FREQUENCY = {1: 2412, 6: 2437, 11: 2462, 36: 5180, 44: 5220}
BROADCAST = "ff:ff:ff:ff:ff:ff"


@dataclass(frozen=True)
class AccessPoint:
    bssid: str
    ssid: str
    channel: int
    oui: str
    rssi: int
    beacon_interval: int = 1000
    privacy: bool = False


@dataclass(frozen=True)
class ScenarioLabels:
    scenario: str
    attack_family: str
    label: str
    bssids: tuple[str, ...] = ()
    ssids: tuple[str, ...] = ()
    clients: tuple[str, ...] = ()
    start: datetime | None = None
    end: datetime | None = None
    packet_count: int = 0
    details: dict[str, object] = field(default_factory=dict)

    def as_json(self) -> dict[str, object]:
        return {
            "scenario": self.scenario,
            "attack_family": self.attack_family,
            "label": self.label,
            "bssids": list(self.bssids),
            "ssids": list(self.ssids),
            "clients": list(self.clients),
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "packet_count": self.packet_count,
            "details": self.details,
        }


@dataclass
class GeneratedScenario:
    name: str
    path: Path
    labels: ScenarioLabels


KNOWN_APS = (
    AccessPoint("00:11:22:33:44:55", "LabNet", 6, "001122", -42),
    AccessPoint("00:11:22:33:44:66", "LabGuest", 1, "001122", -55, privacy=True),
    AccessPoint("00:11:22:33:44:77", "Office-IoT", 11, "001122", -61, privacy=True),
)
LAB_CLIENTS = (
    "aa:bb:cc:00:00:01",
    "aa:bb:cc:00:00:02",
    "aa:bb:cc:00:00:03",
)
TWIN_BSSID = "02:de:ad:be:ef:01"
TWIN_SSID = "LabNet"
DEAUTH_BSSID = KNOWN_APS[0].bssid
DEAUTH_CLIENT = LAB_CLIENTS[0]
KARMA_BSSID = "02:00:00:00:10:01"


def _timestamp(seconds: float) -> datetime:
    return datetime.fromtimestamp(BASE_TIME + seconds, tz=UTC)


def _radio(channel: int, rssi: int) -> RadioTap:
    return RadioTap(
        present="Channel+dBm_AntSignal",
        ChannelFrequency=CHANNEL_FREQUENCY[channel],
        ChannelFlags=0x00A0,
        dBm_AntSignal=rssi,
    )


def _ssid(ssid: str) -> Dot11Elt:
    return Dot11Elt(ID="SSID", info=ssid.encode("utf-8"))


BEACON_TEMPLATES: dict[tuple[str, str, int, int, int, bool], object] = {}


def _build_beacon(ap: AccessPoint, sequence: int, interval: int, rssi: int) -> object:
    key = (ap.bssid, ap.ssid, ap.channel, rssi, interval, ap.privacy)
    packet = BEACON_TEMPLATES.get(key)
    if packet is None:
        packet = (
            _radio(ap.channel, rssi)
            / Dot11(
                type=0,
                subtype=8,
                addr1=BROADCAST,
                addr2=ap.bssid,
                addr3=ap.bssid,
                SC=0,
            )
            / Dot11Beacon(
                cap=0x0411 if ap.privacy else 0x0401,
                beacon_interval=interval,
            )
            / _ssid(ap.ssid)
        )
        BEACON_TEMPLATES[key] = packet
    packet[Dot11].SC = (sequence & 0xFFF) << 4
    return packet


def _probe_request(client: str, sequence: int, ssid: str | None = None) -> object:
    packet = (
        _radio(6, -70)
        / Dot11(
            type=0,
            subtype=4,
            addr1=BROADCAST,
            addr2=client,
            addr3=BROADCAST,
            SC=(sequence & 0xFFF) << 4,
        )
        / Dot11ProbeReq()
    )
    if ssid is not None:
        packet = packet / _ssid(ssid)
    return packet


def _probe_response(ap: AccessPoint, client: str, sequence: int, ssid: str, rssi: int) -> object:
    return (
        _radio(ap.channel, rssi)
        / Dot11(
            type=0,
            subtype=5,
            addr1=client,
            addr2=ap.bssid,
            addr3=ap.bssid,
            SC=(sequence & 0xFFF) << 4,
        )
        / Dot11ProbeResp(cap=0x0401, beacon_interval=ap.beacon_interval)
        / _ssid(ssid)
    )


def _stamp(packet: object, seconds: float) -> object:
    packet.time = BASE_TIME + seconds
    return packet


def _benign(seed: int) -> tuple[list[object], ScenarioLabels]:
    rng = random.Random(seed + 1)
    packets: list[object] = []
    sequences = {ap.bssid: 0 for ap in KNOWN_APS}
    next_beacon = {ap.bssid: 0.0 + rng.uniform(0, 0.5) for ap in KNOWN_APS}
    duration = BENIGN_DURATION_SECONDS
    ssids = [ap.ssid for ap in KNOWN_APS]
    while True:
        active = [ap for ap in KNOWN_APS if next_beacon[ap.bssid] <= duration]
        if not active:
            break
        ap = min(active, key=lambda item: next_beacon[item.bssid])
        seconds = next_beacon[ap.bssid]
        interval = ap.beacon_interval + rng.randint(
            -BENIGN_BEACON_JITTER_MS, BENIGN_BEACON_JITTER_MS
        )
        packets.append(
            _stamp(
                _build_beacon(ap, sequences[ap.bssid], interval, ap.rssi + rng.randint(-3, 3)),
                seconds,
            )
        )
        sequences[ap.bssid] += 1
        next_beacon[ap.bssid] += interval / 1000.0

    probe_sequence = 0
    for second in range(10, duration, 27):
        client = rng.choice(LAB_CLIENTS)
        ssid = rng.choice([*ssids, None])
        packets.append(_stamp(_probe_request(client, probe_sequence, ssid), second + rng.random()))
        probe_sequence += 1
        if ssid is not None:
            ap = next(item for item in KNOWN_APS if item.ssid == ssid)
            packets.append(
                _stamp(
                    _probe_response(ap, client, probe_sequence, ssid, ap.rssi + rng.randint(-2, 2)),
                    second + rng.random() + 0.02,
                )
            )
            probe_sequence += 1

    packets.sort(key=lambda packet: float(packet.time))
    start = _timestamp(0)
    end = _timestamp(duration)
    labels = ScenarioLabels(
        scenario="benign_baseline",
        attack_family="benign",
        label="benign",
        bssids=tuple(ap.bssid for ap in KNOWN_APS),
        ssids=tuple(ap.ssid for ap in KNOWN_APS),
        clients=LAB_CLIENTS,
        start=start,
        end=end,
        packet_count=len(packets),
        details={
            "duration_seconds": duration,
            "beacon_jitter_ms": BENIGN_BEACON_JITTER_MS,
            "access_points": len(KNOWN_APS),
        },
    )
    return packets, labels


def _evil_twin(seed: int) -> tuple[list[object], ScenarioLabels]:
    rng = random.Random(seed + 2)
    legit = KNOWN_APS[0]
    twin = AccessPoint(TWIN_BSSID, TWIN_SSID, 11, "02deadaa", -25, beacon_interval=70)
    packets: list[object] = []
    start_second = 15.0
    for index in range(12):
        seconds = start_second + index * 0.1
        packets.append(
            _stamp(_build_beacon(legit, 300 + index, legit.beacon_interval, legit.rssi), seconds)
        )
        packets.append(
            _stamp(
                _build_beacon(
                    twin,
                    700 + index,
                    twin.beacon_interval + rng.randint(-1, 1),
                    twin.rssi,
                ),
                seconds + 0.02,
            )
        )
    packets.append(_stamp(_probe_request(LAB_CLIENTS[1], 800, TWIN_SSID), start_second + 2))
    packets.sort(key=lambda packet: float(packet.time))
    labels = ScenarioLabels(
        scenario="evil_twin",
        attack_family="evil_twin_rogue_ap",
        label="suspicious",
        bssids=(legit.bssid, twin.bssid),
        ssids=(legit.ssid,),
        clients=(LAB_CLIENTS[1],),
        start=_timestamp(start_second),
        end=_timestamp(start_second + 4),
        packet_count=len(packets),
        details={
            "legit_bssid": legit.bssid,
            "twin_bssid": twin.bssid,
            "rssi_delta": twin.rssi - legit.rssi,
            "oui_mismatch": True,
            "channel_mismatch": legit.channel != twin.channel,
        },
    )
    return packets, labels


def _deauth_burst(seed: int) -> tuple[list[object], ScenarioLabels]:
    rng = random.Random(seed + 3)
    ap = KNOWN_APS[0]
    packets: list[object] = []
    start_second = 20.0
    for index in range(40):
        seconds = start_second + index * 0.025
        packets.append(
            _stamp(
                _radio(ap.channel, ap.rssi + rng.randint(-2, 2))
                / Dot11(
                    type=0,
                    subtype=12,
                    addr1=DEAUTH_CLIENT if index % 5 else BROADCAST,
                    addr2=ap.bssid,
                    addr3=ap.bssid,
                    SC=(1200 + index) << 4,
                )
                / Dot11Deauth(reason=7 if index % 3 else 1),
                seconds,
            )
        )
    packets.sort(key=lambda packet: float(packet.time))
    labels = ScenarioLabels(
        scenario="deauth_burst",
        attack_family="deauth_disassoc_anomaly",
        label="suspicious",
        bssids=(ap.bssid,),
        ssids=(),
        clients=(DEAUTH_CLIENT, "ff:ff:ff:ff:ff:ff"),
        start=_timestamp(start_second),
        end=_timestamp(start_second + 2),
        packet_count=len(packets),
        details={"broadcast_deauths": 8, "reason_codes": [1, 7]},
    )
    return packets, labels


def _karma(seed: int) -> tuple[list[object], ScenarioLabels]:
    rng = random.Random(seed + 4)
    ap = AccessPoint("02:00:00:00:10:01", "FreeWiFi", 6, "020000", -31)
    clients = LAB_CLIENTS[:2]
    packets: list[object] = []
    start_second = 30.0
    for index, ssid in enumerate(
        ("CoffeeShop", "Airport_Free", "Hotel_Guest", "FreeWiFi", "Mall_WiFi")
    ):
        client = clients[index % len(clients)]
        seconds = start_second + index * 0.2
        packets.append(_stamp(_probe_request(client, 1500 + index, ssid), seconds))
        packets.append(
            _stamp(
                _probe_response(ap, client, 1600 + index, ssid, ap.rssi + rng.randint(-1, 1)),
                seconds + 0.03,
            )
        )
    packets.sort(key=lambda packet: float(packet.time))
    labels = ScenarioLabels(
        scenario="karma_probe_responses",
        attack_family="probe_response_karma",
        label="suspicious",
        bssids=(ap.bssid,),
        ssids=("CoffeeShop", "Airport_Free", "Hotel_Guest", "FreeWiFi", "Mall_WiFi"),
        clients=clients,
        start=_timestamp(start_second),
        end=_timestamp(start_second + 1.5),
        packet_count=len(packets),
        details={"unrelated_ssids": 5, "single_responding_bssid": True},
    )
    return packets, labels


def _beacon_anomaly(seed: int) -> tuple[list[object], ScenarioLabels]:
    rng = random.Random(seed + 5)
    ap = KNOWN_APS[2]
    packets: list[object] = []
    start_second = 40.0
    duplicate_sequence = 2200
    for index in range(14):
        seconds = start_second + index * 0.1
        interval = 100 if index % 3 else rng.choice((20, 250, 500))
        sequence = duplicate_sequence if index % 4 == 0 else 2300 + index
        packets.append(
            _stamp(
                _build_beacon(
                    AccessPoint(
                        ap.bssid, ap.ssid, ap.channel, ap.oui, ap.rssi + rng.randint(-2, 2)
                    ),
                    sequence,
                    interval,
                    ap.rssi,
                ),
                seconds,
            )
        )
    packets.sort(key=lambda packet: float(packet.time))
    labels = ScenarioLabels(
        scenario="beacon_sequence_anomaly",
        attack_family="beacon_management_anomaly",
        label="suspicious",
        bssids=(ap.bssid,),
        ssids=(ap.ssid,),
        clients=(),
        start=_timestamp(start_second),
        end=_timestamp(start_second + 2),
        packet_count=len(packets),
        details={"duplicate_sequence_numbers": 4, "unusual_beacon_intervals": [20, 250, 500]},
    )
    return packets, labels


SCENARIOS = {
    "benign_baseline": _benign,
    "evil_twin": _evil_twin,
    "deauth_burst": _deauth_burst,
    "karma_probe_responses": _karma,
    "beacon_sequence_anomaly": _beacon_anomaly,
}


def generate_dataset(out_dir: str | Path, seed: int = SEED) -> list[GeneratedScenario]:
    """Write all synthetic scenarios and labels under out_dir."""
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    generated: list[GeneratedScenario] = []
    for name, builder in SCENARIOS.items():
        packets, labels = builder(seed)
        path = destination / f"{name}.pcap"
        wrpcap(str(path), packets)
        generated.append(GeneratedScenario(name=name, path=path, labels=labels))
    manifest = {
        "seed": seed,
        "generated_at": "deterministic",
        "scenarios": [item.labels.as_json() for item in generated],
    }
    (destination / "labels.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return generated
