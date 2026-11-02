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
LAB_CLIENTS = ("aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "aa:bb:cc:00:00:03")
TWIN_BSSID = "02:de:ad:be:ef:01"
TWIN_SSID = "LabNet"
DEAUTH_BSSID = "02:de:ad:de:01:01"
DEAUTH_CLIENT = "de:ad:cc:00:00:01"
KARMA_BSSID = "02:00:00:00:10:01"
KARMA_CLIENTS = ("de:ad:cc:00:00:11", "de:ad:cc:00:00:12")
BEACON_ATTACK_BSSID = "02:be:ac:00:01:01"
BEACON_ATTACK_SSID = "LabBeaconAnomaly"


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
    template = BEACON_TEMPLATES.get(key)
    if template is None:
        template = (
            _radio(ap.channel, rssi)
            / Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=ap.bssid, addr3=ap.bssid, SC=0)
            / Dot11Beacon(cap=0x0411 if ap.privacy else 0x0401, beacon_interval=interval)
            / _ssid(ap.ssid)
        )
        BEACON_TEMPLATES[key] = template
    packet = template.copy()
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
        / Dot11ProbeResp(cap=0x0411 if ap.privacy else 0x0401, beacon_interval=ap.beacon_interval)
        / _ssid(ssid)
    )


def _stamp(packet: object, seconds: float) -> object:
    packet.time = BASE_TIME + seconds
    return packet


def _benign(seed: int) -> tuple[list[object], ScenarioLabels]:
    rng = random.Random(seed + 1)
    packets: list[object] = []
    sequences = {ap.bssid: 0 for ap in KNOWN_APS}
    next_beacon = {ap.bssid: rng.uniform(0, 0.5) for ap in KNOWN_APS}
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
    labels = ScenarioLabels(
        scenario="benign_baseline",
        attack_family="benign",
        label="benign",
        bssids=tuple(ap.bssid for ap in KNOWN_APS),
        ssids=tuple(ap.ssid for ap in KNOWN_APS),
        clients=LAB_CLIENTS,
        start=_timestamp(0),
        end=_timestamp(duration),
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
    twin = AccessPoint(TWIN_BSSID, TWIN_SSID, 11, "02deadaa", -25, beacon_interval=70)
    packets: list[object] = []
    start_second = 15.0
    for index in range(12):
        seconds = start_second + index * 0.1
        packets.append(
            _stamp(
                _build_beacon(
                    twin, 700 + index, twin.beacon_interval + rng.randint(-1, 1), twin.rssi
                ),
                seconds,
            )
        )
    packets.append(_stamp(_probe_request(DEAUTH_CLIENT, 800, TWIN_SSID), start_second + 2))
    packets.sort(key=lambda packet: float(packet.time))
    labels = ScenarioLabels(
        scenario="evil_twin",
        attack_family="evil_twin_rogue_ap",
        label="suspicious",
        bssids=(twin.bssid,),
        ssids=(twin.ssid,),
        clients=(DEAUTH_CLIENT,),
        start=_timestamp(start_second),
        end=_timestamp(start_second + 4),
        packet_count=len(packets),
        details={
            "legit_bssid": KNOWN_APS[0].bssid,
            "twin_bssid": twin.bssid,
            "rssi_delta": twin.rssi - KNOWN_APS[0].rssi,
            "oui_mismatch": True,
            "channel_mismatch": KNOWN_APS[0].channel != twin.channel,
        },
    )
    return packets, labels


def _deauth_burst(seed: int) -> tuple[list[object], ScenarioLabels]:
    rng = random.Random(seed + 3)
    packets: list[object] = []
    start_second = 20.0
    for index in range(40):
        packets.append(
            _stamp(
                _radio(6, -43 + rng.randint(-2, 2))
                / Dot11(
                    type=0,
                    subtype=12,
                    addr1=DEAUTH_CLIENT if index % 5 else BROADCAST,
                    addr2=DEAUTH_BSSID,
                    addr3=DEAUTH_BSSID,
                    SC=(1200 + index) << 4,
                )
                / Dot11Deauth(reason=7 if index % 3 else 1),
                start_second + index * 0.025,
            )
        )
    packets.sort(key=lambda packet: float(packet.time))
    labels = ScenarioLabels(
        scenario="deauth_burst",
        attack_family="deauth_disassoc_anomaly",
        label="suspicious",
        bssids=(DEAUTH_BSSID,),
        ssids=(),
        clients=(DEAUTH_CLIENT, BROADCAST),
        start=_timestamp(start_second),
        end=_timestamp(start_second + 2),
        packet_count=len(packets),
        details={"broadcast_deauths": 8, "reason_codes": [1, 7]},
    )
    return packets, labels


def _karma(seed: int) -> tuple[list[object], ScenarioLabels]:
    rng = random.Random(seed + 4)
    ap = AccessPoint(KARMA_BSSID, "FreeWiFi", 6, "020000", -31)
    packets: list[object] = []
    start_second = 30.0
    for index, ssid in enumerate(
        ("CoffeeShop", "Airport_Free", "Hotel_Guest", "FreeWiFi", "Mall_WiFi")
    ):
        client = KARMA_CLIENTS[index % len(KARMA_CLIENTS)]
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
        clients=KARMA_CLIENTS,
        start=_timestamp(start_second),
        end=_timestamp(start_second + 1.5),
        packet_count=len(packets),
        details={"unrelated_ssids": 5, "single_responding_bssid": True},
    )
    return packets, labels


def _beacon_anomaly(seed: int) -> tuple[list[object], ScenarioLabels]:
    rng = random.Random(seed + 5)
    ap = AccessPoint(BEACON_ATTACK_BSSID, BEACON_ATTACK_SSID, 11, "02beac", -50)
    packets: list[object] = []
    start_second = 40.0
    for index in range(14):
        interval = 100 if index % 3 else rng.choice((20, 250, 500))
        sequence = 2200 if index % 4 == 0 else 2300 + index
        packets.append(
            _stamp(
                _build_beacon(ap, sequence, interval, ap.rssi + rng.randint(-2, 2)),
                start_second + index * 0.1,
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
MIXED_ATTACKS = {
    "mixed_evil_twin": "evil_twin",
    "mixed_deauth_burst": "deauth_burst",
    "mixed_karma_probe_responses": "karma_probe_responses",
    "mixed_beacon_sequence_anomaly": "beacon_sequence_anomaly",
}
MIXED_ATTACK_START_SECONDS = 300.0


def _shift_packet(packet: object, seconds: float) -> object:
    shifted = packet.copy()
    shifted.time = float(shifted.time) + seconds
    return shifted


def _mixed_labels(
    scenario: str, benign: ScenarioLabels, attack: ScenarioLabels, shift: float, packet_count: int
) -> ScenarioLabels:
    if attack.start is None or attack.end is None:
        raise ValueError("Attack labels need start and end timestamps")
    shifted_start = datetime.fromtimestamp(attack.start.timestamp() + shift, tz=UTC)
    shifted_end = datetime.fromtimestamp(attack.end.timestamp() + shift, tz=UTC)
    details = dict(attack.details)
    details.update(
        {
            "mixed": True,
            "background": "benign_baseline",
            "attack_offset_seconds": shift,
            "attack_label": attack.scenario,
            "attack_start": shifted_start.isoformat(),
            "attack_end": shifted_end.isoformat(),
        }
    )
    return ScenarioLabels(
        scenario=scenario,
        attack_family=attack.attack_family,
        label="suspicious",
        bssids=tuple(dict.fromkeys((*benign.bssids, *attack.bssids))),
        ssids=tuple(dict.fromkeys((*benign.ssids, *attack.ssids))),
        clients=tuple(dict.fromkeys((*benign.clients, *attack.clients))),
        start=benign.start,
        end=max(benign.end, shifted_end) if benign.end else shifted_end,
        packet_count=packet_count,
        details=details,
    )


def generate_dataset(out_dir: str | Path, seed: int = SEED) -> list[GeneratedScenario]:
    """Write isolated and mixed scenarios plus labels under out_dir."""
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    generated: list[GeneratedScenario] = []
    scenario_packets: dict[str, list[object]] = {}
    scenario_labels: dict[str, ScenarioLabels] = {}
    for name, builder in SCENARIOS.items():
        packets, labels = builder(seed)
        scenario_packets[name] = packets
        scenario_labels[name] = labels
        path = destination / f"{name}.pcap"
        wrpcap(str(path), packets)
        generated.append(GeneratedScenario(name=name, path=path, labels=labels))
    benign_packets = scenario_packets["benign_baseline"]
    benign_labels = scenario_labels["benign_baseline"]
    for mixed_name, attack_name in MIXED_ATTACKS.items():
        shifted_attack = [
            _shift_packet(packet, MIXED_ATTACK_START_SECONDS)
            for packet in scenario_packets[attack_name]
        ]
        packets = sorted([*benign_packets, *shifted_attack], key=lambda packet: float(packet.time))
        labels = _mixed_labels(
            mixed_name,
            benign_labels,
            scenario_labels[attack_name],
            MIXED_ATTACK_START_SECONDS,
            len(packets),
        )
        path = destination / f"{mixed_name}.pcap"
        wrpcap(str(path), packets)
        generated.append(GeneratedScenario(name=mixed_name, path=path, labels=labels))
    manifest = {
        "seed": seed,
        "generated_at": "deterministic",
        "scenarios": [item.labels.as_json() for item in generated],
    }
    (destination / "labels.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return generated
