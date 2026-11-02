from __future__ import annotations

from datetime import UTC, datetime

from scapy.all import (
    AKMSuite,
    Dot11,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Elt,
    Dot11EltRSN,
    Dot11ProbeResp,
    RadioTap,
    RSNCipherSuite,
)
from scapy.packet import Raw

from wids_ai.parser.dot11 import parse_frame

CHANNEL = 6
RSSI = -41


def _radio() -> RadioTap:
    return RadioTap(
        present="Channel+dBm_AntSignal",
        ChannelFrequency=2437,
        ChannelFlags=0x00A0,
        dBm_AntSignal=RSSI,
    )


def _beacon(subtype: int = 8, *, bssid: str = "00:11:22:33:44:55", ssid: str = "lab") -> object:
    type_code = 0
    dot11 = Dot11(
        type=type_code,
        subtype=subtype,
        addr1="ff:ff:ff:ff:ff:ff",
        addr2=bssid,
        addr3=bssid,
        SC=0x1234,
    )
    if subtype == 8:
        body = Dot11Beacon(cap=0x0411, beacon_interval=100)
    else:
        body = Dot11ProbeResp(cap=0x0411, beacon_interval=100)
    return _radio() / dot11 / body / Dot11Elt(ID="SSID", info=ssid.encode())


def test_beacon_fields_and_radiotap() -> None:
    packet = _beacon()
    packet.time = 1_700_000_000
    frame = parse_frame(packet)
    assert frame is not None
    assert frame.frame_type == "management"
    assert frame.subtype == "beacon"
    assert frame.addr1 == "ff:ff:ff:ff:ff:ff"
    assert frame.addr2 == "00:11:22:33:44:55"
    assert frame.bssid == "00:11:22:33:44:55"
    assert frame.ssid == "lab"
    assert frame.channel == CHANNEL
    assert frame.rssi == RSSI
    assert frame.seq_num == 0x123
    assert frame.fragment_num == 4
    assert frame.beacon_interval == 100
    assert frame.capabilities == 0x0411
    assert frame.timestamp == datetime.fromtimestamp(1_700_000_000, tz=UTC)


def test_captured_at_overrides_packet_time() -> None:
    packet = _beacon()
    captured = datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)
    frame = parse_frame(packet, captured_at=captured)
    assert frame is not None
    assert frame.timestamp == captured


def test_rsn_security_is_parsed() -> None:
    packet = (
        _radio()
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="00:11:22:33:44:55",
            addr3="00:11:22:33:44:55",
        )
        / Dot11Beacon(cap=0x0411, beacon_interval=100)
        / Dot11Elt(ID="SSID", info=b"lab")
        / Dot11EltRSN(
            version=1,
            group_cipher_suite=RSNCipherSuite(cipher=4),
            nb_pairwise_cipher_suites=1,
            pairwise_cipher_suites=[RSNCipherSuite(cipher=4)],
            nb_akm_suites=1,
            akm_suites=[AKMSuite(suite=2)],
            mfp_required=1,
        )
    )
    frame = parse_frame(packet)
    assert frame is not None
    assert frame.rsn.present is True
    assert frame.rsn.group_cipher == "CCMP"
    assert frame.rsn.pairwise_ciphers == ("CCMP",)
    assert frame.rsn.akm_suites == ("PSK",)
    assert frame.rsn.mfp_required is True
    assert frame.security == "wpa2"


def test_open_network_has_no_rsn() -> None:
    packet = _beacon()
    packet[Dot11Beacon].cap = 0x0401
    frame = parse_frame(packet)
    assert frame is not None
    assert frame.rsn.present is False
    assert frame.security == "open"


def test_deauth_reason_code_and_broadcast() -> None:
    bssid = "00:11:22:33:44:55"
    packet = (
        _radio()
        / Dot11(
            type=0,
            subtype=12,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2=bssid,
            addr3=bssid,
        )
        / Dot11Deauth(reason=7)
    )
    frame = parse_frame(packet)
    assert frame is not None
    assert frame.subtype == "deauthentication"
    assert frame.reason_code == 7
    assert frame.is_broadcast is True
    assert frame.is_multicast is True
    assert frame.bssid == bssid


def test_control_frame_does_not_require_body() -> None:
    packet = _radio() / Dot11(type=1, subtype=13, addr1="00:11:22:33:44:55")
    frame = parse_frame(packet)
    assert frame is not None
    assert frame.frame_type == "control"
    assert frame.subtype == "ack"
    assert frame.is_control is True


def test_non_dot11_packet_is_ignored() -> None:
    packet = _radio() / Raw(b"not an 802.11 frame")
    assert parse_frame(packet) is None


def test_malformed_dot11_is_ignored() -> None:
    packet = _radio() / Dot11(type=0, subtype=8, addr1=None, addr2=None, addr3=None)
    assert parse_frame(packet) is None
