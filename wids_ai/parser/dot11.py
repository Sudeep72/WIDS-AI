"""Defensive parser for 802.11 management and control frames."""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime
from typing import Any

from scapy.layers.dot11 import (
    Dot11,
    Dot11AssoReq,
    Dot11AssoResp,
    Dot11Beacon,
    Dot11Deauth,
    Dot11Disas,
    Dot11Elt,
    Dot11EltMicrosoftWPA,
    Dot11EltRSN,
    Dot11EltVendorSpecific,
    Dot11ProbeResp,
    Dot11ReassoReq,
    Dot11ReassoResp,
    RadioTap,
)
from scapy.packet import Packet

from wids_ai.parser.models import (
    CONTROL_SUBTYPES,
    DATA_SUBTYPES,
    FRAME_TYPE_NAMES,
    MANAGEMENT_SUBTYPES,
    Frame,
    FrameSubtype,
    RSNInfo,
    SecurityMode,
)

LOGGER = logging.getLogger(__name__)
MAC_PATTERN = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")

CIPHER_NAMES = {
    0x000FAC00: "Use group cipher",
    0x000FAC01: "WEP-40",
    0x000FAC02: "TKIP",
    0x000FAC04: "CCMP",
    0x000FAC05: "WEP-104",
    0x000FAC08: "GCMP",
    0x000FAC09: "GCMP-256",
    0x000FAC0A: "CCMP-256",
}
AKM_NAMES = {
    0x000FAC01: "802.1X",
    0x000FAC02: "PSK",
    0x000FAC03: "FT-802.1X",
    0x000FAC04: "FT-PSK",
    0x000FAC05: "802.1X-SHA256",
    0x000FAC06: "PSK-SHA256",
    0x000FAC08: "SAE",
    0x000FAC09: "FT-SAE",
    0x000FAC0B: "Suite-B-192",
    0x000FAC0C: "OWE",
}


def _normalize_mac(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).lower()
    return text if MAC_PATTERN.fullmatch(text) else None


def _oui(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        raw = value.hex()
    else:
        raw = str(value).replace(":", "").replace("-", "").lower()
    return raw if len(raw) == 6 else None


def _element_info(element: Dot11Elt) -> bytes:
    value = element.info
    if isinstance(value, str):
        return value.encode("utf-8", errors="replace")
    return bytes(value or b"")


def _cipher_name(value: Any) -> str | None:
    if value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value)
    return CIPHER_NAMES.get(number, f"0x{number:08x}")


def _akm_name(value: Any) -> str | None:
    if value is None:
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value)
    return AKM_NAMES.get(number, f"0x{number:08x}")


def _suite_ois(packet: Packet) -> list[int]:
    oui = getattr(packet, "oui", None)
    suite = getattr(packet, "suite", getattr(packet, "cipher", None))
    if oui is None or suite is None:
        return []
    try:
        return [(int(oui) << 8) | int(suite)]
    except (TypeError, ValueError):
        return []


def _rsn_info(packet: Packet) -> RSNInfo:
    rsn = packet.getlayer(Dot11EltRSN)
    wpa = packet.getlayer(Dot11EltMicrosoftWPA)
    if rsn is None and wpa is None:
        return RSNInfo()

    source = rsn if rsn is not None else wpa
    assert source is not None
    group_cipher = getattr(source, "group_cipher_suite", None)
    group_value = _suite_ois(group_cipher) if group_cipher is not None else []
    pairwise: list[str] = []
    for suite in getattr(source, "pairwise_cipher_suites", []) or []:
        for value in _suite_ois(suite):
            name = _cipher_name(value)
            if name:
                pairwise.append(name)
    akms: list[str] = []
    for suite in getattr(source, "akm_suites", []) or []:
        for value in _suite_ois(suite):
            name = _akm_name(value)
            if name:
                akms.append(name)

    return RSNInfo(
        present=True,
        version=getattr(source, "version", None),
        group_cipher=_cipher_name(group_value[0]) if group_value else None,
        pairwise_ciphers=tuple(pairwise),
        akm_suites=tuple(akms),
        mfp_capable=bool(getattr(source, "mfp_capable", False)),
        mfp_required=bool(getattr(source, "mfp_required", False)),
        wpa_present=wpa is not None,
    )


def _security_mode(packet: Packet, privacy: bool, rsn: RSNInfo) -> SecurityMode:
    if not privacy:
        return "wpa3" if rsn.akm_suites and set(rsn.akm_suites) <= {"OWE", "SAE"} else "open"
    if rsn.present:
        akm = set(rsn.akm_suites)
        if {"SAE"} <= akm and ({"PSK"} & akm or {"802.1X"} & akm):
            return "wpa2_wpa3"
        if "SAE" in akm:
            return "wpa3"
        if rsn.wpa_present:
            return "wpa"
        return "wpa2"
    if packet.haslayer(Dot11EltMicrosoftWPA):
        return "wpa"
    vendor = packet.getlayer(Dot11EltVendorSpecific)
    if vendor is not None and _oui(getattr(vendor, "oui", None)) is not None:
        return "wep"
    return "wep" if privacy else "open"


def _ssid(packet: Packet) -> str | None:
    for element in packet.layers():
        if not issubclass(element, Dot11Elt) or element in {Dot11EltRSN, Dot11EltVendorSpecific}:
            continue
        for layer in packet.getlayer(element, nb=1) or []:
            if getattr(layer, "ID", None) != 0:
                continue
            info = _element_info(layer)
            if not info:
                return None
            try:
                return info.decode("utf-8")
            except UnicodeDecodeError:
                return info.decode("utf-8", errors="replace")
    return None


def _vendor_oui(packet: Packet) -> str | None:
    element = packet.getlayer(Dot11EltVendorSpecific)
    if element is None:
        return None
    return _oui(getattr(element, "oui", None))


def _radio_metadata(packet: Packet) -> tuple[int | None, int | None]:
    radio = packet.getlayer(RadioTap)
    if radio is None:
        return None, None
    frequency = getattr(radio, "ChannelFrequency", None)
    channel = None
    if isinstance(frequency, int) and frequency > 0:
        if 2412 <= frequency <= 2484:
            channel = 14 if frequency == 2484 else (frequency - 2407) // 5
        elif 5000 <= frequency <= 5900:
            channel = (frequency - 5000) // 5
        elif 5955 <= frequency <= 7115:
            channel = (frequency - 5950) // 5
    signal = getattr(radio, "dBm_AntSignal", None)
    return channel, int(signal) if isinstance(signal, (int, float)) else None


def _timestamp(packet: Packet, captured_at: datetime | None) -> datetime:
    if captured_at is not None:
        return captured_at if captured_at.tzinfo else captured_at.replace(tzinfo=UTC)
    packet_time = getattr(packet, "time", None)
    if packet_time is not None:
        try:
            return datetime.fromtimestamp(float(packet_time), tz=UTC)
        except (TypeError, ValueError, OverflowError, OSError):
            pass
    return datetime.now(tz=UTC)


def _subtype(frame_type: int, subtype: int) -> tuple[str, int, int]:
    type_code = frame_type & 0x03
    subtype_code = subtype & 0x0F
    if type_code in FRAME_TYPE_NAMES:
        return FRAME_TYPE_NAMES[type_code], type_code, subtype_code
    return "unknown", type_code, subtype_code


def _subtype_name(frame_type: str, subtype_code: int) -> FrameSubtype:
    if frame_type == "management":
        return MANAGEMENT_SUBTYPES.get(subtype_code, "unknown")
    if frame_type == "control":
        return CONTROL_SUBTYPES.get(subtype_code, "unknown")
    if frame_type == "data":
        return DATA_SUBTYPES.get(subtype_code, "unknown")
    return "unknown"


def _reason_code(packet: Packet) -> int | None:
    for layer in (Dot11Deauth, Dot11Disas):
        value = packet.getlayer(layer)
        if value is not None:
            reason = getattr(value, "reason", None)
            return int(reason) if isinstance(reason, int) else None
    return None


def _beacon_interval(packet: Packet) -> int | None:
    for layer in (Dot11Beacon, Dot11ProbeResp):
        value = packet.getlayer(layer)
        if value is not None:
            interval = getattr(value, "beacon_interval", None)
            return int(interval) if isinstance(interval, int) else None
    return None


def _capabilities(packet: Packet) -> int | None:
    for layer in (
        Dot11Beacon,
        Dot11ProbeResp,
        Dot11AssoReq,
        Dot11AssoResp,
        Dot11ReassoReq,
        Dot11ReassoResp,
    ):
        value = packet.getlayer(layer)
        if value is not None:
            cap = getattr(value, "cap", None)
            if cap is not None:
                return int(cap)
    return None


def parse_frame(packet: Packet, captured_at: datetime | None = None) -> Frame | None:
    """Parse one Scapy packet. Return None when it is not an 802.11 frame."""
    dot11 = packet.getlayer(Dot11)
    if dot11 is None:
        return None
    try:
        frame_type, _, subtype_code = _subtype(int(dot11.type), int(dot11.subtype))
        subtype = _subtype_name(frame_type, subtype_code)
        channel, rssi = _radio_metadata(packet)
        rsn = _rsn_info(packet)
        cap = _capabilities(packet)
        privacy = bool(cap is not None and cap & 0x0010)
        addr1 = _normalize_mac(getattr(dot11, "addr1", None))
        addr2 = _normalize_mac(getattr(dot11, "addr2", None))
        addr3 = _normalize_mac(getattr(dot11, "addr3", None))
        if frame_type in {"management", "control"} and addr1 is None and addr2 is None:
            return None
        ssid = _ssid(packet) if frame_type in {"management", "data"} else None
        bssid = addr3
        if (
            bssid is None
            and frame_type == "management"
            and subtype
            in {
                "probe_response",
                "beacon",
                "association_response",
            }
        ):
            bssid = addr2
        return Frame(
            timestamp=_timestamp(packet, captured_at),
            frame_type=frame_type,  # type: ignore[arg-type]
            subtype=subtype,
            type_code=int(dot11.type),
            subtype_code=subtype_code,
            addr1=addr1,
            addr2=addr2,
            addr3=addr3,
            ssid=ssid,
            bssid=bssid,
            channel=channel,
            rssi=rssi,
            seq_num=int(dot11.SC >> 4) if getattr(dot11, "SC", None) is not None else None,
            fragment_num=int(dot11.SC & 0x0F) if getattr(dot11, "SC", None) is not None else None,
            beacon_interval=_beacon_interval(packet),
            capabilities=cap,
            rsn=rsn,
            security=_security_mode(packet, privacy, rsn),
            vendor_oui=_vendor_oui(packet),
            reason_code=_reason_code(packet),
            body_length=len(bytes(dot11.payload)) if dot11.payload else 0,
        )
    except (AttributeError, TypeError, ValueError, IndexError) as exc:
        LOGGER.debug("Skipping malformed 802.11 packet: %s", exc)
        return None
