"""Typed 802.11 management and control frame model."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

FrameType = Literal["management", "control", "data", "extension", "unknown"]
FrameSubtype = Literal[
    "association_request",
    "association_response",
    "reassociation_request",
    "reassociation_response",
    "probe_request",
    "probe_response",
    "beacon",
    "atim",
    "disassociation",
    "authentication",
    "deauthentication",
    "action",
    "action_no_ack",
    "trigger",
    "block_ack_request",
    "block_ack",
    "ps_poll",
    "rts",
    "cts",
    "ack",
    "cf_end",
    "cf_end_ack",
    "data",
    "null",
    "qos_data",
    "unknown",
]
SecurityMode = Literal["open", "wep", "wpa", "wpa2", "wpa3", "wpa2_wpa3", "unknown"]


class RSNInfo(BaseModel):
    """Security information advertised by a management frame."""

    model_config = ConfigDict(frozen=True)

    present: bool = False
    version: int | None = None
    group_cipher: str | None = None
    pairwise_ciphers: tuple[str, ...] = ()
    akm_suites: tuple[str, ...] = ()
    mfp_capable: bool = False
    mfp_required: bool = False
    wpa_present: bool = False


class Frame(BaseModel):
    """Normalized frame record shared by detection components."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    frame_type: FrameType
    subtype: FrameSubtype
    type_code: int
    subtype_code: int
    addr1: str | None = None
    addr2: str | None = None
    addr3: str | None = None
    ssid: str | None = None
    bssid: str | None = None
    channel: int | None = None
    rssi: int | None = None
    seq_num: int | None = None
    fragment_num: int | None = None
    beacon_interval: int | None = None
    capabilities: int | None = None
    rsn: RSNInfo = Field(default_factory=RSNInfo)
    security: SecurityMode = "unknown"
    vendor_oui: str | None = None
    reason_code: int | None = None
    body_length: int = 0

    @property
    def is_management(self) -> bool:
        return self.frame_type == "management"

    @property
    def is_control(self) -> bool:
        return self.frame_type == "control"

    @property
    def transmitter(self) -> str | None:
        return self.addr2

    @property
    def receiver(self) -> str | None:
        return self.addr1

    @property
    def is_broadcast(self) -> bool:
        return self.addr1 == "ff:ff:ff:ff:ff:ff"

    @property
    def is_multicast(self) -> bool:
        if not self.addr1:
            return False
        first_octet = int(self.addr1.split(":", maxsplit=1)[0], 16)
        return bool(first_octet & 0x01)


FRAME_TYPE_NAMES: dict[int, FrameType] = {
    0: "management",
    1: "control",
    2: "data",
    3: "extension",
}

MANAGEMENT_SUBTYPES: dict[int, FrameSubtype] = {
    0: "association_request",
    1: "association_response",
    2: "reassociation_request",
    3: "reassociation_response",
    4: "probe_request",
    5: "probe_response",
    8: "beacon",
    9: "atim",
    10: "disassociation",
    11: "authentication",
    12: "deauthentication",
    13: "action",
    14: "action_no_ack",
}

CONTROL_SUBTYPES: dict[int, FrameSubtype] = {
    2: "trigger",
    8: "block_ack_request",
    9: "block_ack",
    10: "ps_poll",
    11: "rts",
    12: "cts",
    13: "ack",
    14: "cf_end",
    15: "cf_end_ack",
}

DATA_SUBTYPES: dict[int, FrameSubtype] = {
    0: "data",
    4: "null",
    8: "qos_data",
}
