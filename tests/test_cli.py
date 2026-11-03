from __future__ import annotations

import sys
from pathlib import Path

import pytest
from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, wrpcap

from wids_ai.cli import main
from wids_ai.inventory import APInventory


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_cli_help_without_command(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "analyze" in capsys.readouterr().out


def test_cli_analyze_reads_pcap(tmp_path: Path) -> None:
    pcap = tmp_path / "sample.pcap"
    packet = (
        RadioTap(present="Channel+dBm_AntSignal", ChannelFrequency=2437, dBm_AntSignal=-45)
        / Dot11(
            type=0,
            subtype=8,
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="00:11:22:33:44:55",
            addr3="00:11:22:33:44:55",
        )
        / Dot11Beacon(cap=0x0401, beacon_interval=100)
        / Dot11Elt(ID="SSID", info=b"lab")
    )
    wrpcap(str(pcap), [packet])
    assert main(["analyze", str(pcap)]) == 0


@pytest.mark.skipif(sys.platform == "linux", reason="Checks non-Linux guard behavior")
@pytest.mark.parametrize(
    "arguments",
    [
        ["live", "--iface", "wlan0mon"],
        ["baseline", "--live", "--iface", "wlan0mon", "--out", "inventory.json"],
        ["train", "--live", "--iface", "wlan0mon", "--out", "models"],
    ],
)
def test_live_preflight_errors_exit_2_without_traceback(
    arguments: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(arguments) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("error: ")
    assert "requires Linux" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.skipif(sys.platform == "linux", reason="Checks non-Linux guard behavior")
def test_live_debug_keeps_traceback() -> None:
    with pytest.raises(RuntimeError, match="requires Linux"):
        main(["--debug", "live", "--iface", "wlan0mon"])


@pytest.mark.skipif(sys.platform == "linux", reason="Checks non-Linux guard behavior")
def test_live_debug_after_subcommand_keeps_traceback() -> None:
    with pytest.raises(RuntimeError, match="requires Linux"):
        main(["live", "--debug", "--iface", "wlan0mon"])


def test_cli_features_writes_csv(tmp_path: Path) -> None:
    pcap = tmp_path / "sample.pcap"
    packets = []
    for index in range(3):
        packet = (
            RadioTap(
                present="Channel+dBm_AntSignal",
                ChannelFrequency=2437,
                dBm_AntSignal=-45,
            )
            / Dot11(
                type=0,
                subtype=8,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2="00:11:22:33:44:55",
                addr3="00:11:22:33:44:55",
                SC=index << 4,
            )
            / Dot11Beacon(cap=0x0401, beacon_interval=1000)
            / Dot11Elt(ID="SSID", info=b"lab")
        )
        packet.time = 1_735_689_600 + index
        packets.append(packet)
    wrpcap(str(pcap), packets)
    output = tmp_path / "features.csv"
    assert main(["features", str(pcap), "--out", str(output)]) == 0
    text = output.read_text(encoding="utf-8")
    assert "window_start" in text
    assert "distinct_ssids_probed" in text
    assert len(text.splitlines()) > 1


def test_cli_baseline_and_analyze(tmp_path: Path) -> None:
    pcap = tmp_path / "sample.pcap"
    packets = []
    for index in range(3):
        packet = (
            RadioTap(
                present="Channel+dBm_AntSignal",
                ChannelFrequency=2437,
                dBm_AntSignal=-45,
            )
            / Dot11(
                type=0,
                subtype=8,
                addr1="ff:ff:ff:ff:ff:ff",
                addr2="00:11:22:33:44:55",
                addr3="00:11:22:33:44:55",
                SC=index << 4,
            )
            / Dot11Beacon(cap=0x0401, beacon_interval=1000)
            / Dot11Elt(ID="SSID", info=b"lab")
        )
        packet.time = 1_735_689_600 + index
        packets.append(packet)
    wrpcap(str(pcap), packets)
    inventory = tmp_path / "inventory.json"
    output = tmp_path / "detections.json"
    assert main(["baseline", str(pcap), "--out", str(inventory)]) == 0
    assert APInventory.load(inventory).is_known("00:11:22:33:44:55")
    assert (
        main(
            [
                "analyze",
                str(pcap),
                "--inventory",
                str(inventory),
                "--rules",
                str(Path(__file__).resolve().parent.parent / "wids_ai" / "rules" / "rules"),
                "--out",
                str(output),
            ]
        )
        == 0
    )
    assert output.is_file()
    assert output.read_text(encoding="utf-8").strip() == "[]"


def test_live_help_exposes_capture_and_serve_flags(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["live", "--help"])
    assert exc.value.code == 0
    output = capsys.readouterr().out
    for flag in ("--write-pcap", "--db", "--serve", "--hop-channels", "--siem-file"):
        assert flag in output


def test_invalid_config_exits_2_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert (
        main(
            [
                "--config",
                str(tmp_path / "missing.yml"),
                "features",
                "missing.pcap",
                "--out",
                "x.csv",
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.err.startswith("error: ")
    assert "Traceback" not in captured.err


def test_debug_keeps_config_traceback(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        main(
            [
                "--debug",
                "--config",
                str(tmp_path / "missing.yml"),
                "features",
                "missing.pcap",
                "--out",
                "x.csv",
            ]
        )
