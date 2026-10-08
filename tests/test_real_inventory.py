import subprocess

import pytest

from app.core import interface_manager, network_scanner, system_commands
from app.core.network_scanner import NetworkScanner
from app.core.system_commands import SystemToolError, run_tool, split_nmcli


def test_nmcli_escaped_fields():
    assert split_nmcli(r"Lab\:Guest\\A:02\:11\:22\:33\:44\:55:6:80:WPA2") == [
        "Lab:Guest\\A",
        "02:11:22:33:44:55",
        "6",
        "80",
        "WPA2",
    ]


def test_real_scan_preserves_units_and_deduplicates(monkeypatch):
    monkeypatch.delenv("WIFI_LAB_MOCK", raising=False)
    commands = []

    def run(args, timeout):
        commands.append(args)
        return "\n".join(
            [
                r"Lab\:Guest:02\:11\:22\:33\:44\:55:6:70:WPA2",
                r"Lab\:Guest:02\:11\:22\:33\:44\:55:6:80:WPA2",
                r":02\:11\:22\:33\:44\:66:36:40:",
            ]
        )

    monkeypatch.setattr(network_scanner, "run_tool", run)
    networks = NetworkScanner().scan()
    assert len(networks) == 2
    assert networks[0].ssid == "Lab:Guest"
    assert networks[0].signal_percent == 80
    assert networks[0].rssi is None
    assert networks[0].band == "2.4 GHz"
    assert networks[1].ssid == ""
    assert networks[1].security == "Abierta"
    assert commands[0][-2:] == ["--rescan", "no"]
    NetworkScanner().scan(rescan=True)
    assert commands[1][-2:] == ["--rescan", "yes"]


def test_real_scan_uses_reported_frequency_for_band_and_channel(monkeypatch):
    monkeypatch.delenv("WIFI_LAB_MOCK", raising=False)
    monkeypatch.setattr(
        network_scanner,
        "run_tool",
        lambda *args, **kwargs: r"Lab:02\:11\:22\:33\:44\:55:1:5955 MHz:88:WPA3",
    )
    network = NetworkScanner().scan()[0]
    assert network.frequency == 5955
    assert network.band == "6 GHz"


def test_network_band_labels_higher_channels_without_guessing_5_or_6_ghz():
    from app.models import Network

    assert Network("five", "02:11:22:33:44:55", 48, None, "WPA2").band == "5/6 GHz"


@pytest.mark.parametrize(
    "output",
    ["invalid", r"Lab:invalid:6:80:WPA2", r"Lab:02\:11\:22\:33\:44\:55:6:101:WPA2"],
)
def test_invalid_scan_is_an_error_not_an_empty_inventory(monkeypatch, output):
    monkeypatch.delenv("WIFI_LAB_MOCK", raising=False)
    monkeypatch.setattr(network_scanner, "run_tool", lambda *args, **kwargs: output)
    with pytest.raises(SystemToolError):
        NetworkScanner().scan()


def test_missing_tool(monkeypatch):
    monkeypatch.setattr(system_commands.shutil, "which", lambda _: None)
    with pytest.raises(SystemToolError, match="Falta la herramienta"):
        run_tool(["nmcli"])


def test_timeout(monkeypatch):
    monkeypatch.setattr(system_commands.shutil, "which", lambda _: "/usr/bin/nmcli")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 2)

    monkeypatch.setattr(system_commands.subprocess, "run", timeout)
    with pytest.raises(SystemToolError, match="no respondió"):
        run_tool(["nmcli"], timeout=2)


def test_tool_error(monkeypatch):
    monkeypatch.setattr(system_commands.shutil, "which", lambda _: "/usr/bin/nmcli")
    monkeypatch.setattr(
        system_commands.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 1, "", "NetworkManager is not running"
        ),
    )
    with pytest.raises(SystemToolError, match="NetworkManager is not running"):
        run_tool(["nmcli"])


def test_real_interfaces_track_phy(monkeypatch):
    monkeypatch.delenv("WIFI_LAB_MOCK", raising=False)
    monkeypatch.setattr(
        interface_manager,
        "run_tool",
        lambda _: "phy#0\n\tInterface lab0\n\t\taddr 02:11:22:33:44:55\n\t\ttype managed\nphy#1\n\tInterface lab1\n\t\ttype monitor\n",
    )
    interfaces = interface_manager.InterfaceManager().list_interfaces()
    assert [(item.name, item.phy, item.mode) for item in interfaces] == [
        ("lab0", "phy0", "managed"),
        ("lab1", "phy1", "monitor"),
    ]
