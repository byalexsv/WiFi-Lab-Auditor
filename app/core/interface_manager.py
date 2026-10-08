from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.core.mock_mode import enabled, scenario
from app.core.system_commands import run_tool


@dataclass(frozen=True, slots=True)
class WirelessInterface:
    name: str
    phy: str = "unknown"
    driver: str = "unknown"
    mac: str = "unknown"
    mode: str = "managed"


class InterfaceManager:
    def list_interfaces(self) -> list[WirelessInterface]:
        if enabled():
            return [WirelessInterface(**item) for item in scenario()["interfaces"]]
        output = run_tool(["iw", "dev"])
        interfaces: list[WirelessInterface] = []
        current: dict[str, str] = {}
        phy = "unknown"
        for line in output.splitlines():
            bits = line.strip().split()
            if len(bits) == 1 and bits[0].startswith("phy#"):
                if current:
                    interfaces.append(WirelessInterface(**current))
                    current = {}
                phy = bits[0].replace("#", "")
            elif line.strip() == "Unnamed/non-netdev interface":
                if current:
                    interfaces.append(WirelessInterface(**current))
                    current = {}
            elif len(bits) == 2 and bits[0] == "Interface":
                if current:
                    interfaces.append(WirelessInterface(**current))
                driver = Path("/sys/class/net") / bits[1] / "device/driver"
                current = {
                    "name": bits[1],
                    "phy": phy,
                    "driver": driver.resolve().name if driver.exists() else "unknown",
                }
            elif len(bits) == 2 and bits[0] == "addr" and current:
                current["mac"] = bits[1]
            elif len(bits) == 2 and bits[0] == "type" and current:
                current["mode"] = bits[1]
        if current:
            interfaces.append(WirelessInterface(**current))
        return interfaces
