from __future__ import annotations

import re

from app.core.mock_mode import enabled, scenario
from app.core.system_commands import SystemToolError, run_tool, split_nmcli
from app.models import Network, Station
from app.utils.validation import is_mac


class NetworkScanner:
    """Passive inventory source. Hardware capture integrations are isolated from the UI."""

    def scan(self, rescan: bool = False) -> list[Network]:
        if enabled():
            return [Network(**item) for item in scenario()["networks"]]
        output = run_tool(
            [
                "nmcli",
                "--terse",
                "--escape",
                "yes",
                "--colors",
                "no",
                "--fields",
                "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
                "device",
                "wifi",
                "list",
                "--rescan",
                "yes" if rescan else "no",
            ],
            timeout=35,
        )
        records = {}
        for line in output.splitlines():
            if not line.strip():
                continue
            fields = split_nmcli(line)
            try:
                if len(fields) == 5:
                    # Kept for older NetworkManager wrappers and deterministic
                    # fixtures that do not expose FREQ.
                    ssid, bssid, channel, signal, security = fields
                    frequency = None
                else:
                    ssid, bssid, channel, frequency, signal, security = fields
                    match = re.search(r"\d{4,5}", frequency)
                    frequency = int(match.group()) if match else None
                channel, signal = int(channel), int(signal)
                if not is_mac(bssid) or channel < 1 or not 0 <= signal <= 100:
                    raise ValueError("invalid network fields")
            except ValueError as error:
                raise SystemToolError(
                    "NetworkManager devolvió datos de red no válidos."
                ) from error
            item = Network(
                ssid,
                bssid.upper(),
                channel,
                None,
                security or "Abierta",
                signal_percent=signal,
                frequency=frequency,
            )
            previous = records.get(item.bssid)
            if previous is None or signal > previous.signal_percent:
                records[item.bssid] = item
        return sorted(
            records.values(), key=lambda item: (-item.signal_percent, item.ssid)
        )

    def stations(self, bssid: str) -> list[Station]:
        if enabled():
            return [
                Station(**{**item, "bssid": bssid}) for item in scenario()["stations"]
            ]
        return []
