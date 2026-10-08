from __future__ import annotations

import platform
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.core.system_commands import SystemToolError, run_tool

REQUIRED_TOOLS = (
    "nmcli",
    "iw",
    "airmon-ng",
    "aireplay-ng",
    "dumpcap",
    "tshark",
    "hcxpcapngtool",
    "hashcat",
    "pkexec",
)

OPTIONAL_CAPTURE_TOOLS = ("hcxdumptool",)


@dataclass(frozen=True)
class SystemHealth:
    """Actionable readiness state for the local capture and analysis backend."""

    online: bool
    message: str
    details: str


def system_health() -> SystemHealth:
    """Check the real host tools used by the production workflow."""
    checks: list[str] = []
    missing = [tool for tool in REQUIRED_TOOLS if shutil.which(tool) is None]
    if missing:
        checks.append("Faltan herramientas: " + ", ".join(missing))

    if "nmcli" not in missing:
        try:
            network = run_tool(["nmcli", "--terse", "general", "status"], timeout=5)
            checks.append(
                "NetworkManager responde"
                + (f": {network.strip()}" if network.strip() else ".")
            )
        except SystemToolError as error:
            checks.append(f"NetworkManager no responde: {error}")

    if "dumpcap" not in missing:
        try:
            interfaces = run_tool(["dumpcap", "-D"], timeout=5)
            if interfaces.strip():
                checks.append("dumpcap puede enumerar interfaces de captura.")
            else:
                checks.append("dumpcap no devolvió interfaces de captura.")
        except SystemToolError as error:
            checks.append(f"dumpcap no está listo: {error}")

    unavailable = any(
        text.startswith(prefix)
        for text in checks
        for prefix in (
            "Faltan herramientas:",
            "NetworkManager no responde:",
            "dumpcap no devolvió",
            "dumpcap no está listo:",
        )
    )
    online = not unavailable
    if online:
        message = "El backend local está listo para capturar y analizar."
    elif missing:
        message = "El backend local está incompleto. Instala las herramientas indicadas en Diagnóstico."
    else:
        message = "El backend local no está listo. Revisa Diagnóstico y los permisos de captura."
    return SystemHealth(online=online, message=message, details="\n".join(checks))


def system_status() -> str:
    details = [
        f"Sistema: {platform.system()} {platform.release()}",
        f"Python: {platform.python_version()}",
        "",
    ]
    for tool in (
        "nmcli",
        "iw",
        "airmon-ng",
        "aireplay-ng",
        "dumpcap",
        "tshark",
        "hcxpcapngtool",
        "hashcat",
        "pkexec",
        "hcxdumptool",
    ):
        details.append(f"{tool}: {shutil.which(tool) or 'No instalado'}")
    for label, command in (
        ("NetworkManager", ["nmcli", "--terse", "general", "status"]),
        ("Radio Wi-Fi", ["nmcli", "radio", "wifi"]),
        ("Dispositivos", ["nmcli", "--terse", "device", "status"]),
        ("Interfaces de captura y permisos", ["dumpcap", "-D"]),
    ):
        try:
            result = run_tool(command, timeout=5).strip()
        except SystemToolError as error:
            result = str(error)
        details.extend(["", f"{label}:", result or "Sin datos"])
    return "\n".join(details)


REDACTIONS = [
    (re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"), "[MAC-REDACTED]"),
    (re.compile(r"/home/[^/\s]+"), "/home/[USER]"),
    (re.compile(r"(?i)(password|token|secret)\s*[:=]\s*\S+"), r"\1=[REDACTED]"),
]


def redact(value: str) -> str:
    for pattern, replacement in REDACTIONS:
        value = pattern.sub(replacement, value)
    return value


def create_diagnostic_bundle(destination: Path) -> Path:
    """Write only sanitized environment facts; packet captures are never included."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    details = [
        f"created={datetime.now(UTC).isoformat()}",
        f"system={platform.platform()}",
        f"kernel={platform.release()}",
    ]
    for tool in ("iw", "aireplay-ng", "hashcat", "tshark", "hcxpcapngtool"):
        path = shutil.which(tool)
        details.append(f"{tool}={path or 'missing'}")
        if path:
            output = subprocess.run(
                [tool, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            ).stdout[:500]
            details.append(redact(output))
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("diagnostics.txt", redact("\n".join(details)))
    return destination
