from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CaptureStatus(StrEnum):
    READY = "ready"
    RUNNING = "running"
    CAPTURE_INVALID = "capture_invalid"
    CAPTURE_PARTIAL = "capture_partial"
    VALID = "valid"


class RecoveryStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PASSWORD_RECOVERED = "password_recovered"
    SEARCH_SPACE_EXHAUSTED = "search_space_exhausted"
    JOB_INTERRUPTED = "job_interrupted"
    JOB_ERROR = "job_error"
    RECOVERY_CURRENTLY_INFEASIBLE = "recovery_currently_infeasible"


@dataclass(frozen=True, slots=True)
class Network:
    ssid: str
    bssid: str
    channel: int
    rssi: int | None
    security: str
    vendor: str = "Unknown"
    signal_percent: int | None = None
    frequency: int | None = None

    @property
    def band(self) -> str:
        """Return a human-readable radio band for the channel inventory.

        NetworkManager exposes the channel in this inventory, not the center
        frequency.  Channels 1–14 are unambiguously 2.4 GHz; higher channels
        can belong to 5 or 6 GHz depending on the regulatory domain, so we
        label them together instead of guessing a band that was not reported.
        """
        if self.frequency is not None:
            if 2400 <= self.frequency <= 2500:
                return "2.4 GHz"
            if 5000 <= self.frequency < 5925:
                return "5 GHz"
            if 5925 <= self.frequency <= 7125:
                return "6 GHz"
        return "2.4 GHz" if self.channel <= 14 else "5/6 GHz"


@dataclass(frozen=True, slots=True)
class Station:
    mac: str
    bssid: str
    rssi: int
    frames: int
    vendor: str = "Unknown"
