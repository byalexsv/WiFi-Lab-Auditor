from __future__ import annotations

from enum import StrEnum


class ThermalState(StrEnum):
    NORMAL = "normal"
    WARM = "warm"
    HOT = "hot"
    THROTTLE_RISK = "throttle_risk"
    ABORT = "abort"


class ThermalGuard:
    def __init__(
        self, warning_c: int = 78, high_c: int = 82, abort_c: int = 88
    ) -> None:
        if not warning_c < high_c < abort_c:
            raise ValueError("Thermal thresholds must increase")
        self.warning_c, self.high_c, self.abort_c = warning_c, high_c, abort_c

    def state_for(self, temperature_c: int) -> ThermalState:
        if temperature_c >= self.abort_c:
            return ThermalState.ABORT
        if temperature_c >= self.high_c:
            return ThermalState.THROTTLE_RISK
        if temperature_c >= self.warning_c:
            return ThermalState.HOT
        if temperature_c >= self.warning_c - 5:
            return ThermalState.WARM
        return ThermalState.NORMAL
