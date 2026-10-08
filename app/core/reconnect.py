from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from app.models.capture_evidence import CaptureEvidence


class ReconnectState(StrEnum):
    IDLE = "idle"
    CAPTURING = "capturing"
    ACTIVE_ATTEMPT = "active_attempt"
    WAITING_AUTH = "waiting_auth"
    WAITING_ASSOC = "waiting_assoc"
    WAITING_EAPOL = "waiting_eapol"
    MATERIAL_DETECTED = "material_detected"
    VALIDATING = "validating"
    DONE = "done"
    TIMEOUT = "timeout"


@dataclass(slots=True)
class DeauthBudgetManager:
    target_station: str
    target_bssid: str
    hard_limit: int = 8
    cooldown_seconds: int = 15
    requested_attempts: int = 0
    actual_frames_observed: int = 0
    actual_frames_acknowledged: int = 0
    start_time: datetime | None = None
    last_frame_time: datetime | None = None

    @property
    def exceeded(self) -> bool:
        return self.actual_frames_observed >= self.hard_limit

    def may_start_attempt(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        if self.exceeded:
            return False
        if self.last_frame_time and now - self.last_frame_time < timedelta(
            seconds=self.cooldown_seconds
        ):
            return False
        return True

    def start_attempt(self, now: datetime | None = None) -> None:
        if not self.may_start_attempt(now):
            raise RuntimeError(
                "Deauthentication budget or cooldown prevents another active attempt"
            )
        self.requested_attempts += 1
        self.start_time = now or datetime.now(UTC)

    def observe_frame(
        self, acknowledged: bool = False, now: datetime | None = None
    ) -> None:
        self.actual_frames_observed += 1
        self.actual_frames_acknowledged += int(acknowledged)
        self.last_frame_time = now or datetime.now(UTC)


class ReconnectStateMachine:
    def __init__(self, observation_seconds: int = 10) -> None:
        self.state = ReconnectState.IDLE
        self.observation_seconds = observation_seconds
        self.material_seen_at: datetime | None = None

    def capture_started(self) -> None:
        self.state = ReconnectState.CAPTURING

    def active_attempt_started(self) -> None:
        if self.state != ReconnectState.CAPTURING:
            raise RuntimeError("Capture must be active before an active attempt")
        self.state = ReconnectState.ACTIVE_ATTEMPT

    def observe(self, event: str, now: datetime | None = None) -> ReconnectState:
        transitions = {
            "auth": ReconnectState.WAITING_ASSOC,
            "assoc": ReconnectState.WAITING_EAPOL,
            "eapol": ReconnectState.WAITING_EAPOL,
        }
        if event in transitions:
            self.state = transitions[event]
        elif event == "material":
            self.state = ReconnectState.MATERIAL_DETECTED
            self.material_seen_at = now or datetime.now(UTC)
        return self.state

    def observation_complete(self, now: datetime | None = None) -> bool:
        if self.state != ReconnectState.MATERIAL_DETECTED or not self.material_seen_at:
            return False
        if (now or datetime.now(UTC)) - self.material_seen_at < timedelta(
            seconds=self.observation_seconds
        ):
            return False
        self.state = ReconnectState.VALIDATING
        return True

    def validate(self, evidence: CaptureEvidence) -> ReconnectState:
        self.state = (
            ReconnectState.DONE
            if evidence.offline_analysis_ready
            else ReconnectState.TIMEOUT
        )
        return self.state
