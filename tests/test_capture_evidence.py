import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.core.reconnect import (
    DeauthBudgetManager,
    ReconnectState,
    ReconnectStateMachine,
)
from app.models.capture_evidence import CaptureEvidence, MaterialStatus, score_evidence


def _evidence() -> CaptureEvidence:
    payload = json.loads(
        (Path(__file__).parents[1] / "fixtures/excessive_deauth_case.json").read_text()
    )
    return CaptureEvidence(
        **{
            key: value
            for key, value in payload.items()
            if key not in {"ssid", "bssid", "station", "channel"}
        }
    )


def test_excessive_deauth_detection() -> None:
    assert _evidence().deauth_total > 8
    assert "excessive" in _evidence().warnings[0]


def test_deauth_budget_stops_active_transmission() -> None:
    budget = DeauthBudgetManager("02:00:00:00:00:02", "02:00:00:00:00:01", hard_limit=2)
    budget.observe_frame()
    budget.observe_frame()
    assert budget.exceeded
    assert not budget.may_start_attempt()


def test_pmkid_only_is_not_full_handshake() -> None:
    evidence = _evidence()
    assert evidence.material_status == MaterialStatus.PMKID_ONLY
    assert evidence.material_status != MaterialStatus.FULL_4WAY


def test_pmkid_allows_offline_analysis() -> None:
    assert _evidence().offline_analysis_ready


def test_hcx_warning_and_missing_radiotap_penalty() -> None:
    quality = score_evidence(_evidence(), rf_score=85)
    assert quality.warning_penalty == -20
    assert quality.format_score == 40


def test_post_material_observation_window() -> None:
    machine = ReconnectStateMachine(observation_seconds=5)
    now = datetime.now(UTC)
    machine.capture_started()
    machine.active_attempt_started()
    machine.observe("material", now)
    assert not machine.observation_complete(now + timedelta(seconds=4))
    assert machine.observation_complete(now + timedelta(seconds=5))


def test_reconnect_state_machine() -> None:
    machine = ReconnectStateMachine()
    machine.capture_started()
    machine.active_attempt_started()
    assert machine.observe("auth") == ReconnectState.WAITING_ASSOC
    assert machine.observe("assoc") == ReconnectState.WAITING_EAPOL
