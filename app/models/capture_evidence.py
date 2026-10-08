from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class MaterialStatus(StrEnum):
    NO_MATERIAL = "no_material"
    PMKID_ONLY = "pmkid_only"
    EAPOL_PARTIAL = "eapol_partial"
    EAPOL_VALID_PAIR = "eapol_valid_pair"
    FULL_4WAY = "full_4way"
    PMKID_AND_EAPOL = "pmkid_and_eapol"


@dataclass(frozen=True, slots=True)
class CaptureEvidence:
    auth_frames: int = 0
    association_frames: int = 0
    reassociation_frames: int = 0
    eapol_total: int = 0
    m1_count: int = 0
    m2_count: int = 0
    m3_count: int = 0
    m4_count: int = 0
    valid_eapol_pairs: int = 0
    rc_checked_pairs: int = 0
    pmkid_total: int = 0
    pmkid_best: int = 0
    pmkid_written: int = 0
    deauth_total: int = 0
    disassoc_total: int = 0
    capture_format: str = "pcapng"
    radiotap_present: bool = True
    capture_duration_seconds: int = 0
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def material_status(self) -> MaterialStatus:
        pmkid = self.pmkid_written > 0 or self.pmkid_best > 0
        full = all((self.m1_count, self.m2_count, self.m3_count, self.m4_count))
        eapol = self.valid_eapol_pairs > 0
        partial = self.eapol_total > 0
        if pmkid and (full or eapol):
            return MaterialStatus.PMKID_AND_EAPOL
        if full:
            return MaterialStatus.FULL_4WAY
        if eapol:
            return MaterialStatus.EAPOL_VALID_PAIR
        if pmkid:
            return MaterialStatus.PMKID_ONLY
        if partial:
            return MaterialStatus.EAPOL_PARTIAL
        return MaterialStatus.NO_MATERIAL

    @property
    def offline_analysis_ready(self) -> bool:
        return self.pmkid_written > 0 or self.valid_eapol_pairs > 0


@dataclass(frozen=True, slots=True)
class CaptureQuality:
    format_score: int
    rf_score: int
    authentication_score: int
    association_score: int
    eapol_score: int
    pmkid_score: int
    replay_counter_score: int
    warning_penalty: int

    @property
    def overall(self) -> int:
        raw = (
            sum(
                (
                    self.format_score,
                    self.rf_score,
                    self.authentication_score,
                    self.association_score,
                    self.eapol_score,
                    self.pmkid_score,
                    self.replay_counter_score,
                )
            )
            // 7
        )
        return max(0, min(100, raw + self.warning_penalty))


def score_evidence(evidence: CaptureEvidence, rf_score: int = 70) -> CaptureQuality:
    warning_penalty = -20 if evidence.warnings else 0
    return CaptureQuality(
        format_score=(
            100
            if evidence.capture_format == "pcapng" and evidence.radiotap_present
            else 60 if evidence.capture_format == "pcapng" else 40
        ),
        rf_score=max(0, min(100, rf_score)),
        authentication_score=100 if evidence.auth_frames else 0,
        association_score=(
            100 if evidence.association_frames or evidence.reassociation_frames else 0
        ),
        eapol_score=(
            100 if evidence.valid_eapol_pairs else 45 if evidence.eapol_total else 0
        ),
        pmkid_score=100 if evidence.pmkid_written else 0,
        replay_counter_score=100 if evidence.rc_checked_pairs else 0,
        warning_penalty=warning_penalty,
    )
