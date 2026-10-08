from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StrategyFingerprint:
    artifact: str
    attack_mode: str
    mask: str
    charset: str
    hashcat_version: str
    settings: str = ""

    @property
    def value(self) -> str:
        payload = "\x1f".join(
            (
                self.artifact,
                self.attack_mode,
                self.mask,
                self.charset,
                self.hashcat_version,
                self.settings,
            )
        )
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class CoverageRecord:
    fingerprint: str
    candidates_tested: int
    total_candidates: int
    result: str

    @property
    def complete(self) -> bool:
        return (
            self.result == "search_space_exhausted"
            and self.candidates_tested >= self.total_candidates
        )


class CoverageEngine:
    def __init__(self) -> None:
        self._records: dict[str, CoverageRecord] = {}

    def record_exhausted(
        self, fingerprint: StrategyFingerprint, candidates: int
    ) -> CoverageRecord:
        record = CoverageRecord(
            fingerprint.value, candidates, candidates, "search_space_exhausted"
        )
        self._records[record.fingerprint] = record
        return record

    def was_exhausted(self, fingerprint: StrategyFingerprint) -> bool:
        return self._records.get(
            fingerprint.value, CoverageRecord("", 0, 1, "")
        ).complete
