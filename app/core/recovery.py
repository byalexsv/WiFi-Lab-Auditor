from __future__ import annotations

from dataclasses import dataclass

CHARSETS = {"?l": 26, "?u": 26, "?d": 10, "?s": 33, "?h": 16, "?H": 16}


def estimate_mask(mask: str) -> int:
    tokens = [mask[index : index + 2] for index in range(0, len(mask), 2)]
    if not mask or any(token not in CHARSETS for token in tokens):
        raise ValueError("Mask must use Hashcat character sets such as ?l, ?u or ?d")
    result = 1
    for token in tokens:
        result *= CHARSETS[token]
    return result


@dataclass(frozen=True, slots=True)
class RecoveryPlan:
    name: str
    candidates: int
    confidence: str
    rationale: str


class RecoveryBrain:
    def recommend(
        self, valid_capture: bool, exhausted: set[str], budget_candidates: int
    ) -> list[RecoveryPlan]:
        if not valid_capture:
            return [
                RecoveryPlan(
                    "Improve capture",
                    0,
                    "high",
                    "A valid EAPOL or PMKID artifact is required before offline analysis.",
                )
            ]
        catalog = [
            RecoveryPlan(
                "Operator-provided dictionary",
                1_000_000,
                "high",
                "Specific lab knowledge has the best cost-to-evidence ratio.",
            ),
            RecoveryPlan(
                "Targeted profile mask",
                100_000_000,
                "medium",
                "Bounded by declared password characteristics.",
            ),
            RecoveryPlan(
                "Numeric eight-character mask",
                100_000_000,
                "low",
                "Only suitable when explicitly justified by the lab profile.",
            ),
        ]
        return [
            plan
            for plan in catalog
            if plan.name not in exhausted and plan.candidates <= budget_candidates
        ]
