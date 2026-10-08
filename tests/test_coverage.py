from app.core.coverage import CoverageEngine, StrategyFingerprint
from app.core.recovery import RecoveryBrain, estimate_mask


def _upper_hex() -> StrategyFingerprint:
    return StrategyFingerprint(
        "synthetic-artifact", "mask", "?H?H?H?H?H?H?H?H", "?H", "mock-hashcat"
    )


def test_exhausted_mask_is_persisted() -> None:
    coverage = CoverageEngine()
    coverage.record_exhausted(_upper_hex(), estimate_mask(_upper_hex().mask))
    assert coverage.was_exhausted(_upper_hex())


def test_exhausted_mask_is_not_repeated() -> None:
    coverage = CoverageEngine()
    coverage.record_exhausted(_upper_hex(), estimate_mask(_upper_hex().mask))
    assert coverage.was_exhausted(_upper_hex())


def test_recovery_brain_replans_after_exhausted() -> None:
    plans = RecoveryBrain().recommend(
        True, {"Numeric eight-character mask"}, 200_000_000
    )
    assert all(plan.name != "Numeric eight-character mask" for plan in plans)


def test_upper_and_lower_hex_are_distinct_spaces() -> None:
    assert estimate_mask("?H" * 8) == estimate_mask("?h" * 8)
    assert (
        _upper_hex().value
        != StrategyFingerprint(
            "synthetic-artifact", "mask", "?h" * 8, "?h", "mock-hashcat"
        ).value
    )
