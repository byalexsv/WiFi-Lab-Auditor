from app.core.recovery import RecoveryBrain


def test_recovery_brain_does_not_recommend_exhausted_strategy() -> None:
    plans = RecoveryBrain().recommend(
        True, {"Operator-provided dictionary"}, 200_000_000
    )
    assert all(plan.name != "Operator-provided dictionary" for plan in plans)


def test_invalid_capture_recommends_capture_remediation() -> None:
    plan = RecoveryBrain().recommend(False, set(), 1)[0]
    assert plan.name == "Improve capture"
