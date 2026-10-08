import pytest

from app.core.recovery import estimate_mask
from app.utils.validation import is_mac


def test_mac_validation() -> None:
    assert is_mac("02:11:22:33:44:55")
    assert not is_mac("not-a-mac")


def test_mask_estimation() -> None:
    assert estimate_mask("?d?d?d") == 1000
    with pytest.raises(ValueError):
        estimate_mask("password")
