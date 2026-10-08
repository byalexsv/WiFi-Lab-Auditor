import os
import time
from datetime import UTC, datetime

from app.ui.datetime_utils import format_local_datetime, local_datetime


def test_naive_database_timestamp_is_interpreted_as_utc(monkeypatch):
    previous_tz = os.environ.get("TZ")
    monkeypatch.setenv("TZ", "America/El_Salvador")
    # time.tzset is required for astimezone() to observe TZ on Unix.
    time.tzset()
    try:
        value = local_datetime(datetime(2026, 10, 8, 14, 32))
        assert value.hour == 8
        assert (
            format_local_datetime(datetime(2026, 10, 8, 14, 32), "%d/%m %H:%M")
            == "08/10 08:32"
        )
    finally:
        if previous_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = previous_tz
        time.tzset()


def test_aware_timestamp_keeps_its_instant():
    value = local_datetime(datetime(2026, 10, 8, 14, 32, tzinfo=UTC))
    assert value.utcoffset() is not None
    assert value.astimezone(UTC).hour == 14
