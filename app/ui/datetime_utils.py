"""Formatting helpers for timestamps persisted by the local database."""

from __future__ import annotations

from datetime import UTC, datetime


def local_datetime(value: datetime) -> datetime:
    """Return a stored UTC timestamp converted to the PC's local timezone.

    SQLite does not preserve the timezone flag on values loaded by SQLAlchemy,
    so naive values from the database are explicitly treated as UTC first.
    ``astimezone()`` then uses the operating system's configured local zone.
    """

    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone()


def format_local_datetime(value: datetime, pattern: str) -> str:
    return local_datetime(value).strftime(pattern)
