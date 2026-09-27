"""Convert scan status timestamps to UTC-naive PostgreSQL timestamps."""

from datetime import datetime, timezone


def database_scan_start(value):
    if not value:
        return None
    started = datetime.fromisoformat(value)
    if started.tzinfo is None:
        started = started.astimezone()
    return started.astimezone(timezone.utc).replace(tzinfo=None)
