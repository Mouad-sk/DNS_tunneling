"""Helpers shared by capture backends."""

from __future__ import annotations

from datetime import datetime, timezone


QTYPE_MAP: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

RCODE_MAP: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def qtype_name(value: int | str | None) -> str:
    if value is None:
        return "UNKNOWN"
    if isinstance(value, str):
        return value.upper().strip() or "UNKNOWN"
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return str(value).upper()
    return QTYPE_MAP.get(ivalue, str(ivalue))


def rcode_name(value: int | str | None) -> str:
    if value is None:
        return "NOERROR"
    if isinstance(value, str):
        text = value.upper().strip()
        return text or "NOERROR"
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return str(value).upper()
    return RCODE_MAP.get(ivalue, str(ivalue))


def parse_ts(value: float | str | datetime) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip()
    try:
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    except ValueError:
        pass
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
