"""Small helpers every collector uses to build findings and handle dates."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from app.rules.engine import Evidence, Finding


def hit(check: str, summary: str, *, source: Optional[str] = None, quote: Optional[str] = None,
        value: Optional[float] = None) -> Finding:
    return Finding(check=check, status="hit", value=value,
                   evidence=[Evidence(summary=summary, source=source, quote=quote)])


def clear(check: str, summary: Optional[str] = None, *, source: Optional[str] = None,
          value: Optional[float] = None) -> Finding:
    evidence = [Evidence(summary=summary, source=source)] if summary else []
    return Finding(check=check, status="clear", value=value, evidence=evidence)


def unknown(check: str, why: str) -> Finding:
    return Finding(check=check, status="unknown", evidence=[Evidence(summary=f"Couldn't check: {why}")])


def measured(check: str, value: Optional[float], summary: str, *, source: Optional[str] = None,
             why_unknown: str = "no data") -> Finding:
    """For banded checks: the engine decides hit or clear from the value."""
    if value is None:
        return unknown(check, why_unknown)
    return Finding(check=check, status="clear", value=value,
                   evidence=[Evidence(summary=summary, source=source)])


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(text: Optional[str]) -> Optional[datetime]:
    """ISO 8601 (RDAP, GitHub) or the 14-digit Wayback timestamp, always as UTC."""
    if not text:
        return None
    text = text.strip()
    try:
        if text.isdigit() and len(text) >= 8:
            return datetime.strptime(text[:14].ljust(14, "0"), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def days_since(then: datetime, now: datetime) -> float:
    return max(0.0, (now - then).total_seconds() / 86400)
