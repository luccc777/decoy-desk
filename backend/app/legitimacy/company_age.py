"""C1: does the company claim to be much older than the public records show?"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from app.legitimacy.common import clear, days_since, hit, unknown
from app.rules.engine import Finding

CHECK = "C1_claimed_age_contradiction"


def claimed_age_finding(*, claimed_founded_year: Optional[int], claim_quote: Optional[str],
                        registered: Optional[datetime], first_capture: Optional[datetime],
                        now: datetime) -> Finding:
    """Fires when the records are under half the claimed age.

    The RDAP registration date wins over the archive: a scammer who buys an expired
    domain gets a fresh registration date, while the archive still shows the old owner's site.
    """
    if claimed_founded_year is None:
        return unknown(CHECK, "the conversation doesn't say how old the company is")
    if registered is not None:
        evidence, what = registered, "its domain was registered on"
    elif first_capture is not None:
        evidence, what = first_capture, "the web archive first saw its site on"
    else:
        return unknown(CHECK, "no registration or archive date to compare with")

    claimed_years = now.year - claimed_founded_year
    record_years = days_since(evidence, now) / 365.25
    summary = (f"Claims to exist since {claimed_founded_year} ({claimed_years} years), "
               f"but {what} {evidence:%Y-%m-%d} ({record_years:.1f} years ago)")
    if claimed_years < 2:
        return clear(CHECK, f"Claims to be young ({claimed_founded_year}); nothing to contradict")
    if record_years < 0.5 * claimed_years:
        return hit(CHECK, summary, quote=claim_quote)
    return clear(CHECK, summary.replace(", but", ", and"))
