"""The contact's email address (P1, P2) and what the user's mail provider said about the email (H6, P3).

Pure functions: no network, no clock.
"""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass
from typing import Optional

from app.legitimacy.common import clear, hit, unknown
from app.legitimacy.domains import EMAIL_RE, FREE_WEBMAIL, registrable
from app.legitimacy.lookalike import ATS_SENDERS, lookalike_reason
from app.rules.engine import Finding

__all__ = ["ATS_SENDERS", "contact_email_findings", "email_auth_findings"]


def _registrable(text: Optional[str]) -> Optional[str]:
    """registrable() that reads a malformed URL ("http://[x") as nothing instead of raising."""
    try:
        return registrable(text)
    except ValueError:
        return None


# ---------------------------------------------------------------- P1, P2

def _email_domain(email: str) -> Optional[str]:
    """The domain of an address, also from "Jane <jane@x.com>"; Unicode domains come back as punycode."""
    m = EMAIL_RE.search(email or "")
    if m:
        return m.group(1).lower()
    # The shared pattern is ASCII-only, and a Unicode domain is exactly what a homoglyph attack uses.
    local, at, domain = (email or "").strip().strip("<>").rpartition("@")
    domain = domain.strip().strip(".>")
    if not at or not local.strip() or not domain:
        return None
    try:
        return domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def contact_email_findings(email: str, *, official_domain: Optional[str]) -> list[Finding]:
    """P1 (free webmail) and P2 (email off the official domain), in that order.

    P2 is clear, not hit, for free webmail (P1 counts it), for recruiting platforms that send
    mail for companies, and for lookalikes (H3 counts them). Those three cases are clear even
    without an official domain, since none of them can be the company's own domain.
    """
    domain = _email_domain(email)
    reg = _registrable(domain)
    if reg is None:
        why = "the contact's email address couldn't be read"
        return [unknown("P1_free_webmail", why), unknown("P2_email_off_official_domain", why)]

    if reg in FREE_WEBMAIL:
        p1 = hit("P1_free_webmail", f"The contact writes from {reg}, a free webmail service")
    else:
        p1 = clear("P1_free_webmail")

    official = _registrable(official_domain)
    p2_check = "P2_email_off_official_domain"
    if reg in FREE_WEBMAIL:
        p2 = clear(p2_check, "Free webmail is counted once, as free webmail")
    elif reg in ATS_SENDERS or domain in ATS_SENDERS:
        p2 = clear(p2_check, f"{reg} is a recruiting platform that sends mail for companies")
    elif official is None:
        p2 = unknown(p2_check, "the company's official domain isn't known")
    elif reg == official:
        p2 = clear(p2_check, f"The contact writes from {official}")
    elif lookalike_reason(domain, official):
        p2 = clear(p2_check, f"{reg} imitates {official}; counted as a lookalike domain instead")
    else:
        p2 = hit(p2_check, f"The contact writes from {reg}, not {official}")
    return [p1, p2]


# ---------------------------------------------------------------- H6, P3

_AUTH_RESULTS = re.compile(r"(?im)^authentication-results[ \t]*:(.*)$")
_DMARC = re.compile(r"\s*dmarc\s*=\s*([a-z]+)", re.IGNORECASE)
_HEADER_FROM = re.compile(r"(?:^|\s)header\.from\s*=\s*\"?([^\s\";]+)", re.IGNORECASE)


@dataclass(frozen=True)
class _AuthResults:
    authserv_id: Optional[str]
    results: tuple[str, ...]  # one "method=result ptype.prop=value ..." string each


def _strip_comments(value: str) -> str:
    """Drop RFC 5322 comments, nested ones too: "dmarc=pass (p=REJECT) header.from=x"."""
    previous = None
    while previous != value:
        previous, value = value, re.sub(r"\([^()]*\)", " ", value)
    return value


def _auth_results_headers(raw_headers: str) -> list[_AuthResults]:
    """Every Authentication-Results header, topmost first (RFC 8601)."""
    text = textwrap.dedent((raw_headers or "").replace("\r\n", "\n").replace("\r", "\n"))
    text = re.sub(r"\n[ \t]+", " ", text)  # unfold continuation lines
    # No stop at the first blank line: a paste often starts with a summary (Gmail's
    # "Show original" page), and the topmost header still comes before any quoted body.
    headers = []
    for m in _AUTH_RESULTS.finditer(text):
        parts = [p.strip() for p in _strip_comments(m.group(1)).split(";")]
        # Outlook leaves out the authserv-id and starts with the first result.
        if parts and parts[0] and "=" not in parts[0]:
            authserv_id, results = parts[0].split()[0].lower(), parts[1:]
        else:
            authserv_id, results = None, parts
        headers.append(_AuthResults(authserv_id, tuple(r for r in results if r)))
    return headers


def _dmarc(headers: list[_AuthResults]) -> Optional[tuple[str, Optional[str], Optional[str]]]:
    """(result, header.from, authserv-id) from the receiving provider's headers, or None.

    Only the topmost header counts, plus the ones right below it with the same authserv-id
    (Proton writes one header per method). Lower headers were added before delivery, possibly
    by the sender.
    """
    if not headers:
        return None
    top = headers[0]
    group = [top]
    if top.authserv_id:
        for h in headers[1:]:
            if h.authserv_id != top.authserv_id:
                break
            group.append(h)
    for h in group:
        for result in h.results:
            m = _DMARC.match(result)
            if m:
                found = _HEADER_FROM.search(result)
                header_from = found.group(1).strip("@").lower() if found else None
                return m.group(1).lower(), header_from, top.authserv_id
    return None


def email_auth_findings(raw_headers: str, *, official_domain: Optional[str]) -> list[Finding]:
    """H6 (DMARC failed for the official domain) and P3 (DMARC passed for it), in that order.

    Read from the topmost Authentication-Results header, which the user's own mail provider added.
    A header.from on a subdomain of the official domain counts as the official domain.
    """
    h6, p3 = "H6_dmarc_fail", "P3_dmarc_aligned_pass"

    def both_unknown(why: str) -> list[Finding]:
        return [unknown(h6, why), unknown(p3, why)]

    official = _registrable(official_domain)
    if official is None:
        return both_unknown("the company's official domain isn't known")
    headers = _auth_results_headers(raw_headers)
    if not headers:
        return both_unknown("the pasted headers have no Authentication-Results line")
    dmarc = _dmarc(headers)
    if dmarc is None:
        return both_unknown("the mail provider's Authentication-Results has no DMARC result")
    result, header_from, authserv_id = dmarc
    from_reg = _registrable(header_from)
    if from_reg is None:
        return both_unknown("the DMARC result doesn't say which domain it checked")

    source = f"Authentication-Results from {authserv_id}" if authserv_id else "Authentication-Results"
    if result == "fail" and from_reg == official:
        return [
            hit(h6, f"The email says it's from {official}, but your mail provider's DMARC check failed",
                source=source),
            clear(p3),
        ]
    if result == "pass" and from_reg == official:
        return [
            clear(h6),
            hit(p3, f"Your mail provider confirmed the email really came from {official} (DMARC pass)",
                source=source),
        ]
    summary = f"DMARC {result} for {from_reg}"
    return [clear(h6, summary, source=source), clear(p3, summary, source=source)]
