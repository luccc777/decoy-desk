"""What public records say about a domain: registration (RDAP), first archive capture (Wayback), mail DNS.

Answers C2_domain_age, C3_first_archive_capture_recent, H4_domain_seized_or_listed
and the three C8 mail checks. Each source fails on its own: one being down only
makes its own checks unknown.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime
from typing import Optional

import httpx
from pydantic import BaseModel, ConfigDict

from app.legitimacy.common import clear, days_since, hit, measured, parse_time, unknown
from app.legitimacy.http import FetchError, get, json_of
from app.rules.engine import Finding

RDAP_URL = "https://rdap.org/domain/{domain}"
WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
DOH_SERVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")

# US law-enforcement seizures point the domain at these name servers (e.g. ns1.fbi.seized.gov).
SEIZED_NS_SUFFIX = ".seized.gov"

DNS_NOERROR, DNS_NXDOMAIN = 0, 3
TYPE_MX, TYPE_TXT = 15, 16


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True)


class Registration(_Frozen):
    domain: str
    registered: Optional[datetime]
    nameservers: list[str]
    source: str


class MailDns(_Frozen):
    domain: str
    has_mx: bool
    has_spf: bool
    has_dmarc: bool
    source: str


# ---------------------------------------------------------------- RDAP

def parse_rdap(data: dict, domain: str, source: str) -> Registration:
    registered = None
    for event in data.get("events") or []:
        if event.get("eventAction") == "registration":
            registered = parse_time(event.get("eventDate"))
    nameservers = sorted({(ns.get("ldhName") or "").lower().rstrip(".")
                          for ns in data.get("nameservers") or [] if ns.get("ldhName")})
    return Registration(domain=domain, registered=registered, nameservers=nameservers, source=source)


async def fetch_registration(client: httpx.AsyncClient, domain: str) -> Optional[Registration]:
    """None when no RDAP server covers the domain (many ccTLDs) or the registry doesn't know it."""
    url = RDAP_URL.format(domain=domain)
    r = await get(client, url, headers={"accept": "application/rdap+json"})
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        raise FetchError(f"RDAP answered HTTP {r.status_code}")
    return parse_rdap(json_of(r), domain, str(r.url))


def registration_findings(reg: Optional[Registration], now: datetime, why: str = "") -> list[Finding]:
    if reg is None:
        why = why or "no RDAP data for this domain (common for country domains)"
        return [unknown("C2_domain_age", why), unknown("H4_domain_seized_or_listed", why)]
    age = days_since(reg.registered, now) if reg.registered else None
    out = [measured("C2_domain_age", age,
                    f"{reg.domain} was registered on {reg.registered:%Y-%m-%d}" if reg.registered else "",
                    source=reg.source, why_unknown="RDAP has no registration date")]
    seized = [ns for ns in reg.nameservers if ns.endswith(SEIZED_NS_SUFFIX)]
    if seized:
        out.append(hit("H4_domain_seized_or_listed",
                       f"{reg.domain} was seized by law enforcement (name server {seized[0]})", source=reg.source))
    else:
        out.append(clear("H4_domain_seized_or_listed", f"{reg.domain} is not under a seizure notice",
                         source=reg.source))
    return out


# ---------------------------------------------------------------- Wayback

async def fetch_first_capture(client: httpx.AsyncClient, domain: str) -> Optional[datetime]:
    """Oldest capture of the site's home page; None when the archive has never seen it."""
    r = await get(client, WAYBACK_CDX, params={"url": domain, "output": "json", "limit": "1",
                                               "fl": "timestamp"})
    if r.status_code != 200:
        raise FetchError(f"the web archive answered HTTP {r.status_code}")
    rows = json_of(r) if r.content.strip() else []
    # First row is the header ["timestamp"].
    return parse_time(rows[1][0]) if len(rows) > 1 and rows[1] else None


def archive_finding(first: Optional[datetime], domain: str, now: datetime) -> Finding:
    if first is None:
        return unknown("C3_first_archive_capture_recent", f"the web archive has no copy of {domain}")
    return measured("C3_first_archive_capture_recent", days_since(first, now),
                    f"The web archive first saw {domain} on {first:%Y-%m-%d}",
                    source=f"https://web.archive.org/web/*/{domain}")


# ---------------------------------------------------------------- mail DNS

async def _resolve(client: httpx.AsyncClient, name: str, rtype: str) -> tuple[int, list[dict], str]:
    last_error: Optional[FetchError] = None
    for server in DOH_SERVERS:
        try:
            r = await get(client, server, params={"name": name, "type": rtype},
                          headers={"accept": "application/dns-json"})
            data = json_of(r)
        except FetchError as e:
            last_error = e
            continue
        status = data.get("Status")
        if r.status_code == 200 and status in (DNS_NOERROR, DNS_NXDOMAIN):
            return status, data.get("Answer") or [], server
        last_error = FetchError(f"DNS lookup of {name} failed (status {status})")
    raise last_error or FetchError("no DNS server answered")


_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')


def _txt(answer: list[dict]) -> list[str]:
    """TXT strings. Some resolvers quote them and split long ones: "v=spf1 a" " include:x"."""
    out = []
    for a in answer:
        if a.get("type") != TYPE_TXT:
            continue
        data = a.get("data", "")
        parts = _QUOTED.findall(data)
        out.append("".join(parts) if parts else data)
    return out


def has_real_mx(answer: list[dict]) -> bool:
    """MX records other than the RFC 7505 "null MX" (0 .), which says "no mail here"."""
    for a in answer:
        if a.get("type") != TYPE_MX:
            continue
        host = a.get("data", "").split()[-1] if a.get("data") else ""
        if host not in ("", "."):
            return True
    return False


async def fetch_mail_dns(client: httpx.AsyncClient, domain: str) -> MailDns:
    _, mx, server = await _resolve(client, domain, "MX")
    _, txt, _ = await _resolve(client, domain, "TXT")
    _, dmarc, _ = await _resolve(client, f"_dmarc.{domain}", "TXT")
    return MailDns(
        domain=domain,
        has_mx=has_real_mx(mx),
        has_spf=any(t.lower().startswith("v=spf1") for t in _txt(txt)),
        has_dmarc=any(t.lower().startswith("v=dmarc1") for t in _txt(dmarc)),
        source=server,
    )


def mail_findings(mail: Optional[MailDns], why: str = "") -> list[Finding]:
    checks = ("C8_no_mx", "C8_no_spf", "C8_no_dmarc")
    if mail is None:
        return [unknown(c, why or "DNS lookup failed") for c in checks]
    out = []
    d = mail.domain
    lines = {
        "C8_no_mx": (mail.has_mx, f"{d} can receive email", f"{d} can't receive email (no MX record)"),
        "C8_no_spf": (mail.has_spf, f"{d} has an SPF record", f"{d} has no SPF record"),
        "C8_no_dmarc": (mail.has_dmarc, f"{d} has a DMARC record", f"{d} has no DMARC record"),
    }
    for check in checks:
        present, yes, no = lines[check]
        out.append(clear(check, yes, source=mail.source) if present else hit(check, no, source=mail.source))
    return out


# ---------------------------------------------------------------- all together

class DomainFacts(_Frozen):
    """Dates other checks reuse, such as the claimed-age contradiction (C1)."""

    registered: Optional[datetime] = None
    first_capture: Optional[datetime] = None


async def domain_findings(client: httpx.AsyncClient, domain: str, now: datetime) -> tuple[list[Finding], DomainFacts]:
    reg_task = asyncio.create_task(fetch_registration(client, domain))
    wb_task = asyncio.create_task(fetch_first_capture(client, domain))
    dns_task = asyncio.create_task(fetch_mail_dns(client, domain))
    reg, first, mail = await asyncio.gather(reg_task, wb_task, dns_task, return_exceptions=True)

    findings: list[Finding] = []
    if isinstance(reg, BaseException):
        findings += registration_findings(None, now, why=_why(reg))
        reg = None
    else:
        findings += registration_findings(reg, now)
    if isinstance(first, BaseException):
        findings.append(unknown("C3_first_archive_capture_recent", _why(first)))
        first = None
    else:
        findings.append(archive_finding(first, domain, now))
    findings += mail_findings(None, _why(mail)) if isinstance(mail, BaseException) else mail_findings(mail)

    facts = DomainFacts(registered=reg.registered if reg else None, first_capture=first)
    return findings, facts


def _why(error: BaseException) -> str:
    if isinstance(error, FetchError):
        return str(error)
    return f"unexpected error ({type(error).__name__})"
