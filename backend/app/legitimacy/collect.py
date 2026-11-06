"""Layer 1, who sent it: runs every sender check for a submission and returns the findings.

1. Read the conversation (model plus plain rules): company, website, job, claimed age, links, emails.
2. Find the company's official website on Wikidata, independently of what the sender says.
3. In parallel: public records for the company's domain, its job board, and GitHub.
4. Pure checks: lookalike domains, fake meeting links, off-domain recruiter, email, headers, LinkedIn.

Any collector that crashes only turns its own checks into "unknown".
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable
from datetime import datetime
from typing import Optional

import httpx
from pydantic import BaseModel, ConfigDict

from app.legitimacy import ats, claims as claims_mod, contact, domain_records, github_meta, lookalike
from app.legitimacy.claims import Claims, Complete
from app.legitimacy.common import clear, hit, unknown
from app.legitimacy.company_age import claimed_age_finding
from app.legitimacy.domains import FREE_WEBMAIL, registrable
from app.legitimacy.http import FetchError
from app.legitimacy.resolve_official import OfficialSite, resolve_official
from app.rules.engine import Finding
from app.schemas import Submission

DOMAIN_CHECKS = ("C2_domain_age", "C3_first_archive_capture_recent", "H4_domain_seized_or_listed",
                 "C8_no_mx", "C8_no_spf", "C8_no_dmarc")
JOB_CHECKS = ("C5_job_not_on_official_board", "C5_job_on_official_board")
GITHUB_CHECKS = ("P5_github_account_age", "P6_repo_on_personal_account", "P7_repo_new_or_copied",
                 "C9_assessment_only_github_org", "C9_verified_github_org")


class SenderReport(BaseModel):
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    findings: list[Finding]
    claims: Optional[Claims] = None
    official: Optional[OfficialSite] = None
    company_domain: Optional[str] = None  # the domain whose records were checked
    notes: list[str] = []                 # what couldn't be done, in plain words


async def _guard(coro: Awaitable[list[Finding]], checks: tuple[str, ...], what: str) -> list[Finding]:
    """Runs one collector; if it fails in any way, its checks become unknown instead of failing the job."""
    try:
        return await coro
    except FetchError as e:
        return [unknown(c, str(e)) for c in checks]
    except Exception as e:  # a bug in one collector must not take the verdict down
        return [unknown(c, f"{what} failed ({type(e).__name__})") for c in checks]


def _is_company_mail_domain(domain: Optional[str]) -> bool:
    return bool(domain) and domain not in FREE_WEBMAIL and domain not in lookalike.ATS_SENDERS


def _linkedin_findings(sub: Submission) -> list[Finding]:
    answers = sub.linkedin
    if not answers:
        return []
    out = []
    pairs = (
        ("P4_linkedin_profile_new", answers.profile_under_6_months, True,
         "You said the profile is less than 6 months old"),
        ("P4_linkedin_unverified", answers.has_any_verification, False,
         "You said the profile has no verification badge"),
        ("P4_linkedin_workplace_verified", answers.workplace_verified_here, True,
         "You said LinkedIn verifies they work at this company"),
    )
    for check, answer, risky_when, summary in pairs:
        if answer is None:
            continue
        out.append(hit(check, summary) if answer == risky_when else clear(check))
    return out


async def check_sender(sub: Submission, *, client: httpx.AsyncClient, now: datetime,
                       complete: Optional[Complete] = None, github_token: Optional[str] = None) -> SenderReport:
    notes: list[str] = []
    findings: list[Finding] = []

    # 1. The conversation.
    said: Optional[Claims] = None
    if sub.conversation:
        said = await claims_mod.extract_claims(sub.conversation, now_year=now.year, complete=complete)
        findings += said.findings
        if not said.model_ok:
            notes.append("The language model was unavailable; only the plain rules read the conversation.")

    company_name = sub.company_name or (said.company_name if said else None)
    job_title = sub.job_title or (said.job_title if said else None)
    emails = ([sub.contact_email] if sub.contact_email else []) + (said.emails if said else [])
    email = emails[0] if emails else None
    email_domain = registrable(email)
    links = ([sub.meeting_link] if sub.meeting_link else []) + (said.links if said else [])
    supplied_site = registrable(sub.company_website) or (said.company_website if said else None)
    repo_url = sub.repo_url or next((u for u in links if registrable(u) == "github.com"), None)

    # 2. The official website, found without trusting the sender.
    official: Optional[OfficialSite] = None
    if company_name:
        try:
            official = await resolve_official(client, company_name)
            if official is None:
                notes.append(f"Wikidata doesn't list an official website for {company_name}.")
        except FetchError as e:
            notes.append(f"Couldn't look up the company on Wikidata: {e}.")
        except Exception as e:
            notes.append(f"The Wikidata lookup failed ({type(e).__name__}).")
    official_domain = official.domain if official else None

    # The domain the sender presents as the company's: their site, else their work email domain.
    company_domain = supplied_site or (email_domain if _is_company_mail_domain(email_domain) else None) \
        or official_domain

    # 3. Network checks, in parallel.
    async def domain_part() -> list[Finding]:
        if not company_domain:
            return [unknown(c, "no company website or work email domain to check") for c in DOMAIN_CHECKS] + \
                   [unknown("C1_claimed_age_contradiction", "no company domain to compare the claim with")]
        found, facts = await domain_records.domain_findings(client, company_domain, now)
        return found + [claimed_age_finding(
            claimed_founded_year=said.founded_year if said else None,
            claim_quote=said.age_quote if said else None,
            registered=facts.registered, first_capture=facts.first_capture, now=now)]

    async def job_part() -> list[Finding]:
        if not job_title:
            return []
        return await ats.job_board_findings(client, company_name=company_name, official_domain=official_domain,
                                            job_title=job_title)

    async def github_part() -> list[Finding]:
        return await github_meta.github_findings(
            client, repo_url=repo_url, github_handle=sub.github_handle, company_name=company_name,
            official_domain=official_domain, claimed_founded_year=said.founded_year if said else None,
            now=now, token=github_token)

    parts = await asyncio.gather(
        _guard(domain_part(), DOMAIN_CHECKS + ("C1_claimed_age_contradiction",), "the domain records check"),
        _guard(job_part(), JOB_CHECKS, "the job board check"),
        _guard(github_part(), GITHUB_CHECKS, "the GitHub check"),
    )
    for part in parts:
        findings += part

    # 4. Pure checks.
    involved = [d for d in {supplied_site, email_domain, *(registrable(u) for u in links)} if d]
    if company_name or sub.company_website or sub.known_contact_domain:
        findings.append(lookalike.lookalike_finding(involved, official_domain=official_domain,
                                                    known_contact_domain=registrable(sub.known_contact_domain)))
        supplied = [d for d in (supplied_site, email_domain if _is_company_mail_domain(email_domain) else None) if d]
        findings.append(lookalike.off_official_domain_finding(supplied, official_domain=official_domain))
    if sub.conversation or sub.meeting_link:
        findings.append(lookalike.meeting_link_finding(links))
    if email:
        findings += contact.contact_email_findings(email, official_domain=official_domain)
    if sub.email_headers:
        findings += contact.email_auth_findings(sub.email_headers, official_domain=official_domain)
    findings += _linkedin_findings(sub)

    return SenderReport(findings=findings, claims=said, official=official, company_domain=company_domain,
                        notes=notes)
