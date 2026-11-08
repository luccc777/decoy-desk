"""What GitHub says about the repo, the account that shared it and the company's org.

Answers P5_github_account_age, P6_repo_on_personal_account, P7_repo_new_or_copied,
C9_assessment_only_github_org and C9_verified_github_org. The pure functions take
GitHub JSON and return values or findings; github_findings() does the few calls.

Unauthenticated, GitHub allows 60 calls an hour, so a full run makes at most
six: the repo, the user, up to three org lookups and one repo listing.
"""

from __future__ import annotations

import asyncio
import re
import unicodedata
from collections.abc import Awaitable, Mapping
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx

from app.legitimacy.common import clear, days_since, hit, measured, parse_time, unknown
from app.legitimacy.domains import label, registrable
from app.legitimacy.http import FetchError, get, json_of
from app.rules.engine import Evidence, Finding

API = "https://api.github.com"
WEB = "https://github.com"

P5 = "P5_github_account_age"
P6 = "P6_repo_on_personal_account"
P7 = "P7_repo_new_or_copied"
C9_TESTS = "C9_assessment_only_github_org"
C9_VERIFIED = "C9_verified_github_org"

NEW_REPO_DAYS = 14
ORG_LATE_YEARS = 2
# GitHub organizations launched in 2010; a company can't have had an org before that.
ORGS_LAUNCHED = 2010
MAX_LISTED = 100
MAX_SLUGS = 3

# GitHub logins: letters, digits and hyphens, up to 39 characters. Underscores
# only appear in enterprise-managed accounts, but they are harmless in a path.
_LOGIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,38}$")
_REPO_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_SSH = re.compile(r"^(?:ssh://)?git@github\.com[:/](?P<path>.+)$", re.IGNORECASE)
_GITHUB_HOSTS = frozenset({"github.com", "www.github.com"})
# First path segments on github.com that are pages, not accounts.
_RESERVED = frozenset({
    "orgs", "settings", "marketplace", "topics", "sponsors", "apps", "features", "about",
    "login", "explore", "collections", "trending", "search", "notifications", "new", "enterprise",
})

_LEGAL_SUFFIXES = frozenset({
    "inc", "incorporated", "llc", "llp", "lp", "ltd", "limited", "corp", "corporation", "co",
    "company", "gmbh", "ag", "sa", "sas", "sarl", "plc", "bv", "pty", "srl", "ltda", "oy", "ab",
    "as", "kk", "pte",
})

# Words that name a hiring test. Matched on whole tokens, so "latest" or
# "testing-library" don't count.
_TEST_WORDS = ("test", "assessment", "skill", "challenge", "task", "interview", "assignment")
_TEST_TOKENS = frozenset(w + s for w in _TEST_WORDS for s in ("", "s")) | {"takehome"}
# Prefixes that, glued to a test word, still name a test: "skilltest", "techchallenge".
_TEST_GLUE = frozenset({"skill", "skills", "coding", "code", "tech", "dev", "hiring", "home", "job", "test"})


# ---------------------------------------------------------------- inputs

def _github_path(text: str) -> Optional[list[str]]:
    """Path segments of a github.com URL (https, bare or SSH form); None for any other host."""
    text = text.strip()
    m = _SSH.match(text)
    if m:
        path = m.group("path")
    else:
        try:
            parts = urlsplit(text if "://" in text else "https://" + text)
            host = (parts.hostname or "").lower()
        except ValueError:
            return None
        if host not in _GITHUB_HOSTS:
            return None
        path = parts.path
    return [s for s in path.split("/") if s]


def parse_repo_url(url: Optional[str]) -> Optional[tuple[str, str]]:
    """(owner, repo) from the usual ways a GitHub repo gets pasted; None for anything else."""
    segments = _github_path(url or "")
    if not segments or len(segments) < 2:
        return None
    owner, repo = segments[0], segments[1]
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if owner.lower() in _RESERVED or not _LOGIN.match(owner):
        return None
    if not _REPO_NAME.match(repo) or repo in {".", ".."}:
        return None
    return owner, repo


def normalize_handle(handle: Optional[str]) -> Optional[str]:
    """"@octocat" or "https://github.com/octocat" -> "octocat"; None when it can't be a login."""
    text = (handle or "").strip()
    if "github.com" in text.lower():
        segments = _github_path(text)
        text = segments[0] if segments else ""
    text = text.lstrip("@")
    return text if _LOGIN.match(text) and text.lower() not in _RESERVED else None


def org_slugs(company_name: Optional[str], official_domain: Optional[str]) -> list[str]:
    """Org names to try: the official domain's label, then the company name hyphenated and joined."""
    candidates = []
    domain_label = label(official_domain) if official_domain else None
    if domain_label:
        candidates.append(domain_label.lower())
    if company_name:
        ascii_name = unicodedata.normalize("NFKD", company_name).encode("ascii", "ignore").decode()
        # Drop dots and apostrophes so "S.A." and "O'Reilly" stay one word.
        words = re.findall(r"[a-z0-9]+", re.sub(r"[.'’]", "", ascii_name.lower()))
        while len(words) > 1 and words[-1] in _LEGAL_SUFFIXES:
            words.pop()
        if words:
            candidates += ["-".join(words), "".join(words)]
    slugs = []
    for slug in candidates:
        if slug not in slugs and _LOGIN.match(slug):
            slugs.append(slug)
    return slugs[:MAX_SLUGS]


# ---------------------------------------------------------------- answers

def is_rate_limited(status: int, headers: Mapping[str, str], body: Any) -> bool:
    """GitHub says "slow down" with a 429, or with a 403 that has no quota left or a rate-limit message."""
    if status == 429:
        return True
    if status != 403:
        return False
    lower = {k.lower(): v for k, v in headers.items()}
    if lower.get("x-ratelimit-remaining") == "0" or lower.get("retry-after"):
        return True
    message = body.get("message") if isinstance(body, dict) else None
    return "rate limit" in str(message or "").lower()


def _api_headers(token: Optional[str]) -> dict[str, str]:
    headers = {"accept": "application/vnd.github+json", "x-github-api-version": "2022-11-28"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    return headers


async def fetch_json(client: httpx.AsyncClient, path: str, *, token: Optional[str] = None,
                     params: Optional[dict] = None) -> Any:
    """GitHub JSON for an API path; None on 404. Anything else that isn't a 200 raises FetchError."""
    r = await get(client, API + path, params=params, headers=_api_headers(token))
    if r.status_code == 404:
        return None
    if r.status_code == 200:
        return json_of(r)
    try:
        body = r.json()
    except ValueError:
        body = None
    if is_rate_limited(r.status_code, r.headers, body):
        raise FetchError("GitHub rate limit reached")
    raise FetchError(f"GitHub answered HTTP {r.status_code}")


# ---------------------------------------------------------------- the account and the repo

def account_age_finding(user: Mapping[str, Any], now: datetime) -> Finding:
    login = user.get("login") or "?"
    source = user.get("html_url") or f"{WEB}/{login}"
    created = parse_time(user.get("created_at"))
    if created is None:
        return unknown(P5, f"GitHub didn't give a creation date for {login}")
    days = days_since(created, now)
    return measured(P5, round(days, 1),
                    f"The GitHub account {login} was created on {created:%Y-%m-%d}, {int(days)} days ago",
                    source=source)


def personal_account_finding(repo: Mapping[str, Any]) -> Finding:
    owner = repo.get("owner") or {}
    login, kind = owner.get("login") or "?", owner.get("type")
    name = repo.get("full_name") or login
    source = repo.get("html_url")
    if kind == "User":
        return hit(P6, f"{name} belongs to the personal account {login}", source=source)
    if kind == "Organization":
        return clear(P6, f"{name} belongs to the GitHub org {login}", source=source)
    return unknown(P6, f"GitHub didn't say what kind of account {login} is")


def new_or_copied_finding(repo: Mapping[str, Any], now: datetime) -> Finding:
    name = repo.get("full_name") or "the repo"
    source = repo.get("html_url")
    created = parse_time(repo.get("created_at"))
    evidence = []
    if created is not None:
        days = days_since(created, now)
        if days < NEW_REPO_DAYS:
            evidence.append(Evidence(summary=f"{name} was created on {created:%Y-%m-%d}, {int(days)} days ago",
                                     source=source))
    if repo.get("fork"):
        parent = (repo.get("parent") or {}).get("full_name")
        evidence.append(Evidence(summary=f"{name} is a near copy of {parent}" if parent
                                 else f"{name} is a fork of another repo", source=source))
    if evidence:
        return Finding(check=P7, status="hit", evidence=evidence)
    if created is None:
        return unknown(P7, f"GitHub didn't give a creation date for {name}")
    return clear(P7, f"{name} was created on {created:%Y-%m-%d} and isn't a fork", source=source)


# ---------------------------------------------------------------- the company's org

def _words(text: Optional[str]) -> list[str]:
    # Split camelCase and letters from digits too: "SkillTest2" -> skill, test, 2.
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text or "")
    return re.findall(r"[a-z]+|[0-9]+", spaced.lower())


def _is_test_word(word: str) -> bool:
    if word in _TEST_TOKENS:
        return True
    return any(word.endswith(t) and word[:-len(t)] in _TEST_GLUE for t in _TEST_TOKENS if len(word) > len(t))


def looks_like_assessment(name: Optional[str], description: Optional[str] = None) -> bool:
    """True when the repo's name or description names a hiring test ("skilltest-frontend", "take-home")."""
    for text in (name, description):
        words = _words(text)
        if any(_is_test_word(w) for w in words):
            return True
        if any(a == "take" and b == "home" for a, b in zip(words, words[1:])):
            return True
    return False


def assessment_only(repos: list[Mapping[str, Any]]) -> bool:
    """True when the org has repos of its own and every one looks like a test.

    Forks are left out: forking a few popular projects is a cheap way to make
    a throwaway org look busy, and says nothing about what the org itself makes.
    """
    own = [r for r in repos if not r.get("fork")]
    return bool(own) and all(looks_like_assessment(r.get("name"), r.get("description")) for r in own)


def years_after_claim(org_created: Optional[datetime], claimed_founded_year: Optional[int]) -> Optional[int]:
    """How many years after the claimed founding the org appeared (counting from 2010 at the earliest)."""
    if org_created is None or claimed_founded_year is None:
        return None
    return org_created.year - max(claimed_founded_year, ORGS_LAUNCHED)


def needs_repo_listing(org: Mapping[str, Any]) -> bool:
    """An org with no public repos, or more than one page of them, can't be test-only; skip the call."""
    count = org.get("public_repos")
    return not isinstance(count, int) or 0 < count <= MAX_LISTED


def assessment_finding(org: Mapping[str, Any], repos: Optional[list[Mapping[str, Any]]],
                       claimed_founded_year: Optional[int], *, why_no_repos: Optional[str] = None) -> Finding:
    """repos is None when it wasn't listed: either not needed (see needs_repo_listing) or it failed."""
    login = org.get("login") or "?"
    source = org.get("html_url") or f"{WEB}/{login}"
    if repos is not None:
        tests_only: Optional[bool] = assessment_only(repos)
    else:
        tests_only = None if needs_repo_listing(org) else False

    evidence = []
    if tests_only:
        names = [r.get("name") or "?" for r in repos or [] if not r.get("fork")]
        shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
        evidence.append(Evidence(summary=f"Every repo in the GitHub org {login} looks like a test: {shown}",
                                 source=source))
    created = parse_time(org.get("created_at"))
    late = years_after_claim(created, claimed_founded_year)
    if late is not None and late > ORG_LATE_YEARS:
        evidence.append(Evidence(summary=f"The GitHub org {login} was created in {created.year}, "
                                         f"but the company says it was founded in {claimed_founded_year}",
                                 source=source))
    if evidence:
        return Finding(check=C9_TESTS, status="hit", evidence=evidence)
    if tests_only is None:
        return unknown(C9_TESTS, why_no_repos or "couldn't list the org's repos")
    if claimed_founded_year is not None and created is None:
        return unknown(C9_TESTS, f"GitHub didn't give a creation date for the org {login}")

    count = org.get("public_repos")
    summary = (f"The GitHub org {login} has no public repos" if count == 0
               else f"Not every repo in the GitHub org {login} looks like a test")
    if claimed_founded_year is not None:
        summary += f"; it was created in {created.year}, the company says it was founded in {claimed_founded_year}"
    return clear(C9_TESTS, summary, source=source)


def verified_finding(org: Mapping[str, Any], official_domain: Optional[str]) -> Finding:
    """Hit only when GitHub verified the org and the site it lists is the company's official domain."""
    login = org.get("login") or "?"
    source = org.get("html_url") or f"{WEB}/{login}"
    if "is_verified" not in org:
        return unknown(C9_VERIFIED, f"GitHub didn't say whether the org {login} is verified")
    if not org["is_verified"]:
        return clear(C9_VERIFIED, f"The GitHub org {login} isn't verified", source=source)
    official = registrable(official_domain)
    if official is None:
        return unknown(C9_VERIFIED, f"the GitHub org {login} is verified, but there's no official domain to compare")
    site = registrable(org.get("blog"))
    if site == official:
        return hit(C9_VERIFIED, f"The GitHub org {login} is verified and lists {official} as its site", source=source)
    return clear(C9_VERIFIED, f"The GitHub org {login} is verified, but its site is {site or 'not set'}, not {official}",
                 source=source)


# ---------------------------------------------------------------- the calls

async def _attempt(call: Optional[Awaitable[Any]]) -> tuple[Any, Optional[str]]:
    """(data, None), or (None, why) when the call failed. No call: (None, None)."""
    if call is None:
        return None, None
    try:
        return await call, None
    except FetchError as e:
        return None, str(e)


async def _find_org(client: httpx.AsyncClient, repo: Optional[Mapping[str, Any]], company_name: Optional[str],
                    official_domain: Optional[str], token: Optional[str]) -> tuple[Optional[dict], Optional[str], bool]:
    """(org, why not found, whether C9 applies). The repo's own org wins over a guess from the name."""
    owner = (repo or {}).get("owner") or {}
    if owner.get("type") == "Organization" and owner.get("login"):
        org, err = await _attempt(fetch_json(client, f"/orgs/{owner['login']}", token=token))
        if isinstance(org, dict):
            return org, None, True
        return None, err or f"GitHub has no org named {owner['login']}", True
    if not (company_name or official_domain):
        return None, None, False
    slugs = org_slugs(company_name, official_domain)
    if not slugs:
        return None, "no name to look up a GitHub org with", True
    errors = []
    for slug in slugs:
        org, err = await _attempt(fetch_json(client, f"/orgs/{slug}", token=token))
        if isinstance(org, dict):
            return org, None, True
        if err:
            errors.append(err)
    return None, errors[0] if errors else f"no GitHub org named {' or '.join(slugs)}", True


async def github_findings(client: httpx.AsyncClient, *, repo_url: Optional[str], github_handle: Optional[str],
                          company_name: Optional[str], official_domain: Optional[str],
                          claimed_founded_year: Optional[int], now: datetime,
                          token: Optional[str] = None) -> list[Finding]:
    """Findings for the GitHub checks whose inputs were given. Errors become unknown, never clear."""
    parsed = parse_repo_url(repo_url) if repo_url else None
    handle = normalize_handle(github_handle) if github_handle else None

    (repo, repo_err), (user, user_err) = await asyncio.gather(
        _attempt(fetch_json(client, f"/repos/{parsed[0]}/{parsed[1]}", token=token) if parsed else None),
        _attempt(fetch_json(client, f"/users/{handle}", token=token) if handle else None),
    )
    findings: list[Finding] = []

    if github_handle:
        if handle is None:
            findings.append(unknown(P5, f"{github_handle!r} isn't a GitHub username"))
        elif user_err:
            findings.append(unknown(P5, user_err))
        elif not isinstance(user, dict):
            findings.append(unknown(P5, f"there's no GitHub account named {handle}"))
        else:
            findings.append(account_age_finding(user, now))

    if repo_url:
        if parsed is None:
            why = "not a GitHub repo"
        elif repo_err:
            why = repo_err
        elif not isinstance(repo, dict):
            why = f"GitHub has no public repo {parsed[0]}/{parsed[1]} (private, renamed away or deleted)"
        else:
            why = None
        if why:
            findings += [unknown(P6, why), unknown(P7, why)]
        else:
            findings += [personal_account_finding(repo), new_or_copied_finding(repo, now)]

    org, org_err, applies = await _find_org(client, repo if isinstance(repo, dict) else None,
                                            company_name, official_domain, token)
    if org is not None:
        repos, repos_err = None, None
        if needs_repo_listing(org):
            login = org.get("login")
            repos, repos_err = await _attempt(fetch_json(
                client, f"/orgs/{login}/repos", token=token, params={"type": "public", "per_page": MAX_LISTED}))
            if not isinstance(repos, list):
                repos, repos_err = None, repos_err or f"GitHub didn't list the repos of {login}"
        tests = assessment_finding(org, repos, claimed_founded_year, why_no_repos=repos_err)
        verified = verified_finding(org, official_domain)
        owner = ((repo or {}) if isinstance(repo, dict) else {}).get("owner") or {}
        from_repo = owner.get("type") == "Organization"
        if not from_repo and verified.status != "hit" and tests.status == "hit":
            # Seen live: "Nexora Labs" matched a GitHub org created in 2025 that nothing ties to the sender.
            tests = unknown(C9_TESTS, f"the GitHub org {org.get('login')} was found by name only, and GitHub "
                                      f"doesn't tie it to the company's domain, so it may belong to someone else")
        findings += [tests, verified]
    elif applies:
        findings += [unknown(C9_TESTS, org_err), unknown(C9_VERIFIED, org_err)]
    return findings
