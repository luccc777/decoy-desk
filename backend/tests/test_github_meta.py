"""GitHub checks: recorded real answers for the main paths, small dicts for the edge cases."""

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.legitimacy.github_meta import (
    C9_TESTS, C9_VERIFIED, P5, P6, P7, account_age_finding, assessment_finding, assessment_only,
    github_findings, is_rate_limited, looks_like_assessment, needs_repo_listing, new_or_copied_finding,
    normalize_handle, org_slugs, parse_repo_url, personal_account_finding, verified_finding, years_after_claim,
)
from app.legitimacy.http import make_client
from app.rules.engine import decide, load_table

from .conftest import replay

NOW = datetime(2026, 11, 5, 12, tzinfo=timezone.utc)
NO_INPUTS = dict(repo_url=None, github_handle=None, company_name=None, official_domain=None,
                 claimed_founded_year=None)


def iso(days_ago: float = 0, *, year: int | None = None) -> str:
    when = NOW.replace(year=year) if year else NOW - timedelta(days=days_ago)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def run(client: httpx.AsyncClient, now: datetime, **inputs) -> dict:
    async def go():
        async with client:
            return await github_findings(client, now=now, **{**NO_INPUTS, **inputs})

    findings = asyncio.run(go())
    assert len({f.check for f in findings}) == len(findings), "one finding per check"
    assert {f.check for f in findings} <= set(load_table().checks)
    return {f.check: f for f in findings}


def summaries(finding) -> str:
    return " | ".join(e.summary for e in finding.evidence)


def mock(routes: dict, seen: list | None = None) -> httpx.AsyncClient:
    """A client answering from {path: (status, json[, headers])}; anything else is a 404."""
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        status, body, *headers = routes.get(request.url.path, (404, {"message": "Not Found"}))
        return httpx.Response(status, json=body, headers=headers[0] if headers else None)

    return make_client(httpx.MockTransport(handler))


# ---------------------------------------------------------------- recorded

class TestRecorded:
    def test_repo_owned_by_a_verified_org(self):
        client, t = replay("github_org_repo")
        f = run(client, t.recorded_at, repo_url="https://github.com/pallets/flask", github_handle="davidism",
                company_name="Pallets", official_domain="palletsprojects.com", claimed_founded_year=2016)
        assert set(f) == {P5, P6, P7, C9_TESTS, C9_VERIFIED}
        assert f[P5].value > 5000
        assert f[P6].status == "clear" and "GitHub org pallets" in summaries(f[P6])
        assert f[P7].status == "clear"
        assert f[C9_TESTS].status == "clear"
        assert f[C9_VERIFIED].status == "hit" and "palletsprojects.com" in summaries(f[C9_VERIFIED])

        verdict = decide(f.values(), {"github_handle", "repo", "company"})
        assert {x.check for x in verdict.fired} == {C9_VERIFIED}

    def test_org_much_younger_than_the_claimed_founding(self):
        # Flask's repo dates from 2010, but the pallets org only from 2016: claiming 2010 trips the 2-year rule.
        client, t = replay("github_org_repo")
        f = run(client, t.recorded_at, repo_url="https://github.com/pallets/flask", claimed_founded_year=2010)
        assert f[C9_TESTS].status == "hit"
        assert "created in 2016" in summaries(f[C9_TESTS])
        assert f[C9_VERIFIED].status == "unknown"  # verified, but no official domain to compare

    def test_repo_on_a_personal_account(self):
        client, t = replay("github_personal_repo")
        f = run(client, t.recorded_at, repo_url="https://github.com/sindresorhus/awesome",
                company_name="Vercel", official_domain="vercel.com", claimed_founded_year=2015)
        assert set(f) == {P6, P7, C9_TESTS, C9_VERIFIED}
        assert f[P6].status == "hit" and "personal account sindresorhus" in summaries(f[P6])
        assert f[P7].status == "clear"
        # vercel has more than 100 public repos, so the listing is skipped (it isn't in the recording).
        assert f[C9_TESTS].status == "clear"
        assert f[C9_VERIFIED].status == "hit"

    def test_fork(self):
        client, t = replay("github_fork")
        f = run(client, t.recorded_at, repo_url="git@github.com:octocat/linguist.git", github_handle="@octocat")
        assert set(f) == {P5, P6, P7}  # a personal repo and no company: no C9
        assert f[P7].status == "hit"
        assert "near copy of github-linguist/linguist" in summaries(f[P7])
        assert f[P6].status == "hit"
        assert f[P5].status == "clear" and f[P5].value > 365

    def test_org_lookup_404_and_non_github_repo(self):
        client, t = replay("github_org_404")
        f = run(client, t.recorded_at, repo_url="https://gitlab.com/quorvex/assessment",
                github_handle="quorvex-recruiter-zz9", company_name="Quorvex Analytics",
                official_domain="quorvex-analytics.io", claimed_founded_year=2012)
        assert {c: x.status for c, x in f.items()} == dict.fromkeys([P5, P6, P7, C9_TESTS, C9_VERIFIED], "unknown")
        assert "no GitHub account named quorvex-recruiter-zz9" in summaries(f[P5])
        assert "not a GitHub repo" in summaries(f[P6])
        assert "no GitHub org named quorvex-analytics or quorvexanalytics" in summaries(f[C9_TESTS])


# ---------------------------------------------------------------- inputs

class TestInputs:
    @pytest.mark.parametrize("url", [
        "https://github.com/owner/repo",
        "https://github.com/owner/repo.git",
        "git@github.com:owner/repo.git",
        "github.com/owner/repo/tree/main/sub",
        "http://www.github.com/owner/repo/",
        "ssh://git@github.com/owner/repo.git",
        "git+https://github.com/owner/repo.git",
        "https://github.com/owner/repo?tab=readme-ov-file#setup",
    ])
    def test_repo_url_forms(self, url):
        assert parse_repo_url(url) == ("owner", "repo")

    @pytest.mark.parametrize("url", [
        "https://gitlab.com/owner/repo", "https://github.com.evil.io/owner/repo", "https://evil.io/github.com/o/r",
        "https://github.com/owner", "https://github.com/orgs/acme/repositories", "owner/repo", "", "http://[bad",
    ])
    def test_not_a_github_repo(self, url):
        assert parse_repo_url(url) is None

    @pytest.mark.parametrize("handle,login", [
        ("octocat", "octocat"), ("@octocat", "octocat"), ("https://github.com/octocat/", "octocat"),
        ("../etc/passwd", None), ("has space", None), ("", None),
    ])
    def test_handle(self, handle, login):
        assert normalize_handle(handle) == login

    def test_org_slugs(self):
        assert org_slugs("Acme Labs, Inc.", "https://www.acme.io/careers") == ["acme", "acme-labs", "acmelabs"]
        assert org_slugs("Vercel", "vercel.com") == ["vercel"]
        assert org_slugs("Société Générale S.A.", None) == ["societe-generale", "societegenerale"]
        assert org_slugs(None, None) == []


# ---------------------------------------------------------------- account and repo

class TestAccountAndRepo:
    def test_account_age_is_measured_and_banded_by_the_engine(self):
        f = account_age_finding({"login": "newbie", "created_at": iso(30)}, NOW)
        assert f.check == P5 and f.value == 30.0
        assert decide([f], {"github_handle"}).fired[0].points == 10
        assert account_age_finding({"login": "x"}, NOW).status == "unknown"

    @pytest.mark.parametrize("days,status", [(0, "hit"), (13.9, "hit"), (14, "clear"), (400, "clear")])
    def test_14_day_rule(self, days, status):
        repo = {"full_name": "acme/app", "created_at": iso(days), "fork": False}
        assert new_or_copied_finding(repo, NOW).status == status

    def test_new_fork_gives_both_reasons(self):
        repo = {"full_name": "dev/app", "created_at": iso(2), "fork": True, "parent": {"full_name": "vercel/next.js"}}
        f = new_or_copied_finding(repo, NOW)
        assert f.status == "hit" and len(f.evidence) == 2
        assert "near copy of vercel/next.js" in summaries(f)

    def test_repo_without_date(self):
        assert new_or_copied_finding({"full_name": "a/b", "fork": False}, NOW).status == "unknown"
        assert new_or_copied_finding({"full_name": "a/b", "fork": True}, NOW).status == "hit"

    @pytest.mark.parametrize("kind,status", [("User", "hit"), ("Organization", "clear"), (None, "unknown")])
    def test_owner_type(self, kind, status):
        repo = {"full_name": "acme/app", "owner": {"login": "acme", "type": kind}}
        assert personal_account_finding(repo).status == status


# ---------------------------------------------------------------- the company's org

def org(**extra) -> dict:
    return {"login": "acme", "html_url": "https://github.com/acme", "created_at": iso(year=2015),
            "public_repos": 3, "is_verified": False, "blog": "", **extra}


def repos(*names: str, fork: bool = False) -> list[dict]:
    return [{"name": n, "description": None, "fork": fork} for n in names]


NORMAL = ["api", "web", "mobile", "docs", "design-system", "infra", "sdk-python", "sdk-js", "cli"]


class TestAssessmentHeuristic:
    @pytest.mark.parametrize("name,desc,expected", [
        ("skilltest-frontend", None, True),
        ("SkillTest2", None, True),
        ("web3-task", None, True),
        ("take-home-react", None, True),
        ("Blockchain-Challenge", None, True),
        ("interview_assignment_v2", None, True),
        ("frontend", "Coding test for candidates", True),
        ("jest-test-utils", None, True),
        ("testing-library", None, False),
        ("latest-news", None, False),
        ("contest-platform", None, False),
        ("multitask", None, False),
        ("api", "Our public REST API", False),
    ])
    def test_single_repo(self, name, desc, expected):
        assert looks_like_assessment(name, desc) is expected

    def test_only_test_repos_is_a_hit(self):
        assert assessment_only(repos("skilltest-frontend"))
        f = assessment_finding(org(public_repos=1), repos("skilltest-frontend"), None)
        assert f.status == "hit" and "skilltest-frontend" in summaries(f)

    def test_real_org_with_a_test_utility_is_clear(self):
        listed = repos(*NORMAL, "jest-test-utils")
        assert not assessment_only(listed)
        assert assessment_finding(org(public_repos=len(listed)), listed, None).status == "clear"

    def test_forks_dont_hide_a_test_only_org(self):
        listed = repos("skill-test") + repos("react", "next.js", fork=True)
        assert assessment_only(listed)

    def test_needs_at_least_one_repo(self):
        assert not assessment_only([])
        assert not assessment_only(repos("react", fork=True))
        empty = org(public_repos=0)
        assert not needs_repo_listing(empty)
        assert assessment_finding(empty, None, None).status == "clear"

    def test_big_org_is_not_listed(self):
        big = org(public_repos=244)
        assert not needs_repo_listing(big)
        assert assessment_finding(big, None, None).status == "clear"

    def test_failed_listing_is_unknown(self):
        f = assessment_finding(org(), None, None, why_no_repos="GitHub rate limit reached")
        assert f.status == "unknown" and "rate limit" in summaries(f)

    def test_failed_listing_still_hits_on_age(self):
        f = assessment_finding(org(created_at=iso(year=2024)), None, 2012)
        assert f.status == "hit"


class TestTwoYearRule:
    @pytest.mark.parametrize("claimed,org_year,status", [
        (2012, 2024, "hit"),
        (2012, 2015, "hit"),     # 3 years
        (2012, 2014, "clear"),   # 2 years is not more than 2
        (2020, 2018, "clear"),   # org older than the claim
        (1998, 2011, "clear"),   # no GitHub orgs before 2010
        (1998, 2016, "hit"),
    ])
    def test_rule(self, claimed, org_year, status):
        f = assessment_finding(org(created_at=iso(year=org_year)), repos(*NORMAL), claimed)
        assert f.status == status

    def test_no_claim_no_age_check(self):
        assert years_after_claim(datetime(2024, 1, 1, tzinfo=timezone.utc), None) is None
        assert assessment_finding(org(created_at=iso(year=2026)), repos(*NORMAL), None).status == "clear"

    def test_both_reasons(self):
        f = assessment_finding(org(created_at=iso(year=2025), public_repos=1), repos("assessment"), 2012)
        assert f.status == "hit" and len(f.evidence) == 2


class TestVerifiedOrg:
    @pytest.mark.parametrize("verified,blog,official,status", [
        (True, "https://www.acme.io/", "acme.io", "hit"),
        (True, "acme.io", "https://careers.acme.io/jobs", "hit"),
        (True, "https://acme-hiring.com", "acme.io", "clear"),
        (True, "", "acme.io", "clear"),
        (False, "https://acme.io", "acme.io", "clear"),
        (True, "https://acme.io", None, "unknown"),
    ])
    def test_rule(self, verified, blog, official, status):
        assert verified_finding(org(is_verified=verified, blog=blog), official).status == status

    def test_missing_flag_is_unknown(self):
        assert verified_finding({"login": "acme"}, "acme.io").status == "unknown"


# ---------------------------------------------------------------- calls and errors

class TestCalls:
    def test_rate_limit_detection(self):
        assert is_rate_limited(403, {"X-RateLimit-Remaining": "0"}, None)
        assert is_rate_limited(403, {}, {"message": "API rate limit exceeded for 203.0.113.9."})
        assert is_rate_limited(403, {"retry-after": "60"}, {"message": "You have exceeded a secondary rate limit"})
        assert is_rate_limited(429, {}, None)
        assert not is_rate_limited(403, {"x-ratelimit-remaining": "41"}, {"message": "Forbidden"})
        assert not is_rate_limited(404, {"x-ratelimit-remaining": "0"}, None)

    def test_403_rate_limit_is_unknown_not_not_found(self):
        limited = (403, {"message": "API rate limit exceeded"}, {"x-ratelimit-remaining": "0"})
        client = mock({"/repos/acme/app": limited, "/users/dev": limited, "/orgs/acme": limited})
        f = run(client, NOW, repo_url="https://github.com/acme/app", github_handle="dev",
                company_name="Acme", official_domain="acme.io", claimed_founded_year=2012)
        assert set(f) == {P5, P6, P7, C9_TESTS, C9_VERIFIED}
        for finding in f.values():
            assert finding.status == "unknown"
            assert "rate limit" in summaries(finding)

    @pytest.mark.parametrize("status", [403, 429, 500, 502])
    def test_errors_are_unknown(self, status):
        client = mock({"/repos/acme/app": (status, {"message": "nope"})})
        f = run(client, NOW, repo_url="https://github.com/acme/app")
        assert f[P6].status == f[P7].status == "unknown"

    def test_bad_json_is_unknown(self):
        client = make_client(httpx.MockTransport(lambda r: httpx.Response(200, text="<html>")))
        f = run(client, NOW, github_handle="dev")
        assert f[P5].status == "unknown"

    def test_headers_and_token(self):
        seen: list[httpx.Request] = []
        run(mock({}, seen), NOW, github_handle="dev")
        run(mock({}, seen), NOW, github_handle="dev", token="test-token")
        anonymous, authed = seen
        assert anonymous.headers["accept"] == "application/vnd.github+json"
        assert anonymous.headers["x-github-api-version"] == "2022-11-28"
        assert "authorization" not in anonymous.headers
        assert authed.headers["authorization"] == "Bearer test-token"

    def test_only_findings_whose_inputs_exist(self):
        seen: list[httpx.Request] = []
        assert run(mock({}, seen), NOW) == {}
        assert seen == []
        user_repo = {"full_name": "dev/app", "created_at": iso(100), "fork": False,
                     "owner": {"login": "dev", "type": "User"}}
        f = run(mock({"/repos/dev/app": (200, user_repo)}), NOW, repo_url="https://github.com/dev/app")
        assert set(f) == {P6, P7}

    def test_org_owned_repo_uses_its_org_and_skips_empty_listing(self):
        seen: list[httpx.Request] = []
        org_repo = {"full_name": "acme/app", "created_at": iso(100), "fork": False,
                    "owner": {"login": "acme", "type": "Organization"}}
        routes = {"/repos/acme/app": (200, org_repo), "/orgs/acme": (200, org(public_repos=0))}
        f = run(mock(routes, seen), NOW, repo_url="https://github.com/acme/app")
        assert [r.url.path for r in seen] == ["/repos/acme/app", "/orgs/acme"]
        assert f[C9_TESTS].status == "clear"
        assert f[C9_VERIFIED].status == "clear"

    def test_test_only_org_is_listed_in_one_page(self):
        seen: list[httpx.Request] = []
        routes = {"/orgs/acme": (200, org(public_repos=2)),
                  "/orgs/acme/repos": (200, repos("skilltest-frontend", "skilltest-backend"))}
        f = run(mock(routes, seen), NOW, company_name="Acme")
        listing = seen[-1]
        assert listing.url.params["per_page"] == "100" and listing.url.params["type"] == "public"
        # Seen live: an org found by the company's name alone may be anyone's, so it can't count against them.
        assert f[C9_TESTS].status == "unknown" and "found by name only" in summaries(f[C9_TESTS])

    def test_a_guessed_org_counts_when_github_ties_it_to_the_official_domain(self):
        routes = {"/orgs/acme": (200, org(public_repos=2, is_verified=True, blog="acme.io")),
                  "/orgs/acme/repos": (200, repos("skilltest-frontend", "skilltest-backend"))}
        f = run(mock(routes), NOW, company_name="Acme", official_domain="acme.io")
        assert f[C9_VERIFIED].status == "hit" and f[C9_TESTS].status == "hit"

    def test_slug_error_then_next_slug_found(self):
        routes = {"/orgs/acme-hiring": (500, {}), "/orgs/acme": (200, org(is_verified=True, blog="acme.io"))}
        f = run(mock(routes), NOW, company_name="Acme", official_domain="acme-hiring.com")
        assert f[C9_VERIFIED].status == "clear"  # verified for acme.io, not acme-hiring.com

    def test_no_org_found_after_an_error_reports_the_error(self):
        f = run(mock({"/orgs/acme": (502, {})}), NOW, company_name="Acme")
        assert f[C9_TESTS].status == "unknown" and "HTTP 502" in summaries(f[C9_TESTS])
