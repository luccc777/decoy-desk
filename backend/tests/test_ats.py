"""Careers-board check: recorded Greenhouse, Lever and Ashby boards, and the pure matching on inline data."""

import asyncio

import httpx
import pytest

from app.legitimacy.ats import (
    NO_BOARD, NOT_ON, ON, Board, Posting, attempts, board_findings, board_tokens, job_board_findings,
    normalize_title, parse_ashby, parse_greenhouse, parse_lever, titles_match,
)
from app.legitimacy.http import FetchError, make_client
from app.rules.engine import load_table
from tests.conftest import replay


def run(client, **kwargs):
    async def go():
        async with client:
            return await job_board_findings(client, **kwargs)

    findings = asyncio.run(go())
    assert [f.check for f in findings] == [NOT_ON, ON]
    return {f.check: f for f in findings}


def recorded(name, **kwargs):
    client, _ = replay(name)
    return run(client, **kwargs)


def mocked(handler, **kwargs):
    return run(make_client(httpx.MockTransport(handler)), **kwargs)


def board(provider="Greenhouse", token="acme", titles=("Senior Software Engineer",)):
    return Board(provider=provider, token=token, url=f"https://boards.example/{token}",
                 postings=tuple(Posting(title=t, url=f"https://boards.example/{token}/{i}")
                                for i, t in enumerate(titles)))


def test_finding_ids_are_in_the_rules_table():
    assert {NOT_ON, ON} <= set(load_table().checks)


# ---------------------------------------------------------------- recorded boards

FIREBLOCKS = dict(company_name="Fireblocks", official_domain="fireblocks.com")
ONEINCH = dict(company_name="1inch", official_domain="1inch.io")
UNISWAP = dict(company_name="Uniswap Labs", official_domain="uniswap.org")


def test_greenhouse_job_that_exists():
    f = recorded("ats_greenhouse_fireblocks", **FIREBLOCKS, job_title="Full-Stack Blockchain Engineer")
    assert f[ON].status == "hit" and f[NOT_ON].status == "clear"
    ev = f[ON].evidence[0]
    assert '"Full Stack Engineer, Blockchain"' in ev.summary and "Greenhouse" in ev.summary
    assert ev.source == "https://www.fireblocks.com/careers/position?gh_jid=4695814006"


def test_greenhouse_job_that_does_not_exist():
    f = recorded("ats_greenhouse_fireblocks", **FIREBLOCKS, job_title="Senior Rust Developer")
    assert f[NOT_ON].status == "hit" and f[ON].status == "clear"
    ev = f[NOT_ON].evidence[0]
    assert ev.source == "https://job-boards.greenhouse.io/fireblocks"
    assert "among 25 open jobs" in ev.summary


def test_lever_job_that_exists():
    f = recorded("ats_lever_1inch", **ONEINCH, job_title="iOS Tech Lead")
    assert f[ON].status == "hit" and f[NOT_ON].status == "clear"
    ev = f[ON].evidence[0]
    assert '"Tech Lead, iOS"' in ev.summary and "Lever" in ev.summary
    assert ev.source.startswith("https://jobs.lever.co/1inch/")


def test_lever_job_that_does_not_exist():
    f = recorded("ats_lever_1inch", **ONEINCH, job_title="Blockchain Developer")
    assert f[NOT_ON].status == "hit" and f[ON].status == "clear"
    assert f[NOT_ON].evidence[0].source == "https://jobs.lever.co/1inch"
    assert "among 5 open jobs" in f[NOT_ON].evidence[0].summary


def test_ashby_job_that_exists():
    f = recorded("ats_ashby_uniswap", **UNISWAP, job_title="Smart Contract Engineer")
    assert f[ON].status == "hit" and f[NOT_ON].status == "clear"
    ev = f[ON].evidence[0]
    assert '"Senior Smart Contract Engineer"' in ev.summary and "Ashby" in ev.summary
    assert ev.source.startswith("https://jobs.ashbyhq.com/uniswap/")


def test_ashby_job_that_does_not_exist():
    f = recorded("ats_ashby_uniswap", **UNISWAP, job_title="Blockchain Developer")
    assert f[NOT_ON].status == "hit" and f[ON].status == "clear"
    assert f[NOT_ON].evidence[0].source == "https://jobs.ashbyhq.com/uniswap"
    assert "among 9 open jobs" in f[NOT_ON].evidence[0].summary


def test_no_board_anywhere_is_unknown():
    f = recorded("ats_no_board", company_name="BlockNovas LLC", official_domain="blocknovas.com",
                 job_title="Senior Blockchain Developer")
    for check in (NOT_ON, ON):
        assert f[check].status == "unknown"
        assert f[check].evidence[0].summary == f"Couldn't check: {NO_BOARD}"


def test_name_slug_alone_finds_the_board():
    # No official domain: "Fireblocks" still slugs to the recorded "fireblocks" token.
    client, _ = replay("ats_greenhouse_fireblocks")
    f = run(client, company_name="Fireblocks", official_domain=None, job_title="Sales Engineer")
    assert f[ON].status == "hit"


# ---------------------------------------------------------------- errors

def test_every_lookup_failing_is_unknown():
    f = mocked(lambda request: httpx.Response(503), company_name="Acme", official_domain="acme.com",
               job_title="Software Engineer")
    for check in (NOT_ON, ON):
        assert f[check].status == "unknown"
        assert "every careers-board lookup failed" in f[check].evidence[0].summary


def test_some_lookups_failing_and_the_rest_missing_is_unknown_not_clear():
    def handler(request):
        return httpx.Response(429) if request.url.host == "api.lever.co" else httpx.Response(404)

    f = mocked(handler, company_name="Acme", official_domain="acme.com", job_title="Software Engineer")
    for check in (NOT_ON, ON):
        assert f[check].status == "unknown"
        assert NO_BOARD in f[check].evidence[0].summary and "1 of 4 lookups failed" in f[check].evidence[0].summary


def test_bad_json_is_an_error_not_a_board():
    def handler(request):
        if request.url.host == "boards-api.greenhouse.io":
            return httpx.Response(200, text="<html>maintenance</html>")
        return httpx.Response(404)

    f = mocked(handler, company_name="Acme", official_domain=None, job_title="Software Engineer")
    assert f[ON].status == "unknown" and "lookups failed" in f[ON].evidence[0].summary


def test_other_4xx_is_an_error():
    f = mocked(lambda request: httpx.Response(403), company_name="Acme", official_domain=None,
               job_title="Software Engineer")
    assert f[ON].status == "unknown" and "HTTP 403" in f[ON].evidence[0].summary


def test_empty_board_counts_as_no_board():
    # Lever answers 200 [] for Kraken's old board.
    def handler(request):
        if request.url.host == "api.lever.co":
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    f = mocked(handler, company_name="Kraken", official_domain=None, job_title="Software Engineer")
    assert f[NOT_ON].status == "unknown"
    assert 'the Lever board "kraken" lists no jobs' in f[NOT_ON].evidence[0].summary


def test_a_found_board_answers_even_if_another_provider_errored():
    def handler(request):
        if request.url.host == "api.lever.co":
            return httpx.Response(200, json=[{"text": "Software Engineer", "hostedUrl": "https://jobs.lever.co/acme/1"}])
        return httpx.Response(503)

    f = mocked(handler, company_name="Acme", official_domain=None, job_title="Software Engineer")
    assert f[ON].status == "hit" and f[ON].evidence[0].source == "https://jobs.lever.co/acme/1"


def test_no_title_or_no_company_makes_no_request():
    def handler(request):
        pytest.fail("no request expected")

    for kwargs in (dict(company_name="Acme", official_domain=None, job_title="  "),
                   dict(company_name="Acme", official_domain=None, job_title="Remote"),
                   dict(company_name=None, official_domain=None, job_title="Software Engineer")):
        f = mocked(handler, **kwargs)
        assert f[NOT_ON].status == "unknown" and f[ON].status == "unknown"


# ---------------------------------------------------------------- findings from boards

def test_match_on_any_of_two_boards():
    boards = [board("Greenhouse", "acme", ["Sales Director"]), board("Ashby", "acme", ["Head of Engineering"])]
    f = {x.check: x for x in board_findings("Head of Engineering", boards, [], 6)}
    assert f[ON].status == "hit" and "Ashby" in f[ON].evidence[0].summary


def test_no_match_lists_every_board_searched():
    boards = [board("Greenhouse", "acme", ["Sales Director", "Sales Engineer"]), board("Ashby", "acme", ["CFO"])]
    f = {x.check: x for x in board_findings("Blockchain Developer", boards, [], 6)}
    assert f[NOT_ON].status == "hit" and f[ON].status == "clear"
    assert [e.source for e in f[NOT_ON].evidence] == ["https://boards.example/acme"] * 2
    assert "among 2 open jobs" in f[NOT_ON].evidence[0].summary
    assert "Searched 3 open jobs on 2 official boards" == f[ON].evidence[0].summary


def test_closest_matching_posting_is_shown():
    b = board(titles=["Senior Software Engineer, Payments", "Senior Software Engineer"])
    f = {x.check: x for x in board_findings("Senior Software Engineer", [b], [], 3)}
    assert f[ON].evidence[0].summary.endswith('as "Senior Software Engineer"')


# ---------------------------------------------------------------- title matching

@pytest.mark.parametrize("claimed, posting", [
    ("Senior Software Engineer", "Software Engineer, Senior"),
    ("Full Stack Engineer", "Full-Stack Engineer"),
    ("Fullstack Engineer", "Full Stack Engineer"),
    ("Sr. Software Engineer", "Senior Software Engineer"),
    ("Smart Contract Engineer", "Senior Smart Contract Engineer"),
    ("iOS Tech Lead", "Tech Lead, iOS"),
    ("Senior Backend Engineer (Remote)", "Senior Backend Engineer"),
    ("Product Manager – Payments", "Product Manager - Payments"),
])
def test_titles_that_match(claimed, posting):
    assert titles_match(claimed, posting)


@pytest.mark.parametrize("claimed, posting", [
    ("Blockchain Developer", "Frontend Developer"),
    ("Backend Engineer", "Frontend Engineer"),
    ("Senior Blockchain Developer", "Senior Software Engineer"),
    ("Solidity Engineer", "Security Engineer"),
    ("Remote", "Remote Software Engineer"),  # nothing significant to look for
    ("", "Software Engineer"),
])
def test_titles_that_do_not_match(claimed, posting):
    assert not titles_match(claimed, posting)


def test_normalize_title():
    assert normalize_title("  Sr. Full-Stack   Engineer, (Web3) ") == "senior full stack engineer web3"


# ---------------------------------------------------------------- tokens

def test_board_tokens():
    assert board_tokens("Coinbase, Inc.", "careers.coinbase.com") == ["coinbase"]
    assert board_tokens("Block Nova Labs", None) == ["blocknovalabs", "block-nova-labs"]
    assert board_tokens("Café Société GmbH", None) == ["cafesociete", "cafe-societe"]
    assert board_tokens("Uniswap Labs", "uniswap.org") == ["uniswap", "uniswaplabs", "uniswap-labs"]
    assert board_tokens(None, None) == []


def test_attempts_try_every_provider_and_the_whole_domain_on_ashby():
    assert attempts("Kraken", "kraken.com") == [
        ("greenhouse", "kraken"), ("lever", "kraken"), ("ashby", "kraken"), ("ashby", "kraken.com")]
    assert attempts("Kraken", None) == [("greenhouse", "kraken"), ("lever", "kraken"), ("ashby", "kraken")]


# ---------------------------------------------------------------- parsers

def test_parse_greenhouse():
    data = {"jobs": [{"title": " Senior Design Engineer", "absolute_url": "https://x/1"}, {"title": ""}],
            "meta": {"total": 2}}
    assert parse_greenhouse(data) == [Posting(title="Senior Design Engineer", url="https://x/1")]


def test_parse_lever():
    assert parse_lever([{"text": "Tech Lead, iOS", "hostedUrl": "https://jobs.lever.co/x/1"}]) == [
        Posting(title="Tech Lead, iOS", url="https://jobs.lever.co/x/1")]
    assert parse_lever([]) == []


def test_parse_ashby():
    data = {"jobs": [{"title": "Head of talent ", "jobUrl": "https://jobs.ashbyhq.com/x/1"}], "apiVersion": "1"}
    assert parse_ashby(data) == [Posting(title="Head of talent", url="https://jobs.ashbyhq.com/x/1")]


@pytest.mark.parametrize("parse, data", [
    (parse_greenhouse, {"status": 404, "error": "Job not found"}),
    (parse_greenhouse, []),
    (parse_lever, {"ok": False, "error": "Document not found"}),
    (parse_ashby, ["jobs"]),
])
def test_parsers_reject_unexpected_shapes(parse, data):
    with pytest.raises(FetchError):
        parse(data)
