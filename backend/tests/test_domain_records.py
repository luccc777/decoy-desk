"""Domain records (RDAP, Wayback, DNS) and the claimed-age check, on recorded real answers."""

import asyncio
from datetime import datetime, timezone

import httpx

from app.legitimacy.company_age import claimed_age_finding
from app.legitimacy.domain_records import _txt, domain_findings, has_real_mx, parse_rdap
from app.legitimacy.http import ReplayTransport, make_client
from app.rules.engine import decide, load_table
from tests.conftest import replay


def run(domain, recording):
    client, transport = replay(recording)

    async def go():
        async with client:
            return await domain_findings(client, domain, transport.recorded_at)

    findings, facts = asyncio.run(go())
    return {f.check: f for f in findings}, facts, transport.recorded_at


def test_blocknovas_is_seized_and_has_no_mail():
    f, facts, _ = run("blocknovas.com", "domain_blocknovas")
    assert f["H4_domain_seized_or_listed"].status == "hit"
    assert "seized" in f["H4_domain_seized_or_listed"].evidence[0].summary
    assert facts.registered == datetime(2024, 7, 16, 1, 48, 55, tzinfo=timezone.utc)
    assert 800 < f["C2_domain_age"].value < 900
    assert [f[c].status for c in ("C8_no_mx", "C8_no_spf", "C8_no_dmarc")] == ["hit"] * 3


def test_coinbase_is_old_and_has_mail():
    f, facts, _ = run("coinbase.com", "domain_coinbase")
    assert f["H4_domain_seized_or_listed"].status == "clear"
    assert facts.registered.year == 2011
    assert facts.first_capture.year == 2001
    assert [f[c].status for c in ("C8_no_mx", "C8_no_spf", "C8_no_dmarc")] == ["clear"] * 3


def test_domain_without_rdap_is_unknown_not_clear():
    f, _, _ = run("softglide.co", "domain_softglide")
    assert f["C2_domain_age"].status == "unknown"
    assert f["H4_domain_seized_or_listed"].status == "unknown"
    assert f["C3_first_archive_capture_recent"].status == "clear"  # the archive still answers


def test_everything_down_is_unknown(tmp_path):
    empty = tmp_path / "empty.json"
    empty.write_text('{"recorded_at": "2026-11-06T00:00:00Z", "responses": {}}', encoding="utf-8")
    transport = ReplayTransport(empty)

    async def go():
        async with make_client(transport) as client:
            return await domain_findings(client, "example.com", transport.recorded_at)

    findings, facts = asyncio.run(go())
    assert {f.status for f in findings} == {"unknown"}
    assert len(findings) == 6
    assert facts.registered is None


def test_engine_gives_blocknovas_red_from_domain_records_alone():
    f, _, _ = run("blocknovas.com", "domain_blocknovas")
    v = decide(f.values(), {"company"}, load_table())
    assert (v.color, v.reason) == ("red", "hard_trigger")


# ---------------------------------------------------------------- pure parsing

def test_parse_rdap_reads_registration_and_nameservers():
    data = {"events": [{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
                       {"eventAction": "registration", "eventDate": "2024-07-16T01:48:55Z"}],
            "nameservers": [{"ldhName": "NS1.FBI.SEIZED.GOV."}, {"ldhName": "ns2.fbi.seized.gov"}]}
    reg = parse_rdap(data, "x.com", "https://rdap.example/x.com")
    assert reg.registered.year == 2024
    assert reg.nameservers == ["ns1.fbi.seized.gov", "ns2.fbi.seized.gov"]


def test_txt_joins_quoted_chunks_and_accepts_unquoted():
    answer = [{"type": 16, "data": '"v=spf1 include:_spf.google.com" " ~all"'},
              {"type": 16, "data": "v=DMARC1; p=reject"},
              {"type": 5, "data": "alias.example.com."}]
    assert _txt(answer) == ["v=spf1 include:_spf.google.com ~all", "v=DMARC1; p=reject"]


def test_null_mx_means_no_mail():
    assert not has_real_mx([{"type": 15, "data": "0 ."}])
    assert has_real_mx([{"type": 15, "data": "10 aspmx.l.google.com."}])
    assert not has_real_mx([])


# ---------------------------------------------------------------- C1 claimed age

NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)


def age(year, registered=None, first=None):
    return claimed_age_finding(claimed_founded_year=year, claim_quote="12 years", registered=registered,
                               first_capture=first, now=NOW)


def test_twelve_years_claimed_against_a_2024_domain_is_a_hit():
    f = age(2014, registered=datetime(2024, 7, 16, tzinfo=timezone.utc))
    assert f.status == "hit"
    assert "2014" in f.evidence[0].summary and "2024-07-16" in f.evidence[0].summary
    assert f.evidence[0].quote == "12 years"


def test_records_matching_the_claim_are_clear():
    assert age(2012, registered=datetime(2011, 7, 2, tzinfo=timezone.utc)).status == "clear"


def test_registration_wins_over_an_old_archive_from_a_previous_owner():
    f = age(2010, registered=datetime(2025, 12, 1, tzinfo=timezone.utc), first=datetime(2003, 1, 1, tzinfo=timezone.utc))
    assert f.status == "hit"


def test_archive_is_used_when_there_is_no_registration_date():
    assert age(2015, first=datetime(2024, 9, 18, tzinfo=timezone.utc)).status == "hit"


def test_brand_new_claim_has_nothing_to_contradict():
    assert age(2026, registered=datetime(2026, 10, 1, tzinfo=timezone.utc)).status == "clear"


def test_no_claim_or_no_records_is_unknown():
    assert age(None, registered=datetime(2024, 1, 1, tzinfo=timezone.utc)).status == "unknown"
    assert age(2014).status == "unknown"


def test_half_the_claimed_age_is_the_line():
    # 4 years claimed: 2.4 years of records is fine, 1.8 is not.
    assert age(2022, registered=datetime(2024, 6, 1, tzinfo=timezone.utc)).status == "clear"
    assert age(2022, registered=datetime(2025, 1, 15, tzinfo=timezone.utc)).status == "hit"
