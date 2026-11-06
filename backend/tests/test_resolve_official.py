"""Official website from Wikidata: recorded real answers, and the pure helpers on inline entities."""

import asyncio
from datetime import datetime, timezone

import httpx
import pytest

from app.legitimacy.http import FetchError, make_client
from app.legitimacy.resolve_official import (
    claim_values, entities_of, looks_like_org, normalize_name, parse_wikidata_time, pick_official,
    resolve_official, search_ids, strip_legal_suffix,
)
from tests.conftest import replay


def resolve(recording, name):
    client, _ = replay(recording)

    async def go():
        async with client:
            return await resolve_official(client, name)

    return asyncio.run(go())


def entity(qid="Q1", *, label="Acme", aliases=(), website="https://www.acme.com/", p31="Q4830453",
           inception=None, extra_claims=None):
    claims = {}
    if p31:
        claims["P31"] = [claim({"entity-type": "item", "id": p31})]
    if website:
        claims["P856"] = [claim(website)]
    if inception:
        claims["P571"] = [claim({"time": inception, "precision": 11})]
    claims.update(extra_claims or {})
    return {"id": qid, "labels": {"en": {"language": "en", "value": label}} if label else {},
            "aliases": {"en": [{"language": "en", "value": a} for a in aliases]}, "claims": claims}


def claim(value, rank="normal", qualifiers=None):
    c = {"mainsnak": {"snaktype": "value", "datavalue": {"value": value}}, "rank": rank}
    if qualifiers:
        c["qualifiers"] = qualifiers
    return c


# ---------------------------------------------------------------- recorded

def test_coinbase_resolves_to_coinbase_com():
    site = resolve("wikidata_coinbase", "Coinbase")
    assert site.domain == "coinbase.com"
    assert site.website == "https://www.coinbase.com"
    assert site.wikidata_id == "Q16972754"
    assert site.label == "Coinbase"
    assert site.inception == datetime(2012, 6, 20, tzinfo=timezone.utc)
    assert site.source == "https://www.wikidata.org/wiki/Q16972754"


def test_legal_suffix_in_the_claimed_name_still_resolves():
    # The search goes out without the suffix, so it's the same recorded request.
    assert resolve("wikidata_coinbase", "Coinbase, Inc.").domain == "coinbase.com"


def test_unknown_company_is_none():
    assert resolve("wikidata_blocknovas", "BlockNovas") is None


def test_ambiguous_name_skips_the_band_and_picks_the_exchange():
    # Wikidata's first "Kraken" is a Colombian band with its own website.
    site = resolve("wikidata_kraken", "Kraken")
    assert site.wikidata_id == "Q22906202"
    assert site.domain == "kraken.com"
    assert site.inception == datetime(2011, 1, 1, tzinfo=timezone.utc)  # year precision only


def test_fetch_errors_raise():
    client = make_client(httpx.MockTransport(lambda request: httpx.Response(503)))

    async def go():
        async with client:
            return await resolve_official(client, "Coinbase")

    with pytest.raises(FetchError):
        asyncio.run(go())


def test_a_request_not_in_the_recording_raises():
    with pytest.raises(FetchError):
        resolve("wikidata_blocknovas", "Coinbase")


def test_empty_name_makes_no_request():
    client = make_client(httpx.MockTransport(lambda request: pytest.fail("no request expected")))
    assert asyncio.run(resolve_official(client, "   ")) is None


# ---------------------------------------------------------------- names

@pytest.mark.parametrize("name, stripped", [
    ("Coinbase, Inc.", "Coinbase"),
    ("Coinbase Inc", "Coinbase"),
    ("Acme LLC", "Acme"),
    ("Acme L.L.C.", "Acme"),
    ("Acme Co., Ltd.", "Acme"),
    ("Acme Corporation", "Acme"),
    ("Siemens AG", "Siemens"),
    ("Acme GmbH", "Acme"),
    ("Acme S.A.", "Acme"),
    ("BlockNova Labs", "BlockNova Labs"),
    ("Coinbase Global", "Coinbase Global"),
    ("Inc.", "Inc."),  # never strip the whole name
])
def test_strip_legal_suffix(name, stripped):
    assert strip_legal_suffix(name) == stripped


def test_normalize_name_ignores_case_and_spacing():
    assert normalize_name("  coinBASE ,  Inc. ") == normalize_name("Coinbase") == "coinbase"


# ---------------------------------------------------------------- picking

def test_label_match_with_website_wins():
    site = pick_official(["Q1"], {"Q1": entity(label="Acme Inc.")}, "ACME")
    assert site.domain == "acme.com" and site.label == "Acme Inc."


def test_alias_match_counts():
    entities = {"Q1": entity(label="Acme Holdings", aliases=["Acme"])}
    assert pick_official(["Q1"], entities, "Acme").wikidata_id == "Q1"


def test_extra_words_do_not_match():
    entities = {"Q1": entity(label="BlockNova", website="https://blocknova.io")}
    assert pick_official(["Q1"], entities, "BlockNova Labs") is None


def test_candidate_without_website_is_skipped():
    entities = {"Q1": entity("Q1", website=None), "Q2": entity("Q2", website="https://acme.example.org")}
    assert pick_official(["Q1", "Q2"], entities, "Acme").domain == "example.org"


def test_search_order_decides_between_two_matches():
    entities = {"Q1": entity("Q1", website="https://first.com"), "Q2": entity("Q2", website="https://second.com")}
    assert pick_official(["Q2", "Q1"], entities, "Acme").domain == "second.com"


def test_non_organization_is_skipped():
    band = entity("Q1", p31="Q215380")  # musical group
    assert pick_official(["Q1"], {"Q1": band}, "Acme") is None


def test_organization_property_is_enough_without_a_known_class():
    exchange = entity("Q1", p31="Q999999", extra_claims={"P452": [claim({"id": "Q1"})]})
    assert looks_like_org(exchange)
    assert pick_official(["Q1"], {"Q1": exchange}, "Acme") is not None


def test_mul_label_counts():
    e = entity(label=None)
    e["labels"] = {"mul": {"language": "mul", "value": "Acme"}}
    site = pick_official(["Q1"], {"Q1": e}, "Acme")
    assert site.label == "Acme"


def test_website_rank_preferred_first_deprecated_never():
    e = entity(website=None)
    e["claims"]["P856"] = [claim("https://old.com", rank="deprecated"),
                           claim("https://normal.com"),
                           claim("https://preferred.com", rank="preferred")]
    assert pick_official(["Q1"], {"Q1": e}, "Acme").domain == "preferred.com"


def test_current_website_before_one_with_an_end_date():
    e = entity(website=None)
    e["claims"]["P856"] = [claim("https://ended.com", qualifiers={"P582": [{}]}), claim("https://now.com")]
    assert pick_official(["Q1"], {"Q1": e}, "Acme").domain == "now.com"


def test_claim_values_drop_no_value_snaks():
    e = entity(website=None)
    e["claims"]["P856"] = [{"mainsnak": {"snaktype": "somevalue"}, "rank": "normal"}, claim("https://acme.com")]
    assert claim_values(e, "P856") == ["https://acme.com"]


def test_website_without_registrable_domain_is_skipped():
    entities = {"Q1": entity("Q1", website="http://localhost/"), "Q2": entity("Q2")}
    assert pick_official(["Q1", "Q2"], entities, "Acme").wikidata_id == "Q2"


def test_missing_entity_is_ignored():
    entities = entities_of({"entities": {"Q1": {"id": "Q1", "missing": ""}, "Q2": entity("Q2")}})
    assert list(entities) == ["Q2"]
    assert pick_official(["Q1", "Q2"], entities, "Acme").wikidata_id == "Q2"


def test_inception_from_p571():
    site = pick_official(["Q1"], {"Q1": entity(inception="+2012-06-20T00:00:00Z")}, "Acme")
    assert site.inception == datetime(2012, 6, 20, tzinfo=timezone.utc)


# ---------------------------------------------------------------- parsing

@pytest.mark.parametrize("value, expected", [
    ({"time": "+2012-06-20T00:00:00Z", "precision": 11}, datetime(2012, 6, 20, tzinfo=timezone.utc)),
    ({"time": "+2015-01-00T00:00:00Z", "precision": 10}, datetime(2015, 1, 1, tzinfo=timezone.utc)),
    ({"time": "+2011-00-00T00:00:00Z", "precision": 9}, datetime(2011, 1, 1, tzinfo=timezone.utc)),
    ({"time": "+1900-00-00T00:00:00Z", "precision": 7}, None),   # century: too coarse
    ({"time": "-0500-00-00T00:00:00Z", "precision": 9}, None),   # BCE
    ({"time": "garbage", "precision": 11}, None),
    ("+2012-06-20T00:00:00Z", None),
])
def test_parse_wikidata_time(value, expected):
    assert parse_wikidata_time(value) == expected


def test_search_ids_keeps_order():
    assert search_ids({"search": [{"id": "Q2"}, {"id": "Q1"}]}) == ["Q2", "Q1"]
    assert search_ids({"searchinfo": {"search": "x"}, "search": []}) == []


@pytest.mark.parametrize("data", [
    {"error": {"code": "maxlag", "info": "Waiting for a database server"}},
    {"unexpected": True},
    ["not", "a", "dict"],
])
def test_api_errors_raise(data):
    with pytest.raises(FetchError):
        search_ids(data)
    with pytest.raises(FetchError):
        entities_of(data)
