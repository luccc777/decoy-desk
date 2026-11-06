"""Find a company's official website on Wikidata, independently of what the sender claims.

Two calls: wbsearchentities for up to five candidates, then one wbgetentities for
their claims, labels and aliases. The first candidate that is a company or
organization, has an official website (P856) and carries the claimed name as its
label or an alias wins. "Not on Wikidata" is None, not an error.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from pydantic import BaseModel, ConfigDict

from app.legitimacy.domains import registrable
from app.legitimacy.http import FetchError, get, json_of

API = "https://www.wikidata.org/w/api.php"
SEARCH_LIMIT = 5
# "mul" holds labels that are the same in every language; newer items may have only that.
LANGUAGES = ("en", "mul")

# Compared after lower-casing and dropping dots, so "Inc.", "S.A." and "L.L.C." are covered.
LEGAL_SUFFIXES = frozenset({
    "inc", "incorporated", "llc", "ltd", "limited", "corp", "corporation", "co", "company",
    "gmbh", "ag", "sa", "sas", "sarl", "srl", "spa", "plc", "bv", "nv", "pty", "pte", "ltda",
    "llp", "lp", "oy", "ab", "se",
})

# Instance-of classes that mark a company or organization. Wikidata has thousands of
# subclasses; these are the usual ones, and ORG_PROPERTIES catches the rest.
ORG_CLASSES = frozenset({
    "Q4830453",   # business
    "Q783794",    # company
    "Q6881511",   # enterprise
    "Q891723",    # public company
    "Q1589009",   # privately held company
    "Q167037",    # corporation
    "Q18388277",  # technology company
    "Q1058914",   # software company
    "Q658255",    # subsidiary company
    "Q219577",    # holding company
    "Q2401749",   # telecommunications company
    "Q1331793",   # media company
    "Q210167",    # video game developer
    "Q25401607",  # cryptocurrency exchange
    "Q20107444",  # bitcoin exchange
    "Q3511068",   # digital currency exchanger
    "Q43229",     # organization
    "Q163740",    # nonprofit organization
    "Q79913",     # non-governmental organization
    "Q157031",    # foundation
})

# Properties only organizations carry: headquarters, industry, legal form, employees,
# stock exchange, CEO, LEI, revenue, parent organization, subsidiary.
ORG_PROPERTIES = frozenset({"P159", "P452", "P1454", "P1128", "P414", "P169", "P1278", "P2139", "P749", "P355"})

_RANK_ORDER = {"preferred": 0, "normal": 1}
_TIME_RE = re.compile(r"^\+(\d{1,4})-(\d{2})-(\d{2})T")


class OfficialSite(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    domain: str                     # registrable domain, e.g. "coinbase.com"
    website: str                    # P856 as Wikidata has it
    wikidata_id: str
    label: str
    inception: Optional[datetime] = None  # P571
    source: str                     # the Wikidata entity page


# ---------------------------------------------------------------- names

def strip_legal_suffix(name: str) -> str:
    """"Coinbase, Inc." -> "Coinbase". Only legal suffixes go: "BlockNova Labs" stays as it is."""
    words = name.replace(",", " ").split()
    while len(words) > 1 and words[-1].lower().replace(".", "") in LEGAL_SUFFIXES:
        words.pop()
    return " ".join(words)


def normalize_name(name: str) -> str:
    return strip_legal_suffix(" ".join(name.split())).casefold()


def names_of(entity: dict) -> list[str]:
    """Labels and aliases in English and "mul"."""
    names = [entity.get("labels", {}).get(lang, {}).get("value") for lang in LANGUAGES]
    for lang in LANGUAGES:
        names += [a.get("value") for a in entity.get("aliases", {}).get(lang, [])]
    return [n for n in names if isinstance(n, str) and n.strip()]


def label_of(entity: dict) -> Optional[str]:
    for lang in LANGUAGES:
        value = entity.get("labels", {}).get(lang, {}).get("value")
        if value:
            return value
    return None


# ---------------------------------------------------------------- claims

def _end_time(claim: dict) -> bool:
    return bool(claim.get("qualifiers", {}).get("P582"))


def claim_values(entity: dict, prop: str) -> list[Any]:
    """Values of a property, preferred rank first, current before ended; deprecated and empty dropped."""
    claims = [c for c in entity.get("claims", {}).get(prop, []) if c.get("rank") in _RANK_ORDER]
    claims.sort(key=lambda c: (_RANK_ORDER[c["rank"]], _end_time(c)))
    values = []
    for c in claims:
        snak = c.get("mainsnak", {})
        if snak.get("snaktype") == "value" and "datavalue" in snak:
            values.append(snak["datavalue"].get("value"))
    return values


def looks_like_org(entity: dict) -> bool:
    """A company or organization, not a band, a film or a product with the same name."""
    classes = {v.get("id") for v in claim_values(entity, "P31") if isinstance(v, dict)}
    return bool(classes & ORG_CLASSES) or any(p in entity.get("claims", {}) for p in ORG_PROPERTIES)


def parse_wikidata_time(value: Any) -> Optional[datetime]:
    """A Wikidata time value as UTC. Month and day 00 (year precision) become 1; coarser than a year is None."""
    if not isinstance(value, dict) or value.get("precision", 0) < 9:
        return None
    m = _TIME_RE.match(value.get("time") or "")
    if not m:
        return None  # BCE or past year 9999
    year, month, day = (int(g) for g in m.groups())
    try:
        return datetime(year, max(month, 1), max(day, 1), tzinfo=timezone.utc)
    except ValueError:
        return None


def website_of(entity: dict) -> Optional[tuple[str, str]]:
    """The first official website that has a registrable domain, as (url, domain)."""
    for url in claim_values(entity, "P856"):
        domain = registrable(url) if isinstance(url, str) else None
        if domain:
            return url, domain
    return None


# ---------------------------------------------------------------- API answers

def _api_error(data: Any) -> None:
    # The API reports errors (bad parameters, maxlag) with HTTP 200 and an "error" object.
    if not isinstance(data, dict):
        raise FetchError("www.wikidata.org sent an unexpected answer")
    if "error" in data:
        code = data["error"].get("code", "error") if isinstance(data["error"], dict) else "error"
        raise FetchError(f"www.wikidata.org answered with an error ({code})")


def search_ids(data: Any) -> list[str]:
    """Item IDs from a wbsearchentities answer, in Wikidata's ranking order."""
    _api_error(data)
    results = data.get("search")
    if not isinstance(results, list):
        raise FetchError("www.wikidata.org sent an unexpected answer")
    return [r["id"] for r in results if isinstance(r, dict) and isinstance(r.get("id"), str)]


def entities_of(data: Any) -> dict[str, dict]:
    """The entities of a wbgetentities answer, without the missing ones."""
    _api_error(data)
    entities = data.get("entities")
    if not isinstance(entities, dict):
        raise FetchError("www.wikidata.org sent an unexpected answer")
    return {k: v for k, v in entities.items() if isinstance(v, dict) and "missing" not in v}


def pick_official(ids: list[str], entities: dict[str, dict], company_name: str) -> Optional[OfficialSite]:
    """The first candidate, in search order, that is an organization with a website and the same name."""
    wanted = normalize_name(company_name)
    if not wanted:
        return None
    for qid in ids:
        entity = entities.get(qid)
        if not entity or not looks_like_org(entity):
            continue
        if wanted not in {normalize_name(n) for n in names_of(entity)}:
            continue
        site = website_of(entity)
        if site is None:
            continue
        inception = next(filter(None, map(parse_wikidata_time, claim_values(entity, "P571"))), None)
        return OfficialSite(domain=site[1], website=site[0], wikidata_id=qid,
                            label=label_of(entity) or company_name, inception=inception,
                            source=f"https://www.wikidata.org/wiki/{qid}")
    return None


# ---------------------------------------------------------------- fetch

async def _api(client: httpx.AsyncClient, params: dict) -> Any:
    r = await get(client, API, params={**params, "format": "json"})
    if r.status_code != 200:
        raise FetchError(f"www.wikidata.org answered HTTP {r.status_code}")
    return json_of(r)


async def resolve_official(client: httpx.AsyncClient, company_name: str) -> Optional[OfficialSite]:
    """The company's official site per Wikidata, or None when Wikidata doesn't know it. Raises FetchError."""
    query = strip_legal_suffix(" ".join((company_name or "").split()))
    if not query:
        return None
    ids = search_ids(await _api(client, {"action": "wbsearchentities", "search": query, "language": "en",
                                         "type": "item", "limit": SEARCH_LIMIT}))
    if not ids:
        return None
    entities = entities_of(await _api(client, {"action": "wbgetentities", "ids": "|".join(ids),
                                               "props": "claims|labels|aliases",
                                               "languages": "|".join(LANGUAGES)}))
    return pick_official(ids, entities, company_name)
