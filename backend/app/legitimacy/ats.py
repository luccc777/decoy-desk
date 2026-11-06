"""Is the job on the company's official careers board? Looks on Greenhouse, Lever and Ashby.

Board tokens are guessed from the official domain ("coinbase.com" -> "coinbase")
and from the company name. Every token is tried on every provider at once, and
every board found is searched: some companies keep boards on two providers.

Answers C5_job_not_on_official_board and C5_job_on_official_board, always both.
"""

from __future__ import annotations

import asyncio
import re
import unicodedata
from difflib import SequenceMatcher
from typing import Any, Callable, NamedTuple, Optional, Union

import httpx
from pydantic import BaseModel, ConfigDict

from app.legitimacy.common import clear, hit, unknown
from app.legitimacy.domains import label, registrable
from app.legitimacy.http import FetchError, get, json_of
from app.legitimacy.resolve_official import strip_legal_suffix
from app.rules.engine import Evidence, Finding

NOT_ON = "C5_job_not_on_official_board"
ON = "C5_job_on_official_board"

NO_BOARD = "no public Greenhouse, Lever or Ashby board found"
MATCH_RATIO = 0.85

# Words that don't say which job it is.
STOPWORDS = frozenset({"a", "an", "and", "the", "of", "for", "to", "in", "at", "on", "with", "or",
                       "remote", "hybrid", "onsite"})
ABBREVIATIONS = {"sr": "senior", "snr": "senior", "jr": "junior"}


class Posting(BaseModel):
    model_config = ConfigDict(frozen=True)

    title: str
    url: Optional[str] = None


class Board(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: str          # "Greenhouse", "Lever" or "Ashby"
    token: str
    url: str               # the public board page
    postings: tuple[Posting, ...]


# ---------------------------------------------------------------- parsing

def _unexpected(provider: str) -> FetchError:
    return FetchError(f"{provider} sent an unexpected answer")


def parse_greenhouse(data: Any) -> list[Posting]:
    """{"jobs": [{"title", "absolute_url"}], "meta": {...}}"""
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, list):
        raise _unexpected("Greenhouse")
    return [Posting(title=j["title"].strip(), url=j.get("absolute_url"))
            for j in jobs if isinstance(j, dict) and isinstance(j.get("title"), str) and j["title"].strip()]


def parse_lever(data: Any) -> list[Posting]:
    """[{"text", "hostedUrl"}]"""
    if not isinstance(data, list):
        raise _unexpected("Lever")
    return [Posting(title=p["text"].strip(), url=p.get("hostedUrl"))
            for p in data if isinstance(p, dict) and isinstance(p.get("text"), str) and p["text"].strip()]


def parse_ashby(data: Any) -> list[Posting]:
    """{"jobs": [{"title", "jobUrl"}], "apiVersion": "1"}"""
    jobs = data.get("jobs") if isinstance(data, dict) else None
    if not isinstance(jobs, list):
        raise _unexpected("Ashby")
    return [Posting(title=j["title"].strip(), url=j.get("jobUrl"))
            for j in jobs if isinstance(j, dict) and isinstance(j.get("title"), str) and j["title"].strip()]


class _Provider(NamedTuple):
    name: str
    api: str      # JSON endpoint
    board: str    # public page, for evidence
    parse: Callable[[Any], list[Posting]]


PROVIDERS = {
    "greenhouse": _Provider(name="Greenhouse", api="https://boards-api.greenhouse.io/v1/boards/{token}/jobs",
                            board="https://job-boards.greenhouse.io/{token}", parse=parse_greenhouse),
    "lever": _Provider(name="Lever", api="https://api.lever.co/v0/postings/{token}?mode=json",
                       board="https://jobs.lever.co/{token}", parse=parse_lever),
    "ashby": _Provider(name="Ashby", api="https://api.ashbyhq.com/posting-api/job-board/{token}",
                       board="https://jobs.ashbyhq.com/{token}", parse=parse_ashby),
}


# ---------------------------------------------------------------- board tokens

def _ascii_words(text: str) -> list[str]:
    plain = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    return re.findall(r"[a-z0-9]+", plain.lower())


def board_tokens(company_name: Optional[str], official_domain: Optional[str]) -> list[str]:
    """"coinbase.com" -> "coinbase"; "Block Nova, Inc." -> "blocknova", "block-nova". Deduplicated, in that order."""
    tokens = []
    domain_label = label(official_domain) if official_domain else None
    if domain_label:
        tokens.append(domain_label.lower())
    words = _ascii_words(strip_legal_suffix(company_name)) if company_name else []
    if words:
        tokens += ["".join(words), "-".join(words)]
    return list(dict.fromkeys(tokens))


def attempts(company_name: Optional[str], official_domain: Optional[str]) -> list[tuple[str, str]]:
    """(provider, token) pairs to try."""
    pairs = [(p, t) for t in board_tokens(company_name, official_domain) for p in PROVIDERS]
    # Some Ashby boards are named after the whole domain: Kraken's is "kraken.com".
    domain = registrable(official_domain) if official_domain else None
    if domain:
        pairs.append(("ashby", domain))
    return list(dict.fromkeys(pairs))


# ---------------------------------------------------------------- title matching

def normalize_title(title: str) -> str:
    """Lower case, punctuation to spaces, spaces collapsed, "Sr" spelled out."""
    words = re.sub(r"[\W_]+", " ", title.casefold()).split()
    return " ".join(ABBREVIATIONS.get(w, w) for w in words)


def significant_words(title: str) -> set[str]:
    return set(normalize_title(title).split()) - STOPWORDS


def title_ratio(claimed: str, posting: str) -> float:
    return SequenceMatcher(None, normalize_title(claimed), normalize_title(posting)).ratio()


def titles_match(claimed: str, posting: str) -> bool:
    """Every significant word of the claimed title is in the posting's title, or the two are near-identical."""
    words = significant_words(claimed)
    if not words:
        return False
    if words <= set(normalize_title(posting).split()):
        return True
    return title_ratio(claimed, posting) >= MATCH_RATIO


def best_match(job_title: str, boards: list[Board]) -> Optional[tuple[Board, Posting]]:
    """The matching posting closest to the claimed title, or None."""
    matches = [(b, p) for b in boards for p in b.postings if titles_match(job_title, p.title)]
    if not matches:
        return None
    return max(matches, key=lambda bp: title_ratio(job_title, bp[1].title))


# ---------------------------------------------------------------- findings

def both_unknown(why: str) -> list[Finding]:
    return [unknown(NOT_ON, why), unknown(ON, why)]


def board_findings(job_title: str, boards: list[Board], errors: list[str], attempted: int) -> list[Finding]:
    """Both C5 findings from what the lookups returned. Empty boards count as no board."""
    live = [b for b in boards if b.postings]
    if not live:
        if errors and len(errors) == attempted:
            return both_unknown(f"every careers-board lookup failed ({errors[0]})")
        details = [f'the {b.provider} board "{b.token}" lists no jobs' for b in boards]
        if errors:
            details.append(f"{len(errors)} of {attempted} lookups failed ({errors[0]})")
        return both_unknown(NO_BOARD + (f" ({'; '.join(details)})" if details else ""))

    found = best_match(job_title, live)
    if found:
        board, posting = found
        source = posting.url or board.url
        return [
            clear(NOT_ON, f'Found "{posting.title}" on the {board.provider} board "{board.token}"', source=source),
            hit(ON, f'Listed on the {board.provider} board "{board.token}" as "{posting.title}"', source=source),
        ]

    searched = [Evidence(summary=f'No posting like "{job_title.strip()}" among {len(b.postings)} open jobs '
                                 f'on the {b.provider} board "{b.token}"', source=b.url) for b in live]
    total = sum(len(b.postings) for b in live)
    return [
        Finding(check=NOT_ON, status="hit", evidence=searched),
        clear(ON, f"Searched {total} open jobs on {len(live)} official board{'s' if len(live) > 1 else ''}"),
    ]


# ---------------------------------------------------------------- fetch

async def fetch_board(client: httpx.AsyncClient, provider: str, token: str) -> Optional[Board]:
    """The board under this token, or None when the provider has none. Raises FetchError."""
    p = PROVIDERS[provider]
    r = await get(client, p.api.format(token=token))
    # All three answer 404 for an unknown token (Greenhouse JSON or HTML, Lever JSON, Ashby plain text).
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        raise FetchError(f"{p.name} answered HTTP {r.status_code}")
    return Board(provider=p.name, token=token, url=p.board.format(token=token),
                 postings=tuple(p.parse(json_of(r))))


async def _attempt(client: httpx.AsyncClient, provider: str, token: str) -> Union[Board, None, FetchError]:
    try:
        return await fetch_board(client, provider, token)
    except FetchError as e:
        return e


async def job_board_findings(client: httpx.AsyncClient, *, company_name: Optional[str],
                             official_domain: Optional[str], job_title: str) -> list[Finding]:
    """C5_job_not_on_official_board and C5_job_on_official_board for this job."""
    if not significant_words(job_title or ""):
        return both_unknown("no job title to look for")
    pairs = attempts(company_name, official_domain)
    if not pairs:
        return both_unknown("no company name or domain to look up a careers board")
    results = await asyncio.gather(*(_attempt(client, p, t) for p, t in pairs))
    boards = [r for r in results if isinstance(r, Board)]
    errors = [str(r) for r in results if isinstance(r, FetchError)]
    return board_findings(job_title, boards, errors, len(pairs))
