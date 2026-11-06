"""P8: the repo's config calls domains that are brand new or imitate well-known APIs.

In the Bybit and Slow Pisces cases the "assessment" fetched its second stage from
a domain registered days earlier (getstockprice[.]com, stockslab[.]org), named in a
config file or .env. We read the config-like files without running anything, pull
out every outside domain, and check its age on RDAP.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime
from pathlib import PurePosixPath
from typing import Optional

import httpx

from app.legitimacy.common import clear, days_since, unknown
from app.legitimacy.domain_records import fetch_registration
from app.legitimacy.domains import registrable
from app.rules.engine import Evidence, Finding

CHECK = "P8_new_domains_in_repo_config"
NEW_DAYS = 30
MAX_LOOKUPS = 8

# Domains every project mentions; checking them only costs time.
COMMON = frozenset({
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org", "npmjs.org", "npmjs.com",
    "yarnpkg.com", "pypi.org", "pythonhosted.org", "nodejs.org", "python.org", "localhost.com",
    "example.com", "example.org", "example.net", "w3.org", "schema.org", "json-schema.org", "mozilla.org",
    "google.com", "googleapis.com", "gstatic.com", "microsoft.com", "apple.com", "cloudflare.com",
    "jsdelivr.net", "unpkg.com", "cdnjs.com", "vercel.app", "vercel.com", "netlify.app", "netlify.com",
    "herokuapp.com", "shields.io", "badge.fury.io", "travis-ci.org", "travis-ci.com", "codecov.io",
    "opensource.org", "creativecommons.org", "wikipedia.org", "stackoverflow.com", "reactjs.org",
    "react.dev", "nextjs.org", "vitejs.dev", "eslint.org", "prettier.io", "typescriptlang.org",
    "docker.com", "docker.io", "readthedocs.io", "readthedocs.org", "sentry.io", "mongodb.com",
    "mongodb.net", "amazonaws.com", "azure.com", "firebaseio.com", "firebaseapp.com",
})

# Well-known APIs a fake one might imitate (checked by edit distance through the lookalike module).
WELL_KNOWN_APIS = (
    "openai.com", "anthropic.com", "infura.io", "alchemy.com", "etherscan.io", "bscscan.com",
    "coingecko.com", "coinmarketcap.com", "binance.com", "coinbase.com", "stripe.com", "paypal.com",
    "polygon.io", "alphavantage.co", "finnhub.io", "moralis.io", "quicknode.com", "chainlink.com",
    "metamask.io", "walletconnect.com", "twilio.com", "sendgrid.com", "mapbox.com", "supabase.co",
)

_CONFIG_NAMES = re.compile(
    r"^(\.env.*|package\.json|.*\.config\.(js|cjs|mjs|ts|json)|config\.(js|ts|json|ya?ml)|"
    r"settings\.(py|json)|appsettings.*\.json|.*\.(ya?ml|toml|ini|cfg)|readme.*|docker-compose.*)$",
    re.IGNORECASE)
_CONFIG_DIRS = {"config", "configs", "conf", "settings", "constants"}
_HOST = re.compile(r"(?:https?|wss?)://([A-Za-z0-9.-]+\.[A-Za-z]{2,})|\b((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b")
_SKIP_SUFFIXES = (".js", ".ts", ".json", ".md", ".py", ".lock", ".png", ".svg", ".css", ".html", ".yml", ".yaml")


def is_config_file(path: str) -> bool:
    p = PurePosixPath(path.replace("\\", "/"))
    if "node_modules" in p.parts or ".git" in p.parts:
        return False
    return bool(_CONFIG_NAMES.match(p.name)) or any(part.lower() in _CONFIG_DIRS for part in p.parts[:-1])


def domains_in_config(files: dict[str, str]) -> dict[str, str]:
    """Outside registrable domains found in config-like files, each with the first file that names it."""
    found: dict[str, str] = {}
    for path in sorted(files):
        if not is_config_file(path):
            continue
        for m in _HOST.finditer(files[path]):
            host = (m.group(1) or m.group(2) or "").lower()
            if not m.group(1) and host.endswith(_SKIP_SUFFIXES):
                continue  # "index.js", "README.md": file names, not hosts
            domain = registrable(host)
            if domain and domain not in COMMON and domain not in found:
                found[domain] = path
    return found


def _imitates(domain: str) -> Optional[str]:
    try:
        from app.legitimacy.lookalike import lookalike_reason
    except ImportError:  # the module is optional for this check
        return None
    for api in WELL_KNOWN_APIS:
        reason = lookalike_reason(domain, api)
        # A brand on another ending is usually the brand itself (stripe.dev, binance.us), so it doesn't count.
        if reason and not _TLD_SWAP.search(reason):
            return reason
    return None


_TLD_SWAP = re.compile(r"\(\.[\w.-]+ instead of \.[\w.-]+\)\s*$")


async def repo_config_finding(client: httpx.AsyncClient, files: dict[str, str], now: datetime) -> Finding:
    domains = domains_in_config(files)
    if not domains:
        return clear(CHECK, "The repo's config doesn't call any outside domain")

    flagged: list[str] = []
    for domain, path in domains.items():
        if reason := _imitates(domain):
            flagged.append(f"{path} calls {domain}: {reason}")

    to_check = list(domains)[:MAX_LOOKUPS]
    results = await asyncio.gather(*(fetch_registration(client, d) for d in to_check), return_exceptions=True)
    answered = 0
    for domain, result in zip(to_check, results):
        if isinstance(result, BaseException) or result is None or result.registered is None:
            continue
        answered += 1
        age = days_since(result.registered, now)
        if age < NEW_DAYS:
            flagged.append(f"{domains[domain]} calls {domain}, registered {age:.0f} days ago "
                           f"({result.registered:%Y-%m-%d})")

    if flagged:
        return Finding(check=CHECK, status="hit", evidence=[Evidence(summary=s) for s in flagged])
    if answered == 0:
        return unknown(CHECK, f"couldn't get registration dates for {', '.join(to_check)}")
    return clear(CHECK, f"Checked {answered} outside domain(s) in the config; none is new")
