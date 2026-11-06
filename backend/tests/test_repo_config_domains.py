"""P8: outside domains in a repo's config, read without running anything."""

import asyncio
import json
from datetime import datetime, timezone

import httpx

from app.legitimacy.http import make_client
from app.legitimacy.repo_config_domains import domains_in_config, is_config_file, repo_config_finding

NOW = datetime(2026, 11, 6, tzinfo=timezone.utc)

TRAP = {
    ".env.example": "PRICE_API=https://api.getstockprice.com/v2\nDB_URL=mongodb://localhost:27017\n",
    "package.json": json.dumps({"name": "wallet-test", "homepage": "https://github.com/x/y",
                                "scripts": {"dev": "vite"}}),
    "src/config/index.js": "export const RPC = 'wss://rpc.chainstack-node.io/ws';\nimport './app.js';\n",
    "src/App.jsx": "fetch('https://ignored-because-not-config.com')",
    "node_modules/x/package.json": "https://inside-node-modules.com",
}


def rdap_transport(created: dict[str, str | None]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        domain = request.url.path.rsplit("/", 1)[-1]
        if domain not in created:
            return httpx.Response(500)
        if created[domain] is None:
            return httpx.Response(404)
        return httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": created[domain]}]})
    return httpx.MockTransport(handler)


def run(files, created):
    async def go():
        async with make_client(rdap_transport(created)) as client:
            return await repo_config_finding(client, files, NOW)
    return asyncio.run(go())


def test_finds_outside_domains_only_in_config_files():
    found = domains_in_config(TRAP)
    assert found == {"getstockprice.com": ".env.example", "chainstack-node.io": "src/config/index.js"}


def test_config_file_detection():
    assert is_config_file(".env")
    assert is_config_file("vite.config.ts")
    assert is_config_file("app/config/settings.ts")
    assert not is_config_file("src/App.jsx")
    assert not is_config_file("node_modules/pkg/package.json")


def test_a_two_day_old_api_domain_is_a_hit():
    f = run(TRAP, {"getstockprice.com": "2026-11-04T00:00:00Z", "chainstack-node.io": "2021-03-01T00:00:00Z"})
    assert f.status == "hit"
    assert "getstockprice.com" in f.evidence[0].summary and "2 days ago" in f.evidence[0].summary


def test_old_domains_are_clear():
    f = run(TRAP, {"getstockprice.com": "2015-01-01T00:00:00Z", "chainstack-node.io": "2021-03-01T00:00:00Z"})
    assert f.status == "clear"


def test_no_outside_domains_is_clear():
    assert run({"package.json": '{"name": "x"}'}, {}).status == "clear"


def test_no_answers_is_unknown():
    assert run(TRAP, {}).status == "unknown"


def test_a_brand_on_another_ending_is_not_an_imitation():
    # Seen live: Stripe's own sample README links stripe.dev and stripe.global.
    files = {"README.md": "Docs at https://stripe.dev/blog and https://stripe.global"}
    f = run(files, {"stripe.dev": "2015-01-01T00:00:00Z", "stripe.global": "2016-01-01T00:00:00Z"})
    assert f.status == "clear"


def test_a_misspelled_api_is_an_imitation():
    files = {".env": "RPC=https://mainnet.lnfura.io/v3/key"}
    f = run(files, {"lnfura.io": "2015-01-01T00:00:00Z"})
    assert f.status == "hit"
    assert "infura.io" in f.evidence[0].summary
