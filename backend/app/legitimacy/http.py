"""Shared HTTP for the legitimacy layer: short timeouts, a 24 h cache, record and replay.

Every collector takes an httpx.AsyncClient. Live, that client talks to the real
public APIs. In tests and in the recorded demo, the same client runs on
ReplayTransport, which answers from a JSON file of recorded responses. The code
path is identical, and the demo can't break because a public API is slow.

Errors never become "ok": a timeout, a 5xx or a rate limit raises FetchError,
and the collector turns that into an "unknown" finding.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import httpx

USER_AGENT = "DecoyDesk/0.1 (+https://github.com/luccc777/decoy-desk)"
TIMEOUT = httpx.Timeout(8.0, connect=5.0)
CACHE_TTL_SECONDS = 24 * 3600

_DROP_HEADERS = {"content-encoding", "content-length", "transfer-encoding"}


class FetchError(Exception):
    """The source couldn't be reached, or answered with a server error or a rate limit."""


def request_key(request: httpx.Request) -> str:
    """Method and URL with sorted query parameters. Auth headers are not part of the key."""
    url = request.url
    base = str(url).split("?", 1)[0]
    query = sorted(url.params.multi_items())
    return f"{request.method} {base}" + ("?" + str(httpx.QueryParams(query)) if query else "")


def _plain_headers(headers: httpx.Headers) -> list[tuple[str, str]]:
    # The body we hand back is already decoded, so encoding and length headers would lie.
    return [(k, v) for k, v in headers.items() if k.lower() not in _DROP_HEADERS]


class ReplayTransport(httpx.AsyncBaseTransport):
    """Answers only from a recording. A request that wasn't recorded fails like a network error."""

    def __init__(self, path: Path | str):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        self.recorded_at = datetime.fromisoformat(data["recorded_at"].replace("Z", "+00:00"))
        self.responses: dict[str, dict] = data["responses"]

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        key = request_key(request)
        rec = self.responses.get(key)
        if rec is None:
            raise httpx.ConnectError(f"not in the recording: {key}", request=request)
        headers = {"content-type": rec.get("content_type") or "application/json"}
        if rec.get("location"):
            headers["location"] = rec["location"]
        return httpx.Response(rec["status"], headers=headers, content=rec["body"].encode("utf-8"), request=request)


class RecordingTransport(httpx.AsyncBaseTransport):
    """Makes real requests and keeps every response, so a run can be replayed later."""

    def __init__(self, path: Path | str, inner: Optional[httpx.AsyncBaseTransport] = None):
        self.path = Path(path)
        self.inner = inner or httpx.AsyncHTTPTransport(retries=1)
        self.recorded_at = datetime.now(timezone.utc).replace(microsecond=0)
        self.responses: dict[str, dict] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.handle_async_request(request)
        body = await response.aread()
        self.responses[request_key(request)] = {
            "status": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "location": response.headers.get("location"),
            "body": body.decode("utf-8", "replace"),
        }
        return httpx.Response(response.status_code, headers=_plain_headers(response.headers),
                              content=body, request=request)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        data = {"recorded_at": self.recorded_at.isoformat().replace("+00:00", "Z"),
                "responses": dict(sorted(self.responses.items()))}
        self.path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    async def aclose(self) -> None:
        await self.inner.aclose()


class CachingTransport(httpx.AsyncBaseTransport):
    """Keeps good GET answers for 24 h, so a second check of the same company is instant."""

    def __init__(self, inner: httpx.AsyncBaseTransport, ttl: float = CACHE_TTL_SECONDS):
        self.inner, self.ttl = inner, ttl
        self._cache: dict[str, tuple[float, int, list[tuple[str, str]], bytes]] = {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        key = request_key(request)
        cached = self._cache.get(key) if request.method == "GET" else None
        if cached and cached[0] > time.monotonic():
            _, status, headers, body = cached
            return httpx.Response(status, headers=headers, content=body, request=request)
        response = await self.inner.handle_async_request(request)
        body = await response.aread()
        headers = _plain_headers(response.headers)
        if request.method == "GET" and response.status_code < 500 and response.status_code != 429:
            self._cache[key] = (time.monotonic() + self.ttl, response.status_code, headers, body)
        return httpx.Response(response.status_code, headers=headers, content=body, request=request)

    async def aclose(self) -> None:
        await self.inner.aclose()


def make_client(transport: Optional[httpx.AsyncBaseTransport] = None) -> httpx.AsyncClient:
    """A client for the collectors. Without a transport it goes live, through the cache."""
    return httpx.AsyncClient(
        transport=transport or CachingTransport(httpx.AsyncHTTPTransport(retries=1)),
        timeout=TIMEOUT,
        follow_redirects=True,
        headers={"user-agent": USER_AGENT},
    )


async def get(client: httpx.AsyncClient, url: str, *, params: Optional[dict] = None,
              headers: Optional[dict] = None) -> httpx.Response:
    """GET that raises FetchError for anything that means "we don't know"; 4xx comes back as is."""
    host = httpx.URL(url).host
    try:
        r = await client.get(url, params=params, headers=headers)
    except httpx.HTTPError as e:
        raise FetchError(f"couldn't reach {host} ({type(e).__name__})") from e
    if r.status_code == 429 or r.status_code >= 500:
        raise FetchError(f"{host} answered HTTP {r.status_code}")
    return r


def json_of(r: httpx.Response) -> Any:
    try:
        return r.json()
    except ValueError as e:
        raise FetchError(f"{r.url.host} sent something that isn't JSON") from e
