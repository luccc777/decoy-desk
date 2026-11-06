"""Shared test helpers. Tests never touch the network: HTTP comes from recordings in tests/recorded/."""

from pathlib import Path

import httpx

from app.legitimacy.http import ReplayTransport, make_client

RECORDED = Path(__file__).with_name("recorded")


def replay(name: str) -> tuple[httpx.AsyncClient, ReplayTransport]:
    """A client answering from tests/recorded/<name>.json, and its transport (for .recorded_at)."""
    transport = ReplayTransport(RECORDED / f"{name}.json")
    return make_client(transport), transport
