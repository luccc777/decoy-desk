"""The recorded demo cases replay to the verdict the video shows."""

import asyncio

import pytest

from app.fixtures import FIXTURES, Replay
from app.legitimacy.collect import check_sender
from app.rules.engine import decide


def replay(name):
    if not (FIXTURES / name / "http.json").is_file():
        pytest.skip(f"{name} isn't recorded yet (scripts/record_fixture.py)")
    r = Replay(name)

    async def go():
        async with r.client() as client:
            return await check_sender(r.submission, client=client, now=r.now, complete=r.complete)

    report = asyncio.run(go())
    return report, decide(report.findings, r.submission.inputs())


def test_blocknovas_is_red_before_anything_runs():
    report, v = replay("fake_company_blocknovas")
    fired = {f.check: f for f in v.fired}
    assert v.color == "red"
    assert fired["H4_domain_seized_or_listed"].hard
    assert "seized" in fired["H4_domain_seized_or_listed"].evidence[0].summary
    assert "C1_claimed_age_contradiction" in fired
    assert "T3_work_computer_or_admin" in fired
    assert report.company_domain == "blocknovas.com"
    assert report.claims and report.claims.model_ok
