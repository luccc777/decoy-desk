"""Each demo the page offers replays end to end to the color the video shows."""

import asyncio
from types import SimpleNamespace

import pytest

from app.fixtures import FIXTURES, Replay
from app.pipeline import run_check


def run_demo(name):
    if not (FIXTURES / name / "http.json").is_file():
        pytest.skip(f"{name} isn't recorded yet (scripts/record_fixture.py)")
    r = Replay(name)
    events = []
    job = SimpleNamespace(id="test", dir=FIXTURES / name,
                          emit=lambda stage, message, status="info", data=None: events.append((stage, status, data)))

    async def go():
        async with r.client() as client:
            return await run_check(job, r.submission, client=client, now=r.now, complete=r.complete,
                                   upload=r.upload(), repo_dir=r.repo_dir)

    return asyncio.run(go())


def fired(result):
    return {f["check"] for f in result["verdict"]["fired"]}


def test_the_fake_company_is_red():
    assert run_demo("fake_company_blocknovas")["verdict"]["color"] == "red"


def test_the_real_invitation_is_green_and_its_repo_is_clean():
    result = run_demo("benign_repo")
    assert result["verdict"]["color"] == "green", result["verdict"]
    assert not {c for c in fired(result) if c.startswith("S")}
    assert result["repo"]["files"] == 4


def test_the_disguised_file_is_red_because_of_the_file():
    result = run_demo("trap_file_pdf")
    assert result["verdict"]["color"] == "red"
    assert "S7_file_type_mismatch" in fired(result)
    assert result["file"]["kind"] == "Windows program"
    assert result["explanation"]["source"] == "template" and result["explanation"]["bullets"]
