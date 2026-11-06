"""The API end to end: a demo replays to the recorded verdict, and the limits hold."""

import time

import pytest
from fastapi.testclient import TestClient

from app import main


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("JOBS_DIR", str(tmp_path))
    main._recent.clear()
    with TestClient(main.app) as client:
        yield client


def wait_done(api, job_id, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = api.get(f"/api/checks/{job_id}").json()
        if snap["state"] in ("done", "failed"):
            return snap
        time.sleep(0.05)
    raise AssertionError("the check didn't finish")


def test_health(api):
    assert api.get("/api/health").json() == {"status": "ok"}


def test_empty_submission_is_refused(api):
    r = api.post("/api/checks", json={})
    assert r.status_code == 422
    assert "at least" in r.json()["detail"]


def test_unknown_fields_are_refused(api):
    assert api.post("/api/checks", json={"repo": "x"}).status_code == 422


def test_blocknovas_demo_replays_red(api):
    demos = {d["name"]: d for d in api.get("/api/demos").json()}
    assert demos["fake_company_blocknovas"]["title"] == "The fake company"

    job_id = api.post("/api/demos/fake_company_blocknovas").json()["id"]
    snap = wait_done(api, job_id)
    assert snap["state"] == "done"
    verdict = snap["result"]["verdict"]
    assert verdict["color"] == "red"
    assert snap["result"]["sender"]["company_domain"] == "blocknovas.com"

    warnings = [e for e in snap["events"] if e["status"] == "warning"]
    assert warnings[0]["data"]["check"] == "H4_domain_seized_or_listed"  # hard triggers first
    assert snap["events"][-1]["stage"] == "verdict"

    # The live feed of a finished check replays everything, then ends.
    with api.stream("GET", f"/api/checks/{job_id}/events") as r:
        body = "".join(r.iter_text())
    assert body.count("event: progress") == len(snap["events"])
    assert "event: end" in body


def test_unknown_ids(api):
    assert api.get("/api/checks/nope").status_code == 404
    assert api.get("/api/checks/..%2F..%2Fetc").status_code == 404
    assert api.post("/api/demos/nope").status_code == 404


def test_finished_checks_survive_a_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("JOBS_DIR", str(tmp_path))
    with TestClient(main.app) as first:
        job_id = first.post("/api/demos/fake_company_blocknovas").json()["id"]
        color = wait_done(first, job_id)["result"]["verdict"]["color"]
    with TestClient(main.app) as second:
        assert second.get(f"/api/checks/{job_id}").json()["result"]["verdict"]["color"] == color


def test_rate_limit(api, monkeypatch):
    async def fake_run(job, sub, **kwargs):
        return {"verdict": None}

    monkeypatch.setattr(main, "run_check", fake_run)
    monkeypatch.setattr(main, "CHECKS_PER_HOUR", 2)
    body = {"conversation": "hello there, please run our repo"}
    assert api.post("/api/checks", json=body).status_code == 202
    assert api.post("/api/checks", json=body).status_code == 202
    assert api.post("/api/checks", json=body).status_code == 429


def test_upload_limits(api, monkeypatch):
    async def fake_run(job, sub, **kwargs):
        return {"file": kwargs["upload"].name}

    monkeypatch.setattr(main, "run_check", fake_run)
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 10)
    assert api.post("/api/checks/upload", files={"file": ("a.pdf", b"x" * 11)}).status_code == 413
    assert api.post("/api/checks/upload", files={"file": ("a.pdf", b"")}).status_code == 422
    r = api.post("/api/checks/upload", files={"file": ("a.pdf", b"%PDF-1.4")},
                 data={"submission": '{"company_name": "Acme"}'})
    assert r.status_code == 202
    assert wait_done(api, r.json()["id"])["result"] == {"file": "a.pdf"}
    bad = api.post("/api/checks/upload", files={"file": ("a.pdf", b"%PDF")}, data={"submission": '{"nope": 1}'})
    assert bad.status_code == 422
