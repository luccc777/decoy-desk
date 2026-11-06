"""Decoy Desk API: receives checks, runs them as jobs and streams their progress.

POST /api/checks            JSON submission (conversation, company, repo link...)
POST /api/checks/upload     the same plus one file, as multipart
GET  /api/checks/{id}       state, events and verdict
GET  /api/checks/{id}/events  live progress (server-sent events)
GET  /api/demos             recorded demo cases
POST /api/demos/{name}      replays one as a normal check
"""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from pydantic import ValidationError
from sse_starlette.sse import EventSourceResponse

from app import fixtures
from app.jobs import JOBS_DIR, JobStore
from app.legitimacy.http import make_client
from app.pipeline import MAX_UPLOAD_BYTES, Upload, run_check
from app.schemas import Submission

CHECKS_PER_HOUR = int(os.environ.get("CHECKS_PER_HOUR", "20"))
DEMOS_PER_HOUR = int(os.environ.get("DEMOS_PER_HOUR", "120"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.client = make_client()
    app.state.jobs = JobStore(Path(os.environ.get("JOBS_DIR", str(JOBS_DIR))))
    yield
    await app.state.client.aclose()


app = FastAPI(title="Decoy Desk", version="0.2.0", lifespan=lifespan)

_recent: dict[str, deque] = defaultdict(deque)


def _limit(request: Request, bucket: str, per_hour: int) -> None:
    """A small per-address limit, so a public demo can't be used to burn the model budget."""
    ip = (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "?")).split(",")[0]
    hits = _recent[f"{bucket}:{ip.strip()}"]
    now = time.monotonic()
    while hits and now - hits[0] > 3600:
        hits.popleft()
    if len(hits) >= per_hour:
        raise HTTPException(429, "Too many checks from your address this hour. Try again later.")
    hits.append(now)


def _require_something(sub: Submission, has_file: bool) -> None:
    if not (sub.inputs() or has_file):
        raise HTTPException(422, "Send at least a conversation, a company, a repo link or a file.")


def _title(sub: Submission, upload: Upload | None) -> str:
    return (sub.repo_url or (upload.name if upload else None) or sub.company_name
            or (sub.conversation or "")[:60] or "Check")


def _start(request: Request, sub: Submission, upload: Upload | None = None) -> dict:
    jobs: JobStore = request.app.state.jobs
    client = request.app.state.client
    inputs = sub.inputs() | ({"file"} if upload else set())
    token = os.environ.get("GITHUB_TOKEN") or None
    job = jobs.start("check", _title(sub, upload), inputs,
                     lambda j: run_check(j, sub, client=client, upload=upload, github_token=token))
    return {"id": job.id}


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/checks", status_code=202)
async def create_check(sub: Submission, request: Request) -> dict:
    _require_something(sub, has_file=False)
    _limit(request, "check", CHECKS_PER_HOUR)
    return _start(request, sub)


@app.post("/api/checks/upload", status_code=202)
async def create_check_with_file(request: Request, file: UploadFile = File(...),
                                 submission: str = Form("{}")) -> dict:
    try:
        sub = Submission.model_validate(json.loads(submission or "{}"))
    except (ValueError, ValidationError) as e:
        raise HTTPException(422, f"The form fields aren't valid: {e}") from e
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"Files up to {MAX_UPLOAD_BYTES // 2**20} MB.")
    if not data:
        raise HTTPException(422, "The file is empty.")
    _limit(request, "check", CHECKS_PER_HOUR)
    return _start(request, sub, Upload(name=(file.filename or "upload")[:255], data=data))


@app.get("/api/checks/{job_id}")
def get_check(job_id: str, request: Request) -> dict:
    job = request.app.state.jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "No check with this id.")
    return job.snapshot()


@app.get("/api/checks/{job_id}/events")
async def check_events(job_id: str, request: Request):
    job = request.app.state.jobs.get(job_id)
    if job is None:
        raise HTTPException(404, "No check with this id.")

    async def stream():
        async for event in job.follow():
            yield {"event": "progress", "id": str(event.seq), "data": event.model_dump_json()}
        yield {"event": "end", "data": json.dumps({"state": job.state})}

    return EventSourceResponse(stream(), ping=15)


@app.get("/api/demos")
def list_demos() -> list[dict]:
    out = []
    for name in fixtures.names():
        meta = fixtures.meta(name)
        out.append({"name": name, "title": meta.get("title", name), "description": meta.get("description", "")})
    return out


@app.post("/api/demos/{name}", status_code=202)
async def run_demo(name: str, request: Request) -> dict:
    if name not in fixtures.names():
        raise HTTPException(404, "No demo with this name.")
    _limit(request, "demo", DEMOS_PER_HOUR)
    replay = fixtures.Replay(name)
    sub = replay.submission
    upload = replay.upload()
    inputs = sub.inputs() | ({"file"} if upload else set()) | ({"repo"} if replay.repo_dir else set())

    async def run(job):
        async with replay.client() as client:
            return await run_check(job, sub, client=client, now=replay.now, complete=replay.complete,
                                   upload=upload, repo_dir=replay.repo_dir)

    job = request.app.state.jobs.start("demo", fixtures.meta(name).get("title", name), inputs, run)
    return {"id": job.id}
