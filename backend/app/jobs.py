"""Checks run as background jobs. Each keeps an event log that the page follows live (SSE).

A job's folder (JOBS_DIR/<id>) holds events.jsonl, written as it goes, and
job.json, written at the end, so a finished check survives a restart.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional

from pydantic import BaseModel

JOBS_DIR = Path(os.environ.get("JOBS_DIR", "/srv/decoy-desk/jobs"))
KEEP_IN_MEMORY = 200
MAX_RUNNING = int(os.environ.get("MAX_RUNNING_JOBS", "3"))

State = Literal["queued", "running", "done", "failed"]
EventStatus = Literal["running", "done", "info", "warning", "failed"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Event(BaseModel):
    seq: int
    at: str
    stage: str
    status: EventStatus
    message: str
    data: Optional[dict[str, Any]] = None


class Job:
    def __init__(self, job_id: str, kind: str, title: str, inputs: list[str], root: Path = JOBS_DIR):
        self.id, self.kind, self.title, self.inputs = job_id, kind, title, inputs
        self.created_at = _now()
        self.state: State = "queued"
        self.events: list[Event] = []
        self.result: Optional[dict[str, Any]] = None
        self.dir = root / job_id
        self._listeners: set[asyncio.Queue] = set()

    def emit(self, stage: str, message: str, status: EventStatus = "running",
             data: Optional[dict[str, Any]] = None) -> Event:
        event = Event(seq=len(self.events), at=_now(), stage=stage, status=status, message=message, data=data)
        self.events.append(event)
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            with (self.dir / "events.jsonl").open("a", encoding="utf-8") as f:
                f.write(event.model_dump_json() + "\n")
        except OSError:
            pass  # the live stream matters more than the log file
        for q in self._listeners:
            q.put_nowait(event)
        return event

    def finish(self, result: Optional[dict[str, Any]], state: State = "done") -> None:
        self.state, self.result = state, result
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            (self.dir / "job.json").write_text(json.dumps(self.snapshot(), ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass
        for q in self._listeners:
            q.put_nowait(None)

    @property
    def finished(self) -> bool:
        return self.state in ("done", "failed")

    async def follow(self) -> AsyncIterator[Event]:
        """Every event so far, then new ones as they come, until the job ends."""
        q: asyncio.Queue = asyncio.Queue()
        self._listeners.add(q)  # listen first, so nothing slips between history and live
        try:
            last = -1
            for event in list(self.events):
                last = event.seq
                yield event
            if self.finished:
                return
            while True:
                event = await q.get()
                if event is None:
                    return
                if event.seq > last:
                    last = event.seq
                    yield event
        finally:
            self._listeners.discard(q)

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "title": self.title, "state": self.state,
            "created_at": self.created_at, "inputs": self.inputs,
            "events": [e.model_dump() for e in self.events], "result": self.result,
        }

    @classmethod
    def from_disk(cls, folder: Path) -> Optional["Job"]:
        try:
            data = json.loads((folder / "job.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        job = cls(data["id"], data["kind"], data["title"], data["inputs"], root=folder.parent)
        job.created_at, job.state, job.result = data["created_at"], data["state"], data["result"]
        job.events = [Event.model_validate(e) for e in data["events"]]
        return job


Runner = Callable[[Job], Awaitable[Optional[dict[str, Any]]]]


class JobStore:
    def __init__(self, root: Path = JOBS_DIR, max_running: int = MAX_RUNNING):
        self.root = root
        self._jobs: OrderedDict[str, Job] = OrderedDict()
        self._slots = asyncio.Semaphore(max_running)
        self._tasks: set[asyncio.Task] = set()

    def get(self, job_id: str) -> Optional[Job]:
        if job_id in self._jobs:
            return self._jobs[job_id]
        if not job_id.replace("-", "").replace("_", "").isalnum():
            return None  # never let an id walk the filesystem
        return Job.from_disk(self.root / job_id)

    def start(self, kind: str, title: str, inputs: set[str], run: Runner) -> Job:
        job = Job(secrets.token_urlsafe(9), kind, title, sorted(inputs), root=self.root)
        self._jobs[job.id] = job
        while len(self._jobs) > KEEP_IN_MEMORY:
            self._jobs.popitem(last=False)
        job.emit("queued", "Waiting for a free slot", "info")
        task = asyncio.create_task(self._run(job, run))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return job

    async def _run(self, job: Job, run: Runner) -> None:
        async with self._slots:
            job.state = "running"
            try:
                result = await run(job)
            except Exception as e:  # report it on the page; never leave the job hanging
                job.emit("error", f"Something went wrong on our side ({type(e).__name__}). The check stopped.",
                         "failed")
                job.finish(None, "failed")
                return
            job.finish(result, "done")
