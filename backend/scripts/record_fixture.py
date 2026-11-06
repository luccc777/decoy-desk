"""Runs a fixture live and records every HTTP answer and the model's reading, for exact replays.

Run it on the server, where the inference key lives; the mount writes the recording back to the checkout:
  docker compose run --rm -v ./backend/fixtures:/app/fixtures api python -m scripts.record_fixture fake_company_blocknovas
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from app import llm
from app.fixtures import FIXTURES
from app.legitimacy.collect import check_sender
from app.legitimacy.http import RecordingTransport, make_client
from app.rules.engine import decide
from app.schemas import Submission


async def record(name: str) -> None:
    folder = FIXTURES / name
    sub = Submission.model_validate_json((folder / "submission.json").read_text(encoding="utf-8"))
    transport = RecordingTransport(folder / "http.json")
    answers: list[dict] = []

    async def complete(**kwargs) -> dict:
        data = await llm.structured(**kwargs)
        answers.append(data)
        return data

    async with make_client(transport) as client:
        report = await check_sender(sub, client=client, now=transport.recorded_at, complete=complete,
                                    github_token=os.environ.get("GITHUB_TOKEN") or None)
    transport.save()
    if answers:
        (folder / "model.json").write_text(json.dumps(answers[0], indent=1, ensure_ascii=False) + "\n",
                                           encoding="utf-8")

    verdict = decide(report.findings, sub.inputs())
    print(f"{name}: {verdict.color.upper()} ({verdict.reason}), score {verdict.score}, "
          f"coverage {verdict.coverage:.0%}, {len(transport.responses)} HTTP answers recorded")
    for f in verdict.fired:
        print(f"  {'HARD' if f.hard else f'{f.points:+d}':>5}  {f.check}: {f.evidence[0].summary if f.evidence else ''}")
    for note in report.notes:
        print(f"  note: {note}")
    print(f"  unknown: {', '.join(verdict.unknown) or 'none'}")


if __name__ == "__main__":
    for fixture in sys.argv[1:] or ["fake_company_blocknovas"]:
        asyncio.run(record(fixture))
