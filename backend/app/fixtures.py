"""Recorded demo cases. Each folder in backend/fixtures holds a submission and everything it fetched.

  submission.json  what the user sent
  http.json        every HTTP answer, recorded by scripts/record_fixture.py
  model.json       the language model's reading of the conversation

Replaying a fixture runs the real code against the recorded answers, so the demo
shows exactly what the live run found, even if a public API is slow that day.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import httpx

from app import llm
from app.legitimacy.claims import Complete
from app.legitimacy.http import ReplayTransport, make_client
from app.schemas import Submission

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class Replay:
    def __init__(self, name: str):
        self.folder = FIXTURES / name
        if not (self.folder / "submission.json").is_file():
            raise FileNotFoundError(f"no fixture named {name}")
        self.submission = Submission.model_validate_json((self.folder / "submission.json").read_text(encoding="utf-8"))
        self.transport = ReplayTransport(self.folder / "http.json")
        self.now = self.transport.recorded_at
        model_file = self.folder / "model.json"
        self._answer: Optional[dict] = (json.loads(model_file.read_text(encoding="utf-8"))
                                        if model_file.is_file() else None)
        repo = self.folder / "repo"
        self.repo_dir: Optional[Path] = repo if repo.is_dir() else None

    def client(self) -> httpx.AsyncClient:
        return make_client(self.transport)

    def upload(self):
        """The fixture's file, if it has one (a file/ folder with exactly one file)."""
        from app.pipeline import Upload

        folder = self.folder / "file"
        files = sorted(p for p in folder.iterdir() if p.is_file()) if folder.is_dir() else []
        return Upload(name=files[0].name, data=files[0].read_bytes()) if files else None

    @property
    def complete(self) -> Complete:
        answer = self._answer

        async def recorded(**_kwargs) -> dict:
            if answer is None:
                raise llm.LLMError("no recorded model answer")
            return answer

        return recorded


def meta(name: str) -> dict:
    """Title and description for the demo list (meta.json, optional)."""
    try:
        return json.loads((FIXTURES / name / "meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def names() -> list[str]:
    return sorted(p.name for p in FIXTURES.iterdir() if (p / "submission.json").is_file()) if FIXTURES.is_dir() else []
