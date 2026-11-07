"""Receipts: one hash-chained line per verdict, so an old verdict can't be changed quietly.

Each line holds the job id, when it was decided, the rules table version, the color,
the score, the SHA-256 of the whole verdict and the hash of the line before it.
Changing any old line breaks every hash after it, and verify() says where.
Off unless RECEIPTS_FILE is set (on the VM: /srv/decoy-desk/receipts.jsonl).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Optional

GENESIS = "0" * 64
_lock = threading.Lock()


def receipts_path() -> Optional[Path]:
    value = os.environ.get("RECEIPTS_FILE")
    return Path(value) if value else None


def digest(body: Any) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _lines(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def append(path: Path, *, job_id: str, at: str, verdict: dict) -> dict:
    with _lock:
        lines = _lines(path)
        body = {"job_id": job_id, "at": at, "table_version": verdict.get("table_version"),
                "color": verdict.get("color"), "score": verdict.get("score"),
                "verdict_sha256": digest(verdict), "prev": lines[-1]["hash"] if lines else GENESIS}
        receipt = {**body, "hash": digest(body)}
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(receipt, sort_keys=True) + "\n")
        return receipt


def find(path: Path, job_id: str) -> Optional[dict]:
    return next((r for r in _lines(path) if r.get("job_id") == job_id), None)


def verify(path: Path) -> dict:
    """{"ok": True, "count": n} or {"ok": False, "broken_at": line number (1-based)}."""
    prev = GENESIS
    lines = _lines(path)
    for n, r in enumerate(lines, start=1):
        body = {k: v for k, v in r.items() if k != "hash"}
        if r.get("prev") != prev or digest(body) != r.get("hash"):
            return {"ok": False, "broken_at": n, "count": len(lines)}
        prev = r["hash"]
    return {"ok": True, "count": len(lines)}


def matches(receipt: dict, verdict: dict) -> bool:
    """True when this verdict is exactly the one the receipt was written for."""
    return receipt.get("verdict_sha256") == digest(verdict)
