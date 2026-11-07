"""Receipts form a chain: any change to an old verdict is detected."""

import json

from app import receipts

V1 = {"color": "red", "score": 80, "table_version": 1, "fired": [{"check": "H4_domain_seized_or_listed"}]}
V2 = {"color": "green", "score": 0, "table_version": 1, "fired": []}


def chain(tmp_path):
    path = tmp_path / "receipts.jsonl"
    a = receipts.append(path, job_id="aaa", at="2026-11-07T10:00:00Z", verdict=V1)
    b = receipts.append(path, job_id="bbb", at="2026-11-07T10:01:00Z", verdict=V2)
    return path, a, b


def test_each_receipt_points_to_the_one_before(tmp_path):
    path, a, b = chain(tmp_path)
    assert a["prev"] == receipts.GENESIS and b["prev"] == a["hash"]
    assert receipts.verify(path) == {"ok": True, "count": 2}
    assert receipts.find(path, "bbb")["color"] == "green"
    assert receipts.find(path, "zzz") is None


def test_a_changed_color_is_caught(tmp_path):
    path, _, _ = chain(tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["color"] = "green"  # someone tries to clean up an old verdict
    path.write_text("\n".join([json.dumps(first)] + lines[1:]) + "\n", encoding="utf-8")
    assert receipts.verify(path)["broken_at"] == 1


def test_a_deleted_line_is_caught(tmp_path):
    path, _, _ = chain(tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[1] + "\n", encoding="utf-8")
    assert receipts.verify(path)["broken_at"] == 1


def test_the_receipt_matches_only_its_own_verdict(tmp_path):
    _, a, _ = chain(tmp_path)
    assert receipts.matches(a, V1)
    assert not receipts.matches(a, {**V1, "score": 10})


def test_off_without_the_setting(monkeypatch):
    monkeypatch.delenv("RECEIPTS_FILE", raising=False)
    assert receipts.receipts_path() is None


def test_the_api_wrapper_writes_one_receipt_per_check(tmp_path, monkeypatch):
    import asyncio
    from types import SimpleNamespace

    from app.main import with_receipt

    path = tmp_path / "r.jsonl"
    monkeypatch.setenv("RECEIPTS_FILE", str(path))

    async def run(job):
        return {"verdict": V1}

    result = asyncio.run(with_receipt(run)(SimpleNamespace(id="job1", created_at="2026-11-07T10:00:00Z")))
    assert result["receipt"]["hash"] == receipts.find(path, "job1")["hash"]
    assert receipts.verify(path) == {"ok": True, "count": 1}
