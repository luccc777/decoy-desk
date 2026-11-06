"""Repo download: only regular files, only inside the target folder, within limits."""

import asyncio
import io
import tarfile

import httpx
import pytest

from app.legitimacy.http import FetchError, make_client
from app.static_scan import fetch
from app.static_scan.fetch import RepoTooBig, download_repo, unpack
from app.static_scan.files import load_dir

SHA = "a" * 40


def tarball(entries, commit=SHA) -> bytes:
    """entries: (name, content bytes | None for a folder | ("sym", target) | ("hard", target))."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.PAX_FORMAT,
                      pax_headers={"comment": commit} if commit else {}) as tar:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            if content is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif isinstance(content, tuple):
                info.type = tarfile.SYMTYPE if content[0] == "sym" else tarfile.LNKTYPE
                info.linkname = content[1]
                tar.addfile(info)
            else:
                info.size = len(content)
                info.mode = 0o755
                tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


GOOD = [
    ("repo-aaa/", None),
    ("repo-aaa/package.json", b'{"name": "x"}'),
    ("repo-aaa/src/index.js", b"console.log(1)"),
]


def test_unpacks_regular_files_and_reads_the_commit(tmp_path):
    commit, files, links = unpack(tarball(GOOD), tmp_path)
    assert (commit, files, links) == (SHA, 2, 0)
    assert (tmp_path / "src" / "index.js").read_text() == "console.log(1)"
    repo = load_dir(tmp_path, "o/r")
    assert set(repo.texts) == {"package.json", "src/index.js"}


def test_links_traversal_and_absolute_paths_never_land(tmp_path):
    target = tmp_path / "out"
    evil = GOOD + [
        ("repo-aaa/../../escape.txt", b"x"),
        ("/etc/evil", b"x"),
        ("repo-aaa/link-to-home", ("sym", "/root/.ssh/id_ed25519")),
        ("repo-aaa/hard", ("hard", "/etc/passwd")),
    ]
    _, files, links = unpack(tarball(evil), target)
    assert files == 2 and links == 2
    assert not (tmp_path / "escape.txt").exists()
    assert sorted(p.relative_to(target).as_posix() for p in target.rglob("*") if p.is_file()) == \
        ["package.json", "src/index.js"]


def test_nothing_is_executable(tmp_path):
    unpack(tarball(GOOD), tmp_path)
    assert not (tmp_path / "src" / "index.js").stat().st_mode & 0o111


def test_too_many_files(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, "MAX_FILES", 1)
    with pytest.raises(RepoTooBig):
        unpack(tarball(GOOD), tmp_path)


def test_damaged_archive(tmp_path):
    with pytest.raises(FetchError):
        unpack(b"not a tarball", tmp_path)


def serve(body: bytes, status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "codeload.github.com"
        assert request.url.path == "/octo/demo/tar.gz/HEAD"
        return httpx.Response(status, content=body)
    return make_client(httpx.MockTransport(handler))


def run(client, url, dest):
    async def go():
        async with client:
            return await download_repo(client, url, dest)
    return asyncio.run(go())


def test_download_repo(tmp_path):
    got = run(serve(tarball(GOOD)), "https://github.com/octo/demo.git", tmp_path)
    assert (got.name, got.files) == (f"octo/demo@{SHA[:7]}", 2)


def test_missing_repo(tmp_path):
    with pytest.raises(FetchError, match="private"):
        run(serve(b"", status=404), "https://github.com/octo/demo", tmp_path)


def test_archive_over_the_limit_stops_downloading(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, "MAX_ARCHIVE_BYTES", 10)
    with pytest.raises(RepoTooBig):
        run(serve(tarball(GOOD)), "https://github.com/octo/demo", tmp_path)


def test_not_github(tmp_path):
    with pytest.raises(FetchError, match="GitHub"):
        run(serve(b""), "https://gitlab.com/octo/demo", tmp_path)
