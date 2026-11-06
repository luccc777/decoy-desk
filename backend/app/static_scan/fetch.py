"""Downloads a public GitHub repo as a tarball and unpacks it safely.

Git never runs on untrusted content: no clone, no hooks, no submodules, no LFS.
codeload.github.com serves the archive without using the API quota, and the
commit it came from is in the tarball's pax header. Unpacking keeps only regular
files, inside the target folder, within size and count limits.
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path, PurePosixPath
from typing import Optional

import httpx
from pydantic import BaseModel, ConfigDict

from app.legitimacy.github_meta import parse_repo_url
from app.legitimacy.http import FetchError

CODELOAD = "https://codeload.github.com/{owner}/{repo}/tar.gz/HEAD"
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_UNPACKED_BYTES = 200 * 1024 * 1024
MAX_FILES = 10_000


class RepoTooBig(FetchError):
    """Over a size or file-count limit; the check reports it instead of unpacking."""


class FetchedRepo(BaseModel):
    model_config = ConfigDict(frozen=True)

    owner: str
    repo: str
    commit: Optional[str]
    path: str            # where it was unpacked
    files: int
    skipped_links: int   # symlinks and hard links, never unpacked

    @property
    def name(self) -> str:
        return f"{self.owner}/{self.repo}" + (f"@{self.commit[:7]}" if self.commit else "")


async def _download(client: httpx.AsyncClient, url: str) -> bytes:
    try:
        async with client.stream("GET", url) as r:
            if r.status_code == 404:
                raise FetchError("GitHub doesn't have this repo, or it's private")
            if r.status_code != 200:
                raise FetchError(f"GitHub answered HTTP {r.status_code} for the archive")
            declared = int(r.headers.get("content-length") or 0)
            if declared > MAX_ARCHIVE_BYTES:
                raise RepoTooBig(f"the repo archive is {declared // 2**20} MB, over the {MAX_ARCHIVE_BYTES // 2**20} MB limit")
            chunks, size = [], 0
            async for chunk in r.aiter_bytes():
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    raise RepoTooBig(f"the repo archive is over the {MAX_ARCHIVE_BYTES // 2**20} MB limit")
                chunks.append(chunk)
            return b"".join(chunks)
    except httpx.HTTPError as e:
        raise FetchError(f"couldn't download the repo ({type(e).__name__})") from e


def _strip_top(name: str) -> Optional[str]:
    """"repo-abc123/src/a.js" -> "src/a.js"; None for the top folder itself or anything odd."""
    parts = PurePosixPath(name).parts
    if len(parts) < 2 or name.startswith("/"):
        return None
    inner = PurePosixPath(*parts[1:])
    if any(p in ("..", "") for p in inner.parts):
        return None
    return inner.as_posix()


def unpack(data: bytes, dest: Path) -> tuple[Optional[str], int, int]:
    """Unpacks regular files only. Returns (commit, files written, links skipped)."""
    dest.mkdir(parents=True, exist_ok=True)
    written = links = total = 0
    try:
        tar = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except (tarfile.TarError, OSError, EOFError) as e:
        raise FetchError("the repo archive is damaged") from e
    with tar:
        commit = tar.pax_headers.get("comment")
        for member in tar:
            if member.issym() or member.islnk():
                links += 1
                continue
            if not member.isfile():
                continue  # folders are made as needed; devices and fifos are dropped
            rel = _strip_top(member.name)
            if rel is None:
                continue
            written += 1
            total += member.size
            if written > MAX_FILES:
                raise RepoTooBig(f"the repo has more than {MAX_FILES} files")
            if total > MAX_UNPACKED_BYTES:
                raise RepoTooBig(f"the repo unpacks to more than {MAX_UNPACKED_BYTES // 2**20} MB")
            member.name = rel
            member.mode = 0o644  # nothing unpacked is executable on this side
            tar.extract(member, dest, filter="data")
    return (commit if commit and len(commit) == 40 else None), written, links


async def download_repo(client: httpx.AsyncClient, repo_url: str, dest: Path) -> FetchedRepo:
    parsed = parse_repo_url(repo_url)
    if not parsed:
        raise FetchError("only public GitHub repos can be checked for now")
    owner, repo = parsed
    data = await _download(client, CODELOAD.format(owner=owner, repo=repo))
    commit, files, links = unpack(data, dest)
    return FetchedRepo(owner=owner, repo=repo, commit=commit, path=str(dest), files=files, skipped_links=links)
