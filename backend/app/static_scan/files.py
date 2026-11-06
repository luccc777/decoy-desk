"""The files of a repo as the static checks see them: read, never run."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict

MAX_TEXT_BYTES = 1_000_000  # bigger files are listed but not read
SKIP_DIRS = {".git", "node_modules"}


class RepoFiles(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str                   # e.g. "owner/repo@abc1234"
    texts: dict[str, str]       # POSIX relative path -> text, for text files up to MAX_TEXT_BYTES
    sizes: dict[str, int]       # every regular file -> size in bytes
    skipped: list[str] = []     # binary, too big, or not a regular file

    def text(self, path: str) -> str | None:
        return self.texts.get(path)

    def find(self, name: str) -> list[str]:
        """Paths whose file name equals name (case-insensitive), shortest first."""
        name = name.lower()
        return sorted((p for p in self.sizes if p.rsplit("/", 1)[-1].lower() == name), key=lambda p: (len(p), p))


def _looks_binary(head: bytes) -> bool:
    return b"\x00" in head


def load_dir(root: Path, name: str) -> RepoFiles:
    """Reads an extracted repo. Symlinks are listed as skipped and never followed."""
    texts: dict[str, str] = {}
    sizes: dict[str, int] = {}
    skipped: list[str] = []
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_symlink():
            skipped.append(rel)
            continue
        if not path.is_file():
            continue
        size = path.stat().st_size
        sizes[rel] = size
        if size > MAX_TEXT_BYTES:
            skipped.append(rel)
            continue
        data = path.read_bytes()
        if _looks_binary(data[:8192]):
            skipped.append(rel)
            continue
        texts[rel] = data.decode("utf-8", errors="replace")
    return RepoFiles(name=name, texts=texts, sizes=sizes, skipped=skipped)


def from_dict(files: dict[str, str], name: str = "test/repo") -> RepoFiles:
    """For tests: a repo from a {path: text} dict."""
    return RepoFiles(name=name, texts=dict(files), sizes={p: len(t.encode()) for p, t in files.items()})
