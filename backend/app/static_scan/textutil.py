"""Shared helpers for the repo checks: which files to read, short quotes, and the final finding."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable
from typing import Optional

from app.legitimacy.common import unknown
from app.rules.engine import Evidence, Finding
from app.static_scan.files import MAX_TEXT_BYTES, RepoFiles

# Files that hold code someone could run.
SOURCE_EXTS = frozenset({
    ".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx", ".vue", ".svelte",
    ".py", ".sh", ".bash", ".zsh", ".command", ".ps1", ".psm1", ".bat", ".cmd",
    ".vbs", ".jse", ".wsf", ".hta",  # Windows Script Host, common in mailed attachments
})

# Build output and vendored copies: minified, so only the strong obfuscation signals count there.
BUNDLE_DIRS = frozenset({"dist", "build", "out", "vendor", "vendors", ".next", ".nuxt", ".output", ".svelte-kit"})
_BUNDLE_NAME = re.compile(r"[.-](?:min|bundle|chunk|prod|production)\.[cm]?js$", re.IGNORECASE)

MAX_QUOTE = 200
MAX_EVIDENCE = 6

_LONG_SPACE = re.compile(r"[ \t]{8,}")


def ext(path: str) -> str:
    name = path.rsplit("/", 1)[-1]
    dot = name.rfind(".")
    return name[dot:].lower() if dot > 0 else ""


def is_source(path: str, text: Optional[str] = None) -> bool:
    """Code that can run: by extension, or any file starting with a #! line.

    TypeScript declaration files (.d.ts) only describe types, so they don't count.
    """
    if path.lower().endswith((".d.ts", ".d.mts", ".d.cts")):
        return False
    return ext(path) in SOURCE_EXTS or (text is not None and text.startswith("#!"))


def is_bundle(path: str, text: Optional[str] = None) -> bool:
    """Minified or vendored code: by folder or name, or a big file made of very long lines."""
    parts = path.lower().split("/")
    if any(p in BUNDLE_DIRS for p in parts[:-1]) or _BUNDLE_NAME.search(parts[-1]):
        return True
    if text is not None and len(text) >= 20_000 and ext(path) in {".js", ".cjs", ".mjs"}:
        return len(text) / (text.count("\n") + 1) >= 400
    return False


def shorten(text: str, limit: int = MAX_QUOTE) -> str:
    """One readable line: long runs of spaces squeezed, cut to about limit characters."""
    text = _LONG_SPACE.sub(" … ", text.strip())
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def line_number(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def excerpt(text: str, start: int, end: Optional[int] = None, limit: int = MAX_QUOTE) -> str:
    """The line around a match; on a long (minified) line, a window around the match."""
    end = start if end is None else end
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end < 0 else line_end
    if line_end - line_start > limit * 2:
        line_start = max(line_start, start - limit // 3)
        line_end = min(line_end, max(end, start + limit))
    return shorten(text[line_start:line_end], limit)


def resolve(base_dir: str, target: str) -> Optional[str]:
    """A repo-relative POSIX path for target as seen from base_dir; None if it leaves the repo."""
    target = target.strip().strip("'\"").replace("\\", "/")
    if not target or target.startswith(("/", "~", "$")) or "://" in target:
        return None
    path = posixpath.normpath(posixpath.join(base_dir, target)) if base_dir else posixpath.normpath(target)
    if path == "." or path.startswith("../") or path == "..":
        return None
    return path


def dir_of(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def why_unread(files: RepoFiles, path: str) -> str:
    size = files.sizes.get(path)
    if size is None:
        return f"{path} (not a regular file)"
    if size > MAX_TEXT_BYTES:
        return f"{path} ({size / 1_000_000:.1f} MB, too big to read)"
    return f"{path} (not a text file)"


def unread_sources(files: RepoFiles) -> list[str]:
    """Skipped source files outside build output: code we couldn't look at."""
    return [p for p in files.skipped if is_source(p) and not is_bundle(p)]


def capped(evidence: list[Evidence]) -> list[Evidence]:
    if len(evidence) <= MAX_EVIDENCE:
        return evidence
    extra = len(evidence) - (MAX_EVIDENCE - 1)
    return evidence[: MAX_EVIDENCE - 1] + [Evidence(summary=f"…and {extra} more like these")]


def conclude(check: str, hits: list[Evidence], clear_summary: str, unread: Iterable[str] = (),
             files: Optional[RepoFiles] = None, notes: Iterable[str] = ()) -> Finding:
    """hit if anything was found, unknown if a relevant file couldn't be read, clear otherwise."""
    if hits:
        return Finding(check=check, status="hit", evidence=capped(hits))
    unread = list(dict.fromkeys(unread))
    if unread:
        shown = [why_unread(files, p) if files else p for p in unread[:3]]
        more = f" and {len(unread) - 3} more" if len(unread) > 3 else ""
        return unknown(check, "couldn't read " + ", ".join(shown) + more)
    evidence = [Evidence(summary=clear_summary)] + [Evidence(summary=n) for n in notes]
    return Finding(check=check, status="clear", evidence=evidence[:MAX_EVIDENCE])
