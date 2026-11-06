"""Static checks for one uploaded file, read without running it.

  S7_file_type_mismatch        the name claims a document but the content is a program, or the name hides its ending
  S8_office_autorun_macro      an Office document runs macros or remote content when it opens (office.py)
  S9_archive_hides_executable  an archive or disk image holds programs or scripts, or hides them behind a password

Pure: no network, no subprocess, nothing written to disk or run.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable

from app.legitimacy.common import clear, unknown
from app.rules.engine import Evidence, Finding
from app.static_scan import archive, office
from app.static_scan.filetype import (
    DANGEROUS_FAMILIES, DECOY_EXTS, DISK_IMAGE_EXTS, DOCUMENT_EXTS, INVISIBLE, MIME_PDF, MIME_RTF, MIME_WORD_XML,
    MIME_ZIP, OOXML_KINDS, RISKY_EXTS, FileKind, a, base_name, detect_type, display_name, extensions, has_bidi,
)

__all__ = ["FileKind", "detect_type", "scan_file", "S7", "S8", "S9"]

S7 = "S7_file_type_mismatch"
S8 = office.CHECK
S9 = "S9_archive_hides_executable"
MAX_FILE_BYTES = 25 * 1024 * 1024
MANY_SPACES = 5            # this many spaces before the extension push it out of view
MAX_LISTED = 5             # archive entries named in the evidence

log = logging.getLogger(__name__)

_NAME_RISKY = RISKY_EXTS | DISK_IMAGE_EXTS
_PADDING = re.compile("([\\s" + "".join(sorted(INVISIBLE)) + "]{%d,})\\.([^.\\s]+)$" % MANY_SPACES)

# Content that makes a name honest: "report.pdf is a real PDF document".
_EXPECTED: dict[str, set[str]] = {
    "pdf": {MIME_PDF},
    "doc": {"application/msword", MIME_RTF, MIME_WORD_XML},
    "xls": {"application/vnd.ms-excel"},
    "ppt": {"application/vnd.ms-powerpoint"},
    "msg": {"application/vnd.ms-outlook"},
    "rtf": {MIME_RTF},
    "jpg": {"image/jpeg"}, "jpeg": {"image/jpeg"}, "png": {"image/png"}, "gif": {"image/gif"},
    "webp": {"image/webp"}, "bmp": {"image/bmp"}, "svg": {"image/svg+xml"}, "heic": {"image/heic"},
    "mp4": {"video/mp4"}, "m4v": {"video/mp4"}, "mov": {"video/quicktime"},
    "zip": {MIME_ZIP}, "html": {"text/html"}, "htm": {"text/html"},
}
for _ext, (_, _, _plain, _macro) in zip(("docx", "xlsx", "pptx"), OOXML_KINDS):
    _EXPECTED[_ext] = {_plain, _macro}
    _EXPECTED[_ext[:-1] + "m"] = {_macro}
_TEXT_EXTS = {"txt", "csv", "md", "log", "json", "xml"}


def scan_file(name: str, data: bytes) -> list[Finding]:
    """Exactly one finding each for S7, S8 and S9, in that order. Never raises on bad input."""
    if len(data) > MAX_FILE_BYTES:
        why = f"the file is bigger than {MAX_FILE_BYTES // (1024 * 1024)} MB"
        return [unknown(check, why) for check in (S7, S8, S9)]
    try:
        kind = detect_type(data)
    except Exception:
        log.exception("detect_type failed")
        return [unknown(check, "the scanner hit an error reading this file") for check in (S7, S8, S9)]
    return [
        _safely(S7, lambda: type_mismatch(name, data, kind)),
        _safely(S8, lambda: office.check(name, data, kind)),
        _safely(S9, lambda: archive_contents(name, data, kind)),
    ]


def _safely(check: str, run: Callable[[], Finding]) -> Finding:
    try:
        return run()
    except Exception:  # a parser bug must read as "couldn't check", never as "clear"
        log.exception("%s failed", check)
        return unknown(check, "the scanner hit an error reading this file")


# ---------------------------------------------------------------- S7

def type_mismatch(name: str, data: bytes, kind: FileKind) -> Finding:
    shown = display_name(name)
    reasons = name_tricks(name)
    exts = extensions(name)
    ext = exts[0] if exts else ""
    # A .zip that really is a zip (even a JAR or APK) is judged by what it holds: S9.
    if ext in DOCUMENT_EXTS and kind.family in DANGEROUS_FAMILIES and not (ext == "zip" and data[:2] == b"PK"):
        reasons.append(f"{shown} is really {a(kind.label)} ({kind.clue})")
    if reasons:
        return Finding(check=S7, status="hit", evidence=[Evidence(summary=r) for r in reasons])
    if kind.mime in _EXPECTED.get(ext, ()) or (ext in _TEXT_EXTS and kind.family == "text"):
        return clear(S7, f"{shown} is a real {kind.label}")
    if kind.family in DANGEROUS_FAMILIES:
        return clear(S7, f"{shown} is {a(kind.label)} and doesn't pretend to be a document; "
                         "the decoy machine will check what it does")
    is_ = "is actually" if ext in _EXPECTED or ext in _TEXT_EXTS else "is"
    if kind.family == "archive":
        return clear(S7, f"{shown} {is_} {a(kind.label)}, not a program; what it holds is checked separately")
    return clear(S7, f"{shown} {is_} {a(kind.label)}, not a program or script")


def name_tricks(name: str) -> list[str]:
    """Ways the file name hides its real ending, as evidence lines."""
    raw = base_name(name)
    shown = display_name(name)
    exts = extensions(name)
    tricks = []
    if has_bidi(raw):
        tail = f"; it really ends in .{exts[0]}" if exts else ""
        tricks.append(f"{shown} hides its real ending with an invisible right-to-left character{tail}")
    if len(exts) >= 2 and exts[0] in _NAME_RISKY and exts[1] in DECOY_EXTS:
        tricks.append(f"{shown} looks like a .{exts[1]} file but really ends in .{exts[0]}")
    m = _PADDING.search(raw.rstrip(" ."))
    if m:
        real, before = m.group(2).lower(), raw[:m.start()].rsplit(".", 1)
        if real in _NAME_RISKY or (len(before) == 2 and before[1].strip().lower() in DECOY_EXTS):
            tricks.append(f"{shown} pushes its real ending .{real} out of view with {len(m.group(1))} spaces")
    return tricks


# ---------------------------------------------------------------- S9

def archive_contents(name: str, data: bytes, kind: FileKind) -> Finding:
    listing = archive.inspect(data, kind)
    if listing is None:
        return clear(S9, "not an archive")
    noun = listing.noun
    lines = []
    if listing.encrypted:
        lines.append(f"the {noun} is password-protected, so its contents are hidden")
    lines += [f"the {noun} holds {x}" for x in listing.risky[:MAX_LISTED]]
    if len(listing.risky) > MAX_LISTED:
        lines.append(f"and {len(listing.risky) - MAX_LISTED} more programs or scripts")
    if lines:
        return Finding(check=S9, status="hit", evidence=[Evidence(summary=s) for s in lines])
    if listing.blind:
        return unknown(S9, "; ".join(listing.blind[:3]))
    if listing.office:
        return clear(S9, f"not an archive: {display_name(name)} is {a(kind.label)}, and it holds no programs or scripts")
    if noun == "compressed file":
        return clear(S9, "the compressed file doesn't hold a program or script")
    if listing.files == 0:
        return clear(S9, f"the {noun} is empty")
    if listing.files == 1:
        return clear(S9, f"the one file in the {noun} isn't a program or script")
    return clear(S9, f"none of the {listing.files} files in the {noun} is a program or script")
