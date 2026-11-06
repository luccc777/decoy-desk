"""What an archive or disk image holds, listed without extracting anything (S9).

Nothing is written out. At most HEAD_BYTES of an entry are decompressed to see
what it really is, entries that look like zip bombs are not opened at all, and
declared sizes are only used to refuse work, never trusted to bound a read.
"""

from __future__ import annotations

import bz2
import io
import lzma
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Optional

from app.static_scan.filetype import (
    DANGEROUS_FAMILIES, MAX_ZIP_ENTRIES, MIME_BZIP2, MIME_CAB, MIME_GZIP, MIME_ISO, MIME_TAR, MIME_XZ, FileKind, a,
    detect_type, display_name, name_risk, zip_entry_count,
)

MAX_ENTRIES = MAX_ZIP_ENTRIES
HEAD_BYTES = 4096
MAX_ENTRY_SIZE = 100 * 1024 * 1024
MAX_RATIO = 100
RATIO_FLOOR = 1024 * 1024        # small runs of zeros compress 1000:1 and are harmless to peek at
NESTED_MAX = 25 * 1024 * 1024    # a zip inside the zip is read whole up to this size, one level deep
UNPACK_MAX = 32 * 1024 * 1024    # a .gz/.bz2/.xz is unpacked in memory up to this size
TOTAL_BUDGET = 64 * 1024 * 1024  # decompressed bytes read for one upload, nested archives included


@dataclass
class Listing:
    """What an archive holds, as short phrases for the evidence card."""
    noun: str                                           # "archive", "disk image" or "compressed file"
    files: int = 0                                      # entries looked at
    risky: list[str] = field(default_factory=list)      # "setup.exe (a Windows program)"
    encrypted: list[str] = field(default_factory=list)  # entries behind a password
    blind: list[str] = field(default_factory=list)      # why part of it couldn't be checked
    office: bool = False                                # an Office Open XML package, not a user archive


class _Budget:
    def __init__(self, total: int = TOTAL_BUDGET):
        self.left = total

    def take(self, n: int) -> bool:
        if n > self.left:
            return False
        self.left -= n
        return True


def _u16(d: bytes, off: int) -> int:
    return int.from_bytes(d[off:off + 2], "little")


def _u32(d: bytes, off: int) -> int:
    return int.from_bytes(d[off:off + 4], "little")


def inspect(data: bytes, kind: FileKind) -> Optional[Listing]:
    """Lists the archive or disk image in data; None when it isn't one."""
    budget = _Budget()
    if data[:2] == b"PK":
        return _zip(data, depth=0, budget=budget)
    if kind.mime == MIME_TAR:
        return _tar(data)
    if kind.mime == MIME_CAB:
        return _cab(data)
    if kind.mime == MIME_ISO:
        return _iso(data)
    if kind.mime in (MIME_GZIP, MIME_BZIP2, MIME_XZ):
        return _compressed(data, kind, budget)
    if kind.family in ("archive", "disk_image"):
        noun = "disk image" if kind.family == "disk_image" else "archive"
        return Listing(noun=noun, blind=[f"can't list {a(kind.label)} here; the decoy machine will open it"])
    return None


def zip_guard(data: bytes) -> Optional[str]:
    """Why a zip isn't safe to hand to a parser that reads whole entries, or None when it is."""
    n = zip_entry_count(data)
    if n > MAX_ENTRIES:
        return f"it has {n:,} parts, more than the {MAX_ENTRIES:,} we check"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                reason = _bomb_reason(info)
                if reason:
                    return f"{display_name(info.filename, keep_path=True)} is {reason}"
    except Exception:
        return "the file is damaged"
    return None


def _bomb_reason(info: zipfile.ZipInfo) -> Optional[str]:
    if info.file_size > MAX_ENTRY_SIZE:
        return "too big to look inside safely"
    if info.file_size > RATIO_FLOOR and info.file_size > MAX_RATIO * max(info.compress_size, 1):
        return "compressed so much it could be a zip bomb, so we didn't open it"
    return None


def _judge_head(head: bytes, shown: str, out: Listing) -> FileKind:
    """Flags an entry whose first bytes are a program, script or shortcut."""
    kind = detect_type(head)
    # Inside an Office package, text parts are XML that can quote anything; only binaries count there.
    flagged = {"executable", "shortcut"} if out.office else DANGEROUS_FAMILIES
    if kind.family in flagged:
        out.risky.append(f"{shown}, which is really {a(kind.label)} ({kind.clue})")
    elif not out.office and kind.family == "archive" and head[:2] != b"PK":
        out.blind.append(f"{shown} is {a(kind.label)} we can't look inside")
    return kind


# ---------------------------------------------------------------- zip

def _zip(data: bytes, *, depth: int, budget: _Budget) -> Listing:
    out = Listing(noun="archive")
    n = zip_entry_count(data)
    if n > MAX_ENTRIES:
        out.blind.append(f"the archive lists {n:,} files, more than the {MAX_ENTRIES:,} we check")
        return out
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        out.blind.append("the archive is damaged and can't be listed")
        return out
    with zf:
        infos = zf.infolist()
        names = {i.filename.lower() for i in infos}
        out.office = "[content_types].xml" in names and any(x.startswith(("word/", "xl/", "ppt/")) for x in names)
        if len(infos) > MAX_ENTRIES:
            out.blind.append(f"the archive has more than {MAX_ENTRIES:,} files; we only checked the first {MAX_ENTRIES:,}")
        for info in infos[:MAX_ENTRIES]:
            if not info.is_dir():
                out.files += 1
                _zip_entry(zf, info, out, depth, budget)
    return out


def _zip_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo, out: Listing, depth: int, budget: _Budget) -> None:
    shown = display_name(info.filename, keep_path=True)
    risk = name_risk(info.filename)
    if risk:
        out.risky.append(f"{shown} ({risk})")
    if info.flag_bits & 0x1:  # encrypted: ZipCrypto and WinZip AES both set bit 0
        out.encrypted.append(shown)
        return
    if risk:
        return
    refused = _bomb_reason(info)
    if refused:
        out.blind.append(f"{shown} is {refused}")
        return
    try:
        with zf.open(info) as f:
            head = f.read(HEAD_BYTES)
    except Exception:
        out.blind.append(f"{shown} couldn't be read")
        return
    _judge_head(head, shown, out)
    if depth == 0 and head[:4] == b"PK\x03\x04":
        _nested_zip(zf, info, shown, out, budget)


def _nested_zip(zf: zipfile.ZipFile, info: zipfile.ZipInfo, shown: str, out: Listing, budget: _Budget) -> None:
    if info.file_size > NESTED_MAX or not budget.take(info.file_size):
        out.blind.append(f"{shown} is an archive too big to look inside here")
        return
    try:
        with zf.open(info) as f:
            inner = f.read(NESTED_MAX + 1)  # zipfile stops at the declared size, which we capped above
    except Exception:
        out.blind.append(f"{shown} couldn't be read")
        return
    sub = _zip(inner, depth=1, budget=budget)
    out.risky += [f"{x} inside {shown}" for x in sub.risky]
    out.encrypted += [f"{x} inside {shown}" for x in sub.encrypted]
    out.blind += [f"inside {shown}, {x}" for x in sub.blind]


# ---------------------------------------------------------------- tar, CAB, ISO 9660, gzip/bzip2/xz

def _tar(data: bytes) -> Listing:
    out = Listing(noun="archive")
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            for member in tf:  # reads headers only; nothing is extracted
                if not member.isfile():
                    continue
                if out.files >= MAX_ENTRIES:
                    out.blind.append(f"the archive has more than {MAX_ENTRIES:,} files; we only checked the first {MAX_ENTRIES:,}")
                    break
                out.files += 1
                shown = display_name(member.name, keep_path=True)
                risk = name_risk(member.name)
                if risk:
                    out.risky.append(f"{shown} ({risk})")
                    continue
                start = member.offset_data
                _judge_head(data[start:start + min(member.size, HEAD_BYTES)], shown, out)
    except Exception:
        out.blind.append("the archive is damaged and can't be listed")
    return out


def _cab(data: bytes) -> Listing:
    """File names from the CFFILE records; the contents are MSZIP/LZX compressed, which we don't unpack."""
    out = Listing(noun="archive")
    if len(data) < 36:
        out.blind.append("the CAB archive is damaged and can't be listed")
        return out
    pos, count = _u32(data, 16), _u16(data, 28)
    for _ in range(min(count, MAX_ENTRIES)):
        end = data.find(b"\0", pos + 16, pos + 16 + 1024)
        if end < 0:
            out.blind.append("the CAB archive is damaged and can't be fully listed")
            break
        utf8 = _u16(data, pos + 14) & 0x80
        name = data[pos + 16:end].decode("utf-8" if utf8 else "cp1252", errors="replace")
        pos = end + 1
        out.files += 1
        risk = name_risk(name)
        if risk:
            out.risky.append(f"{display_name(name, keep_path=True)} ({risk})")
    if count > MAX_ENTRIES:
        out.blind.append(f"the archive has more than {MAX_ENTRIES:,} files; we only checked the first {MAX_ENTRIES:,}")
    out.blind.append("the files in a CAB archive are compressed in a way we can't read here, so only their names were checked")
    return out


def _iso(data: bytes) -> Listing:
    """Walks the ISO 9660 directory tree, preferring Joliet's long Unicode names."""
    out = Listing(noun="disk image")
    primary = joliet = None
    for sector in range(16, 80):
        vd = data[sector * 2048:(sector + 1) * 2048]
        if len(vd) < 2048 or vd[1:6] != b"CD001" or vd[0] == 255:
            break
        if vd[0] == 1 and primary is None:
            primary = vd
        elif vd[0] == 2 and vd[88:91] in (b"%/@", b"%/C", b"%/E"):
            joliet = vd
    vd = joliet or primary
    if vd is None:
        out.blind.append("the disk image is damaged and can't be listed")
        return out
    codec = "utf-16-be" if vd is joliet else "latin-1"
    block = _u16(vd, 128) if _u16(vd, 128) in (512, 1024, 2048, 4096) else 2048
    stack = [(_u32(vd, 156 + 2), _u32(vd, 156 + 10), "", 0)]  # the root directory record
    seen: set[int] = set()
    while stack:
        lba, size, path, depth = stack.pop()
        if lba in seen or depth > 8:
            continue
        seen.add(lba)
        records = data[lba * block:lba * block + min(size, 4 * 1024 * 1024)]
        pos = 0
        while pos < len(records):
            length = records[pos]
            if length == 0:  # records never cross a sector; zeros pad to the next one
                pos = (pos // 2048 + 1) * 2048
                continue
            rec = records[pos:pos + length]
            pos += length
            if length < 34 or len(rec) < 34:
                break
            raw = rec[33:33 + rec[32]]
            if raw in (b"\x00", b"\x01"):  # "." and ".."
                continue
            name = raw.decode(codec, errors="replace").split(";")[0].rstrip(".")
            full = f"{path}/{name}" if path else name
            extent, extent_size = _u32(rec, 2), _u32(rec, 10)
            if rec[25] & 0x02:
                stack.append((extent, extent_size, full, depth + 1))
                continue
            if out.files >= MAX_ENTRIES:
                out.blind.append(f"the disk image has more than {MAX_ENTRIES:,} files; we only checked the first {MAX_ENTRIES:,}")
                return out
            out.files += 1
            shown = display_name(full, keep_path=True)
            risk = name_risk(full)
            if risk:
                out.risky.append(f"{shown} ({risk})")
                continue
            start = extent * block
            _judge_head(data[start:start + min(extent_size, HEAD_BYTES)], shown, out)
    return out


def _gzip_name(d: bytes) -> Optional[str]:
    """The original file name a gzip header may carry (FNAME)."""
    flags, pos = d[3] if len(d) > 3 else 0, 10
    if flags & 0x04:
        pos += 2 + _u16(d, 10)
    if not flags & 0x08:
        return None
    end = d.find(b"\0", pos, pos + 1024)
    return d[pos:end].decode("latin-1") if end > pos else None


def _compressed(data: bytes, kind: FileKind, budget: _Budget) -> Listing:
    out = Listing(noun="compressed file")
    if kind.mime == MIME_GZIP:
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    elif kind.mime == MIME_BZIP2:
        dec = bz2.BZ2Decompressor()
    else:
        dec = lzma.LZMADecompressor()
    try:
        inner = dec.decompress(data, UNPACK_MAX + 1)  # output is capped here, whatever the header claims
    except Exception:
        out.blind.append(f"the {kind.label} is damaged and can't be unpacked")
        return out
    is_tar = inner[257:262] == b"ustar"
    if is_tar and len(inner) <= UNPACK_MAX and budget.take(len(inner)):
        return _tar(inner)
    if is_tar:
        out.blind.append("the compressed tar archive is too big to unpack safely here; the decoy machine will open it")
        return out
    out.files = 1
    inner_name = _gzip_name(data) if kind.mime == MIME_GZIP else None
    risk = name_risk(inner_name) if inner_name else None
    if risk:
        out.risky.append(f"{display_name(inner_name)} ({risk})")
    elif inner_name:
        _judge_head(inner[:HEAD_BYTES], display_name(inner_name), out)
    else:
        inner_kind = detect_type(inner[:HEAD_BYTES])
        if inner_kind.family in DANGEROUS_FAMILIES:
            out.risky.append(f"{a(inner_kind.label)} ({inner_kind.clue})")
    return out
