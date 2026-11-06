"""Office documents that run something when they open (S8).

olevba reads VBA source without running it. Remote templates and Follina-style
links come from the package's relationship files, read with plain regexes.
Two oletools habits are patched once at import (see _harden_olefile and
_harden_oletools): reading small byte strings as file paths, and inflating
zlib data without a size limit.
"""

from __future__ import annotations

import contextvars
import html
import io
import itertools
import logging
import re
import struct
import warnings
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from app.legitimacy.common import clear, unknown
from app.rules.engine import Evidence, Finding
from app.static_scan.archive import zip_guard
from app.static_scan.filetype import (
    MIME_MSI, MIME_RTF, OFFICE_XML_MIMES, OLE_MAGIC, OOXML_MIMES, FileKind, display_name,
)

CHECK = "S8_office_autorun_macro"
PART_MAX = 2 * 1024 * 1024  # bytes read from one .rels or workbook.xml part
INFLATE_MAX = 64 * 1024 * 1024  # zlib output allowed from one embedded part; real VBA projects are a few MB

log = logging.getLogger(__name__)

# olevba tags ActiveX events such as Button1_Click as AutoExec; those wait for a click.
_NEEDS_CLICK = ("_click", "_dblclick", "_followhyperlink")
# Shown first when picking the three keywords for the evidence line.
_STRONG = ("shell", "wscript.shell", "createobject", "urldownloadtofile", "urldownloadtofilea", "powershell",
           "run", "exec", "shell.application", "msxml2.xmlhttp", "adodb.stream", "callbyname", "environ")
_NOISE = {"hex strings", "base64 strings", "dridex strings", "vba strings"}

_REMOTE_RELS = {
    "attachedtemplate": "{name} opens a remote template from {host} when you open it",
    "oleobject": "{name} loads a remote object from {host} when you open it (the trick the Follina attack used)",
    "frame": "{name} loads a remote page from {host} when you open it",
    "subdocument": "{name} loads a remote document from {host} when you open it",
}
_REL = re.compile(rb"<(?:\w+:)?Relationship\b([^>]*)>", re.I)
_ATTR = re.compile(rb"([\w:.-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")
_AUTO_OPEN_NAME = re.compile(rb"<(?:\w+:)?definedName\b[^>]*\bname\s*=\s*[\"'](?:_xlnm\.)?auto_open", re.I)
_RTF_TEMPLATE = re.compile(rb"\{\\\*\\template\s*([^}]{1,4096})\}", re.I)
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s\x00\"'<>]+")


def _harden_olefile() -> None:
    """Make olefile read bytes as content, never as a path.

    olefile treats a bytes argument shorter than 1536 bytes as a file name, and
    oletools passes attacker bytes that way (rtfobj with an embedded object's data,
    ftguess with a small OLE part), so an upload could make us open() a path it
    chose: a FIFO that hangs, or a network share on Windows.
    """
    try:
        import olefile
    except ImportError:
        return
    if getattr(olefile, "_bytes_are_data", False):
        return
    real_is_ole, real_open = olefile.isOleFile, olefile.OleFileIO.open

    def is_ole_file(filename=None, data=None):
        if data is None and isinstance(filename, (bytes, bytearray)):
            return real_is_ole(data=bytes(filename))
        return real_is_ole(filename, data)

    def open_(self, filename, write_mode=False):
        if isinstance(filename, (bytes, bytearray)):
            filename = io.BytesIO(bytes(filename))
        return real_open(self, filename, write_mode)

    olefile.isOleFile, olefile.OleFileIO.open = is_ole_file, open_
    olefile._bytes_are_data = True


_harden_olefile()


class InflateLimit(Exception):
    """An embedded zlib stream unpacks past INFLATE_MAX. Deliberately not a ValueError, which oletools swallows."""


# Set when a cap fires; olevba's MHT reader swallows every exception, so _open_parser checks this too.
_inflate_limit_hit: contextvars.ContextVar[bool] = contextvars.ContextVar("inflate_limit_hit", default=False)


def _over_limit() -> InflateLimit:
    _inflate_limit_hit.set(True)
    return InflateLimit()


def _inflate(data: bytes) -> bytes:
    """zlib.decompress with a ceiling."""
    dec = zlib.decompressobj()
    out = dec.decompress(data, INFLATE_MAX + 1)
    if len(out) > INFLATE_MAX:
        raise _over_limit()
    if not dec.eof:
        raise zlib.error("incomplete zlib stream")
    return out


def _harden_oletools(olevba) -> None:
    """Cap the two places oletools inflates zlib data without a limit.

    ppt_parser.iterative_decompress unpacks PowerPoint 97 VBA storages (reached by
    any OLE part, even one embedded in a .docx), and olevba.mso_file_extract unpacks
    ActiveMime parts of MHT and Word 2003 XML files. Both would follow a zlib bomb.
    """
    if getattr(olevba, "_inflate_capped", False):
        return

    def iterative_decompress(stream, size, chunk_size=4096):
        dec, out, n_read = zlib.decompressobj(), bytearray(), 0
        try:
            while n_read < size:
                n_new = min(size - n_read, chunk_size)
                out += dec.decompress(stream.read(n_new), INFLATE_MAX + 1 - len(out))
                n_read += n_new
                if len(out) > INFLATE_MAX:
                    raise _over_limit()
        except zlib.error as err:
            return bytes(out), n_read, err
        return bytes(out), n_read, None

    def mso_file_extract(data):
        try:
            starts = [struct.unpack_from("<H", data, 0x1E)[0] + 46, 0x32, 0x22A]
        except struct.error:
            raise olevba.MsoExtractionError("Unable to parse MSO/ActiveMime file header")
        starts += [m.start() for m in itertools.islice(re.finditer(rb"x", data), 16)]  # zlib headers start with 0x78
        for start in starts:
            try:
                return _inflate(data[start:])
            except zlib.error:
                continue
        raise olevba.MsoExtractionError("Unable to decompress data from a MSO/ActiveMime file")

    olevba.ppt_parser.iterative_decompress = iterative_decompress
    olevba.mso_file_extract = mso_file_extract
    olevba._inflate_capped = True


@dataclass
class _Found:
    hits: list[str] = field(default_factory=list)
    unknown: Optional[str] = None
    click_macros: bool = False


def check(name: str, data: bytes, kind: FileKind) -> Finding:
    """S8 for one file: hit, clear, or unknown when the document couldn't be read."""
    shown = display_name(name)
    if kind.mime == MIME_RTF:
        return _rtf(shown, data)
    is_ole = data[:8] == OLE_MAGIC and kind.mime != MIME_MSI
    is_ooxml = data[:2] == b"PK" and kind.mime in OOXML_MIMES
    if not (is_ole or is_ooxml or kind.mime in OFFICE_XML_MIMES):
        return clear(CHECK, "not an Office document")
    if is_ole and _ole_encrypted(data):
        return unknown(CHECK, f"{shown} is password-protected, so its macros are hidden; the decoy machine will open it")
    found = _Found()
    if is_ooxml:
        problem = zip_guard(data)
        if problem:
            return unknown(CHECK, f"{shown} can't be opened safely: {problem}")
        _package_parts(shown, data, found)
    _macros(shown, data, found, project_expected="with macros" in kind.label,
            office_xml=kind.mime in OFFICE_XML_MIMES)
    if found.hits:
        return Finding(check=CHECK, status="hit", evidence=[Evidence(summary=s) for s in found.hits])
    if found.unknown:
        return unknown(CHECK, found.unknown)
    if found.click_macros:
        return clear(CHECK, f"{shown} has macros that need a click to run")
    return clear(CHECK, f"{shown} has no macros")


# ---------------------------------------------------------------- VBA (olevba)

def _open_parser(data: bytes):
    """olevba's parser for the document in memory, or None for a format it would only read as plain text."""
    with warnings.catch_warnings():  # olevba builds pyparsing grammars with deprecated names at import
        warnings.simplefilter("ignore", DeprecationWarning)
        from oletools import olevba
    _harden_oletools(olevba)
    _inflate_limit_hit.set(False)
    # P-code is only used to spot VBA stomping, which olevba can't do in memory anyway.
    parser = olevba.VBA_Parser("upload", data=data, disable_pcode=True)
    if _inflate_limit_hit.get():
        parser.close()
        raise InflateLimit
    if parser.type in (None, olevba.TYPE_TEXT):
        parser.close()
        return None
    parser.vba_stomping_detected = False  # skips that check and the warning it logs for in-memory files
    return parser


def _macros(shown: str, data: bytes, found: _Found, *, project_expected: bool, office_xml: bool) -> None:
    damaged = f"{shown} looks damaged, so its macros couldn't be read"
    try:
        parser = _open_parser(data)
    except ImportError:
        found.unknown = "the macro scanner (oletools) isn't installed"
        return
    except InflateLimit:
        found.unknown = f"{shown} holds compressed data that unpacks to more than 64 MB, like a zip bomb"
        return
    except Exception:
        found.unknown = damaged
        return
    if parser is None:
        if project_expected:
            found.unknown = f"{shown} has a macro project that couldn't be read"
        elif office_xml:  # olevba fell back to reading it as plain text
            found.unknown = f"{shown} couldn't be read as an Office web or XML document"
        return
    try:
        _read_macros(shown, parser, found, project_expected=project_expected)
    except InflateLimit:
        found.unknown = f"{shown} holds compressed data that unpacks to more than 64 MB, like a zip bomb"
    except Exception:
        log.info("olevba failed on %s", shown, exc_info=True)
        found.unknown = damaged
    finally:
        try:
            parser.close()
        except Exception:
            pass


def _read_macros(shown: str, parser, found: _Found, *, project_expected: bool) -> None:
    if not parser.detect_macros():
        if project_expected:
            found.unknown = f"{shown} has a macro project that couldn't be read"
        return
    results = parser.analyze_macros() or []
    autoexec = [(kw, desc) for kind, kw, desc in results
                if kind == "AutoExec" and not kw.lower().endswith(_NEEDS_CLICK)]
    if not autoexec:
        found.click_macros = True
        return
    autoexec.sort(key=lambda t: "open" not in t[1].lower())  # an on-open trigger says it best
    desc = autoexec[0][1].lower()
    when = "when you open it" if "open" in desc else "when you close it" if "close" in desc else "by itself"
    trigger = ", ".join(dict.fromkeys(kw for kw, _ in autoexec[:2]))
    line = f"{shown} has a macro that runs {when} ({trigger})"
    keywords = _top_keywords([kw for kind, kw, _ in results if kind == "Suspicious"])
    if keywords:
        line += f" and uses {', '.join(keywords)}"
    found.hits.append(line)


def _top_keywords(keywords: list[str]) -> list[str]:
    seen: dict[str, str] = {}
    for kw in keywords:
        seen.setdefault(kw.lower(), kw)
    ranked = sorted((k for k in seen if k not in _NOISE),
                    key=lambda k: _STRONG.index(k) if k in _STRONG else len(_STRONG))
    return [seen[k] for k in ranked[:3]]


def _ole_encrypted(data: bytes) -> bool:
    try:
        import olefile
        from oletools import crypto
        with olefile.OleFileIO(io.BytesIO(data)) as ole:
            return ole.exists("EncryptedPackage") or bool(crypto.is_encrypted(ole))
    except Exception:
        return False


# ---------------------------------------------------------------- OOXML parts

def _package_parts(shown: str, data: bytes, found: _Found) -> None:
    """Remote templates, Follina-style links and Excel 4.0 auto-open sheets."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        for info in infos:
            if not info.filename.lower().endswith(".rels"):
                continue
            for rel_type, target in _relationships(_read_part(zf, info)):
                host = _remote_host(target)
                if host and rel_type in _REMOTE_RELS:
                    line = _REMOTE_RELS[rel_type].format(name=shown, host=host)
                    if line not in found.hits:
                        found.hits.append(line)
        if any(i.filename.lower().startswith("xl/macrosheets/") for i in infos):
            book = next((i for i in infos if i.filename.lower() == "xl/workbook.xml"), None)
            if book is not None and _AUTO_OPEN_NAME.search(_read_part(zf, book)):
                found.hits.append(f"{shown} has an Excel 4.0 macro sheet that runs when you open it (Auto_Open)")
            else:
                found.click_macros = True


def _read_part(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    try:
        with zf.open(info) as f:
            return f.read(PART_MAX)
    except Exception:
        return b""


def _relationships(xml: bytes) -> list[tuple[str, str]]:
    """(type, target) of each Relationship, the type cut to its last segment: 'attachedtemplate'."""
    rels = []
    for m in _REL.finditer(xml):
        attrs = {k.lower(): (v1 or v2) for k, v1, v2 in _ATTR.findall(m.group(1))}
        rel_type = attrs.get(b"type", b"").decode("utf-8", "replace").rsplit("/", 1)[-1].lower()
        target = html.unescape(attrs.get(b"target", b"").decode("utf-8", "replace"))
        rels.append((rel_type, target))
    return rels


def _remote_host(target: str) -> Optional[str]:
    """The server a target points to (web, FTP or a network share), or None for a local part."""
    t = target.strip()
    if t.lower().startswith("mhtml:"):
        t = t[6:]
    if re.match(r"(?i)(?:https?|ftp)://", t):
        try:
            return urlsplit(t).hostname or "an unnamed server"
        except ValueError:
            return "an unnamed server"
    if t.startswith(("\\\\", "//")) or re.match(r"(?i)file://[^/]", t):
        rest = re.sub(r"(?i)^file:", "", t).lstrip("\\/")
        return re.split(r"[\\/@]", rest, maxsplit=1)[0].lower() or "an unnamed server"
    return None


# ---------------------------------------------------------------- RTF

def _rtf(shown: str, data: bytes) -> Finding:
    hits = []
    for m in _RTF_TEMPLATE.finditer(data):
        host = _remote_host(_rtf_text(m.group(1)))
        if host:
            hits.append(f"{shown} opens a remote template from {host} when you open it")
    objects = None
    try:
        from oletools import rtfobj
        parser = rtfobj.RtfObjParser(data)
        parser.parse()
        objects = parser.objects
    except Exception:
        log.info("rtfobj failed on %s", shown, exc_info=True)
    for obj in objects or ():
        if (obj.class_name or b"").rstrip(b"\0").lower() == b"ole2link":
            host = _host_in_blob(obj.oledata or obj.rawdata or b"")
            where = f" from {host}" if host else ""
            hits.append(f"{shown} has a link that loads a remote object{where} when you open it")
    if hits:
        return Finding(check=CHECK, status="hit", evidence=[Evidence(summary=s) for s in hits])
    if objects is None:
        return unknown(CHECK, f"{shown} looks damaged, so its embedded objects couldn't be read")
    return clear(CHECK, f"{shown} is an RTF document: it can't hold macros, and it loads nothing remote")


def _rtf_text(raw: bytes) -> str:
    """Plain text of an RTF destination: hex and Unicode escapes decoded, control words dropped."""
    s = raw.decode("latin-1").replace("\\\\", "\0")
    s = re.sub(r"\\'([0-9a-fA-F]{2})", lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"\\u(-?\d{1,6})\??", lambda m: chr(int(m.group(1)) % 0x10000), s)
    s = re.sub(r"\\[a-zA-Z]+-?\d* ?", "", s)
    return s.replace("\0", "\\")


def _host_in_blob(blob: bytes) -> Optional[str]:
    """The host of the first URL in binary data, stored as ASCII or UTF-16 at either alignment."""
    for text in (blob.decode("latin-1"), blob.decode("utf-16-le", "ignore"), blob[1:].decode("utf-16-le", "ignore")):
        m = _URL.search(text)
        if m:
            return _remote_host(m.group())
    return None
