"""S5: web addresses hidden in encoded strings.

The fake-interview loaders kept their server address base64-encoded in a config
file or .env (aHR0cDovLzE0Ny4uLg== is "http://147..."), so a search for "http"
finds nothing. We decode base64, hex, \\xNN escapes, character-code lists and
reversed strings, and report the ones that turn into a URL or an IP address.

Not reported: data: URIs (inline images and fonts), lock files, source maps,
PEM certificates, JWTs, XML namespace addresses, local addresses, and any
address that also appears in plain text in the same file.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from typing import Optional

from app.rules.engine import Evidence, Finding
from app.static_scan.files import RepoFiles
from app.static_scan.textutil import conclude, ext, is_bundle, is_source, line_number, shorten

CHECK = "S5_hidden_urls"
MAX_PER_FILE = 5

SKIP_NAMES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "poetry.lock",
    "pipfile.lock", "composer.lock", "gemfile.lock", "cargo.lock", "go.sum", "uv.lock", "pdm.lock",
})
SKIP_EXTS = frozenset({".map", ".pem", ".crt", ".cer", ".key", ".p7b", ".lock", ".snap"})
# Addresses that show up inside encoded SVG, XMP image metadata and XML, never as a server.
NAMESPACE_HOSTS = frozenset({
    "www.w3.org", "w3.org", "ns.adobe.com", "purl.org", "schemas.xmlsoap.org", "schemas.microsoft.com",
    "schemas.openxmlformats.org", "xmlns.com", "www.inkscape.org", "inkscape.org", "sodipodi.sourceforge.net",
    "creativecommons.org", "iptc.org", "ns.useplus.org", "www.npes.org", "cipa.jp", "www.aiim.org",
})
LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"})

_B64 = re.compile(r"(?<![A-Za-z0-9+/_\-])[A-Za-z0-9+/_-]{16,8192}={0,2}(?![A-Za-z0-9+/_\-=])")
_HEX = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{24,4096}(?![0-9a-fA-F])")
_HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){8,}")
_U_ESCAPES = re.compile(r"(?:\\u[0-9a-fA-F]{4}){8,}")
_CODE_LIST = re.compile(r"(?<![\w.])\d{1,3}(?:\s*,\s*\d{1,3}){11,}")
_REVERSED = re.compile(r"""(["'`])([^"'`\n]{4,300}?//:s?(?:ptth|sw))\1""")
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{1,40}-----.*?-----END [A-Z0-9 ]{1,40}-----", re.DOTALL)

_URL = re.compile(r"\b(?:https?|wss?)://[^\s\"'<>`\\]{1,200}", re.IGNORECASE)
# Not after "/", so a version such as Chrome/120.0.0.0 in a user agent isn't taken for an address.
_IPV4 = re.compile(r"(?<![\d./])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\d.])")


def _printable(raw: bytes) -> Optional[str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    good = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return text if good / len(text) >= 0.95 else None


def _b64(token: str) -> Optional[str]:
    token = token.rstrip("=")
    if len(token) % 4 == 1:
        return None
    urlsafe = "-" in token or "_" in token
    if urlsafe and ("+" in token or "/" in token):
        return None
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_" if urlsafe else None, validate=True)
    except (binascii.Error, ValueError):
        return None
    return _printable(raw)


def _host(url: str) -> str:
    rest = url.split("://", 1)[1] if "://" in url else url
    host = re.split(r"[/?#]", rest, maxsplit=1)[0].rsplit("@", 1)[-1]
    return host.rsplit(":", 1)[0].lower() if host.count(":") == 1 else host.lower()


def address_in(decoded: str) -> Optional[str]:
    """The first outside URL or public IPv4 address in decoded text."""
    for m in _URL.finditer(decoded):
        url = m.group(0).rstrip(".,;)")
        host = _host(url)
        if host and host not in NAMESPACE_HOSTS and host not in LOCAL_HOSTS:
            return url
    for m in _IPV4.finditer(decoded):
        ip = m.group(0).split(":", 1)[0]
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if not (addr.is_loopback or addr.is_unspecified or addr.is_multicast or ip == "255.255.255.255"):
            return m.group(0)
    return None


def _skip_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return name in SKIP_NAMES or ext(path) in SKIP_EXTS or name.endswith((".min.css.map", ".js.map"))


def _decoded_candidates(text: str):
    """(kind, start, end, decoded text) for every encoded string that decodes to readable text."""
    for m in _B64.finditer(text):
        token = m.group(0)
        if not (any(c.isupper() for c in token) and any(c.islower() for c in token)):
            continue  # identifiers and hex hashes; real base64 of text mixes cases
        s = m.start()
        if text[max(0, s - 7):s].lower() == "base64,":
            continue  # data: URI, an inline image or font
        if token.startswith("eyJ") and (text[m.end():m.end() + 1] == "." or text[s - 1:s] == "."):
            continue  # a JWT; its claims name their issuer's URL
        decoded = _b64(token)
        if decoded is not None:
            inner = decoded.strip()
            if 16 <= len(inner) <= 8192 and _B64.fullmatch(inner) and (twice := _b64(inner)):
                decoded = twice  # encoded twice
            yield "a base64 string", s, m.end(), decoded
    for m in _HEX.finditer(text):
        if len(m.group(0)) % 2 == 0 and (decoded := _printable(bytes.fromhex(m.group(0)))):
            yield "a hex string", m.start(), m.end(), decoded
    for pattern, width in ((_HEX_ESCAPES, 4), (_U_ESCAPES, 6)):
        for m in pattern.finditer(text):
            s = m.group(0)
            decoded = "".join(chr(int(s[i + 2:i + width], 16)) for i in range(0, len(s), width))
            yield "an escaped string", m.start(), m.end(), decoded
    for m in _CODE_LIST.finditer(text):
        codes = [int(n) for n in re.findall(r"\d+", m.group(0))]
        if all(9 <= c <= 126 for c in codes):
            yield "a list of character codes", m.start(), m.end(), "".join(map(chr, codes))
    if "//:" in text:
        for m in _REVERSED.finditer(text):
            yield "a reversed string", m.start(2), m.end(2), m.group(2)[::-1]


def find_hidden_urls(path: str, text: str) -> list[Evidence]:
    """Evidence for every address hidden in an encoded string in one file."""
    if _skip_file(path):
        return []
    if "-----BEGIN " in text:
        text = _PEM.sub(lambda m: " " * len(m.group(0)), text)
    out: list[Evidence] = []
    seen: set[str] = set()
    for kind, start, end, decoded in _decoded_candidates(text):
        if len(out) >= MAX_PER_FILE:
            break
        address = address_in(decoded)
        if not address or address in seen or address in text:
            continue
        seen.add(address)
        what = "address" if "://" in address else "IP address"
        out.append(Evidence(summary=f"{path} hides the {what} {shorten(address, 120)} in {kind} "
                                    f"(line {line_number(text, start)})",
                            source=path, quote=shorten(text[start:end], 120)))
    return out


def check_hidden_urls(files: RepoFiles) -> Finding:
    hits: list[Evidence] = []
    read = 0
    for path, text in sorted(files.texts.items()):
        if _skip_file(path):
            continue
        read += 1
        hits.extend(find_hidden_urls(path, text))
    unread = [p for p in files.skipped if (is_source(p) and not is_bundle(p))
              or p.rsplit("/", 1)[-1].lower().startswith(".env")]
    return conclude(CHECK, hits, f"Read {read} file(s); no web address is hidden in an encoded string",
                    unread, files)
