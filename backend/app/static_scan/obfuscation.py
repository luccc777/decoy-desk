"""S4: code made hard to read on purpose.

Strong signals count everywhere, including minified bundles: javascript-obfuscator
names (_0x3f2a), running a decoded string (eval(atob(...)), exec(base64.b64decode(...))),
and code pushed off-screen after 150+ spaces, as in the 2025 fake-interview repos.
Weak signals (long character-code lists, strings made of \\xNN escapes) don't count
in build output, where minifiers produce them too.
"""

from __future__ import annotations

import re
from typing import NamedTuple

from app.rules.engine import Evidence, Finding
from app.static_scan.files import RepoFiles
from app.static_scan.textutil import conclude, excerpt, is_bundle, is_source, line_number, unread_sources

CHECK = "S4_obfuscated_code"
MIN_HEX_NAMES = 10
MIN_GAP = 150
MIN_CHAR_CODES = 20
MIN_ESCAPES = 50

_HEX_NAME = re.compile(r"\b_0x[0-9a-fA-F]{4,6}\b")
# Running a decoded string. Each pattern has words a file must contain first, a cheap test
# that skips the regex on almost every file.
_RUN_DECODED = (
    (("eval", "Function"), re.compile(  # JavaScript
        r"\b(?:eval|Function)\s*\(\s*(?:(?:window|globalThis|self|global)\.)?"
        r"(?:atob|unescape|decodeURIComponent\s*\(\s*escape|String\.fromCharCode|(?:new\s+)?Buffer\.from)\s*\(")),
    (("exec", "eval", "marshal", "__import__"), re.compile(  # Python
        r"\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.(?:b64decode|b32decode|b16decode|b85decode|"
        r"urlsafe_b64decode|decodebytes)|zlib\.decompress|lzma\.decompress|bz2\.decompress|gzip\.decompress"
        r"|marshal\.loads|codecs\.decode|bytes\.fromhex|binascii\.(?:a2b_base64|unhexlify))\s*\("
        r"|\bmarshal\.loads\s*\("
        r"|__import__\(\s*['\"](?:zlib|marshal|base64|lzma|bz2)['\"]\s*\)\s*\.\s*(?:decompress|loads|b64decode)\b"
        r"|\bexec\s*\(\s*__import__\(\s*['\"](?:base64|zlib|marshal|codecs)['\"]")),
    (("base64",), re.compile(  # shell
        r"\bbase64\s+(?:-d|--decode|-D)\b[^\n|]{0,200}\|\s*(?:sh|bash|zsh)\b")),
    (("powershell", "pwsh", "frombase64string"), re.compile(  # PowerShell; the words are tested lower-cased
        r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,80}\s-e(?:nc|ncodedcommand)?\s+[a-z0-9+/=]{40,}"
        r"|\b(?:iex|invoke-expression)\b[^\n]{0,200}frombase64string"
        r"|frombase64string[^\n]{0,200}\b(?:iex|invoke-expression)\b", re.IGNORECASE)),
)
# The lookbehind starts each match at the beginning of a run, so a long run costs one pass.
_GAP = re.compile(rf"(?<![ \t])[ \t]{{{MIN_GAP},}}(?=\S)")
_CHAR_CODES = re.compile(
    r"String\.fromCharCode(?:\.apply\s*\(\s*\w*\s*,)?\s*\(\s*(?:\.\.\.)?\s*\[?\s*([0-9a-fA-FxX,\s]{40,})"
    r"|\bmap\s*\(\s*chr\s*,\s*[\[(]\s*([0-9a-fA-FxX,\s]{40,})"
    r"|\bchr\s*\(\s*\w+\s*\)\s*for\s+\w+\s+in\s*[\[(]\s*([0-9a-fA-FxX,\s]{40,})")
_NUMBER = re.compile(r"0[xX][0-9a-fA-F]+|\d+")
_ASCII_ESCAPE = re.compile(r"\\x[2-7][0-9a-fA-F]|\\u00[2-7][0-9a-fA-F]")
_ANY_ESCAPE = re.compile(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}")
_STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|`(?:[^`\\]|\\.)*`', re.DOTALL)


class Signal(NamedTuple):
    strong: bool
    summary: str
    start: int
    end: int


def _signals(path: str, text: str) -> list[Signal]:
    found: list[Signal] = []
    names = []
    for m in _HEX_NAME.finditer(text):
        names.append(m)
        if len(names) >= 1000:
            break
    if len(names) >= MIN_HEX_NAMES:
        count = f"{len(names)}+" if len(names) >= 1000 else str(len(names))
        found.append(Signal(True, f"{path} looks machine-obfuscated: {count} scrambled names like "
                                  f"{names[0].group(0)}", names[0].start(), names[0].end()))
    lower = text.lower()
    for words, pattern in _RUN_DECODED:
        haystack = lower if words[0] == "powershell" else text
        if any(w in haystack for w in words) and (m := pattern.search(text)):
            found.append(Signal(True, f"{path} decodes a hidden string and runs it as code "
                                      f"(line {line_number(text, m.start())})", m.start(), m.end()))
            break
    for m in _GAP.finditer(text):
        line_end = text.find("\n", m.end())
        rest = text[m.end(): line_end if line_end >= 0 else len(text)].strip()
        if len(rest) >= 6:
            found.append(Signal(True, f"{path} hides code {len(m.group(0))} spaces to the right on line "
                                      f"{line_number(text, m.start())}, off the edge of the editor",
                                m.end(), m.end() + len(rest)))
            break
    for m in _CHAR_CODES.finditer(text) if ("fromCharCode" in text or "chr" in text) else ():
        numbers = _NUMBER.findall(m.group(1) or m.group(2) or m.group(3) or "")
        if len(numbers) >= MIN_CHAR_CODES:
            found.append(Signal(False, f"{path} builds text from a list of {len(numbers)} character codes "
                                       f"(line {line_number(text, m.start())})", m.start(), m.end()))
            break
    if len(_ASCII_ESCAPE.findall(text)) >= MIN_ESCAPES:
        for m in _STRING.finditer(text):
            s = m.group(0)
            if len(s) < MIN_ESCAPES * 4:
                continue
            ascii_escapes = len(_ASCII_ESCAPE.findall(s))
            # Binary data (b"\x58\x00\x4c\x00...") mixes in control bytes; hidden text is almost all printable.
            if ascii_escapes >= MIN_ESCAPES and ascii_escapes >= 0.8 * len(_ANY_ESCAPE.findall(s)):
                found.append(Signal(False, f"{path} spells out plain text as escape codes (\\x..) to hide it "
                                           f"(line {line_number(text, m.start())})", m.start(), m.end()))
                break
    return found


def find_obfuscation(path: str, text: str, *, bundle: bool = False) -> list[Evidence]:
    """Evidence of obfuscation in one file; in a bundle only the strong signals count."""
    return [Evidence(summary=s.summary, source=path, quote=excerpt(text, s.start, s.end))
            for s in _signals(path, text) if s.strong or not bundle]


def check_obfuscation(files: RepoFiles) -> Finding:
    hits: list[Evidence] = []
    read = 0
    for path, text in sorted(files.texts.items()):
        if not is_source(path, text):
            continue
        read += 1
        hits.extend(find_obfuscation(path, text, bundle=is_bundle(path, text)))
    return conclude(CHECK, hits, f"Read {read} source file(s); none looks obfuscated",
                    unread_sources(files), files)
