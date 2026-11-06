"""Domain helpers: pull hosts out of URLs, emails and free text, and reduce them to the registrable domain."""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlsplit

import tldextract

# The bundled public suffix list snapshot; never downloads anything at run time.
# Private suffixes count, so "evil.github.io" and "evil.vercel.app" are their own sites.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>\"'()\[\]{}]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")

FREE_WEBMAIL = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "ymail.com", "aol.com", "icloud.com", "me.com", "mac.com", "proton.me",
    "protonmail.com", "pm.me", "gmx.com", "gmx.net", "mail.com", "zoho.com", "yandex.com",
    "yandex.ru", "mail.ru", "tutanota.com", "tuta.io", "fastmail.com", "hey.com", "qq.com",
    "163.com", "126.com",
})


def host_of(text: Optional[str]) -> Optional[str]:
    """Host from a URL, an email address or a bare domain, lower-case, without "www."."""
    if not text:
        return None
    text = text.strip().strip(".,;:!?()<>\"'").lower()
    if "@" in text and "://" not in text:
        m = EMAIL_RE.search(text)
        if not m:
            return None
        text = m.group(1)
    elif "://" in text or text.startswith("www."):
        try:
            text = urlsplit(text if "://" in text else "http://" + text).hostname or ""
        except ValueError:  # e.g. "http://[abc": not a URL we can read
            return None
    else:
        text = text.split("/", 1)[0].split(":", 1)[0]
    text = text.strip(".")
    if text.startswith("www."):
        text = text[4:]
    return text or None


def registrable(text: Optional[str]) -> Optional[str]:
    """"careers.coinbase.com" -> "coinbase.com". None when there is no real public suffix."""
    host = host_of(text)
    if not host:
        return None
    parts = _extract(host)
    if not parts.domain or not parts.suffix:
        return None
    return f"{parts.domain}.{parts.suffix}"


def label(domain: Optional[str]) -> Optional[str]:
    """"coinbase.com" -> "coinbase"."""
    host = host_of(domain)
    return _extract(host).domain or None if host else None


def urls_in(text: Optional[str]) -> list[str]:
    return [m.group(0).rstrip(".,;:!?") for m in URL_RE.finditer(text or "")]


def emails_in(text: Optional[str]) -> list[str]:
    return [m.group(0).lower() for m in EMAIL_RE.finditer(text or "")]
