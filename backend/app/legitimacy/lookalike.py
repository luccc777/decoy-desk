"""Lookalike domains (H3), fake meeting links (H2) and recruiters off the official domain (C4).

Pure functions: no network, no clock. Every input may be a bare domain, a URL or an email address.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from typing import Optional
from urllib.parse import urlsplit

from app.legitimacy.common import clear, unknown
from app.legitimacy.domains import FREE_WEBMAIL, host_of, registrable
from app.rules.engine import Evidence, Finding

# Recruiting platforms that send mail for many companies. contact.py re-exports this set;
# it lives here because contact.py imports this module, not the other way round.
ATS_SENDERS = frozenset({
    "greenhouse.io", "greenhouse-mail.io", "lever.co", "hire.lever.co", "ashbyhq.com",
    "smartrecruiters.com", "myworkday.com", "workday.com", "icims.com", "jobvite.com",
    "bamboohr.com", "workable.com", "teamtailor.com", "recruitee.com", "linkedin.com",
})

# Big shared services. They are never lookalikes themselves (lever.co is not a typo of
# clever.com), and their subdomains belong to the provider, so coinbase.zoom.us or
# coinbase.wd1.myworkdayjobs.com is a company's tenant, not a decoy.
_SHARED_SERVICES = FREE_WEBMAIL | ATS_SENDERS | frozenset({
    "myworkdayjobs.com", "github.com", "gitlab.com", "bitbucket.org", "slack.com",
    "zoom.us", "zoom.com", "zoomgov.com", "microsoft.com", "live.com", "google.com",
    "webex.com", "skype.com",
})

# Words a fake recruiting domain glues to the brand without a hyphen ("coinbasehr").
# With a hyphen any extra word counts ("coinbase-login"), so this list only matters for glued forms.
_ADDITIONS = frozenset({
    "careers", "career", "jobs", "job", "hr", "hiring", "recruit", "recruiting", "recruiter",
    "recruitment", "talent", "team", "official", "llc", "inc", "corp", "group", "global",
    "app", "portal", "apply", "interview", "hq",
})

# Characters from other scripts that render like Latin letters.
_CONFUSABLES = {
    # Cyrillic: a e o p c x y i j s d h l w
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "у": "y", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h",
    "ӏ": "l", "ԝ": "w",
    # Greek: omicron alpha nu iota kappa rho upsilon chi
    "ο": "o", "α": "a", "ν": "v", "ι": "i", "κ": "k", "ρ": "p",
    "υ": "u", "χ": "x",
    # Latin dotless i, script a, script g
    "ı": "i", "ɑ": "a", "ɡ": "g",
}
_ASCII_TRICKS = (("0", "o"), ("1", "l"), ("rn", "m"), ("vv", "w"))


# ---------------------------------------------------------------- text helpers

def damerau_levenshtein(a: str, b: str) -> int:
    """Edits (insert, delete, substitute, swap adjacent) to turn a into b; unrestricted variant."""
    big = len(a) + len(b)
    d = [[0] * (len(b) + 2) for _ in range(len(a) + 2)]
    d[0][0] = big
    for i in range(len(a) + 1):
        d[i + 1][0], d[i + 1][1] = big, i
    for j in range(len(b) + 1):
        d[0][j + 1], d[1][j + 1] = big, j
    last_row: dict[str, int] = {}
    for i in range(1, len(a) + 1):
        last_col = 0
        for j in range(1, len(b) + 1):
            i1, j1 = last_row.get(b[j - 1], 0), last_col
            cost = 1
            if a[i - 1] == b[j - 1]:
                cost, last_col = 0, j
            d[i + 1][j + 1] = min(
                d[i][j] + cost,
                d[i + 1][j] + 1,
                d[i][j + 1] + 1,
                d[i1][j1] + (i - i1 - 1) + 1 + (j - j1 - 1),
            )
        last_row[a[i - 1]] = i
    return d[len(a) + 1][len(b) + 1]


def _unicode(label: str) -> str:
    """A punycode label (xn--...) as the user sees it; anything else unchanged."""
    if label.startswith("xn--"):
        try:
            return label.encode("ascii").decode("idna")
        except UnicodeError:
            return label
    return label


def _parse(text: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """(host, registrable domain), or nothing for a malformed URL ("http://[x" makes host_of raise)."""
    try:
        return host_of(text), registrable(text)
    except ValueError:
        return None, None


def _registrable(text: Optional[str]) -> Optional[str]:
    return _parse(text)[1]


def _unicode_host(host: str) -> str:
    return ".".join(_unicode(part) for part in host.split("."))


def _skeleton(text: str) -> tuple[str, list[str]]:
    """Fold lookalike characters to plain Latin, and name each trick found ("0 for o")."""
    out: list[str] = []
    tricks: list[str] = []
    for ch in text:
        if unicodedata.category(ch) == "Cf":  # zero-width and other invisible characters
            if "hidden character" not in tricks:
                tricks.append("hidden character")
            continue
        base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c))
        plain = "".join(_CONFUSABLES.get(c, c) for c in base).lower()
        if plain != ch:
            script = unicodedata.name(ch, "").split(" ", 1)[0]
            prefix = f"{script.title()} " if script in ("CYRILLIC", "GREEK") else ""
            note = f"{prefix}{ch} for {plain}"
            if note not in tricks:
                tricks.append(note)
        out.append(plain)
    folded = "".join(out)
    for fake, real in _ASCII_TRICKS:
        if fake in folded:
            folded = folded.replace(fake, real)
            tricks.append(f"{fake} for {real}")
    return folded, tricks


def _char(c: str) -> str:
    return "hyphen" if c == "-" else c


def _describe_edit(cand: str, ref: str) -> str:
    """Plain words for a one-character typo; a count otherwise."""
    distance = damerau_levenshtein(cand, ref)
    if distance != 1:
        return f"{distance} characters off"
    i = next((k for k, (x, y) in enumerate(zip(cand, ref)) if x != y), min(len(cand), len(ref)))
    if len(cand) > len(ref):
        return f"extra {_char(cand[i])}"
    if len(cand) < len(ref):
        return f"missing {_char(ref[i])}"
    if cand[i + 1:] == ref[i + 1:]:
        return f"{_char(cand[i])} for {_char(ref[i])}"
    return f"{_char(ref[i])} and {_char(ref[i + 1])} swapped"


def _extra_words(cand: str, ref: str) -> Optional[list[str]]:
    """What a label adds around the brand: "coinbase-careers" and "coinbasehr" -> the added words."""
    if len(ref) < 3 or cand == ref:
        return None
    padded = f"-{cand}-"
    if f"-{ref}-" in padded:
        before, _, after = padded.partition(f"-{ref}-")
        words = [w.strip("-") for w in (before, after) if w.strip("-")]
        return words or None
    for word in _ADDITIONS:
        if cand in (ref + word, word + ref):
            return [word]
    return None


def _label_detail(cand: str, ref: str) -> Optional[str]:
    """Why label cand imitates label ref (both already decoded from punycode), or None."""
    skel_c, tricks_c = _skeleton(cand)
    skel_r, tricks_r = _skeleton(ref)
    # Tricks the reference itself has ("rn" in "cornell") explain nothing.
    tricks = [t for t in tricks_c if t not in tricks_r]
    if skel_c == skel_r:
        flipped = [" for ".join(t.split(" for ")[::-1]) for t in tricks_r if t not in tricks_c]
        return ", ".join(tricks or flipped) or "looks the same"
    words, also = _extra_words(cand, ref), []
    if words is None:
        words, also = _extra_words(skel_c, skel_r), tricks  # "c0inbase-careers"
    if words:
        return ", ".join(["adds " + " and ".join(f'"{w}"' for w in words), *also])
    # Distance 2 on a short label is mostly unrelated words (rome vs ramp), so it needs 6+ letters.
    limit = 2 if len(skel_r) >= 6 else 1 if len(skel_r) >= 4 else 0
    if damerau_levenshtein(skel_c, skel_r) <= limit:
        return _describe_edit(cand, ref)
    return None


def _brand_in_part(part: str, ref_label: str) -> bool:
    """Whether a subdomain label carries the brand: "coinbase", "coinbase-login", "c0inbase"."""
    if len(ref_label) < 3:
        return False
    skel_p, skel_r = _skeleton(_unicode(part))[0], _skeleton(ref_label)[0]
    return f"-{skel_r}-" in f"-{skel_p}-"


def _userinfo(text: str) -> str:
    """The "coinbase.com" in https://coinbase.com@evil.io: shown to people, ignored by browsers."""
    if "://" not in text:
        return ""
    try:
        return (urlsplit(text.strip()).username or "").lower()
    except ValueError:
        return ""


def _path(text: str) -> str:
    text = text.strip()
    if "@" in text and "://" not in text:
        return ""  # an email address
    try:
        path = urlsplit(text if "://" in text else "http://" + text).path
    except ValueError:
        return ""
    return path.lower() if path not in ("", "/") else ""


def _shown(host: str, userinfo: str = "") -> str:
    """How to name a host to a person: with what a punycode host renders as."""
    uni = _unicode_host(host)
    shown = host if uni == host else f"{host} ({uni})"
    return f"{userinfo}@{shown}" if userinfo else shown


# ---------------------------------------------------------------- H3

def lookalike_reason(candidate: str, reference: str) -> Optional[str]:
    """A one-line reason when candidate imitates reference ("c0inbase.com imitates coinbase.com (0 for o)").

    None when it doesn't, when either can't be parsed, or when both share a registrable domain.
    """
    (cand_host, cand_reg), ref_reg = _parse(candidate), _registrable(reference)
    if not cand_host or not cand_reg or not ref_reg or cand_reg == ref_reg:
        return None
    cand_label, cand_suffix = cand_reg.split(".", 1)
    ref_label, ref_suffix = ref_reg.split(".", 1)
    cand_label, ref_label = _unicode(cand_label), _unicode(ref_label)
    userinfo = _userinfo(candidate)

    if cand_reg not in _SHARED_SERVICES:
        shown = _shown(cand_host, userinfo)
        if cand_label == ref_label:
            return f"{shown} imitates {ref_reg} (.{cand_suffix} instead of .{ref_suffix})"
        detail = _label_detail(cand_label, ref_label)
        if detail:
            return f"{shown} imitates {ref_reg} ({detail})"
        subdomain = cand_host[: -len(cand_reg)].rstrip(".") if cand_host.endswith(cand_reg) else ""
        decoy_parts = [p for p in f"{userinfo}.{subdomain}".split(".") if p]
        if any(_brand_in_part(p, ref_label) for p in decoy_parts):
            return f"{shown} imitates {ref_reg} (the site is really {cand_reg})"

    # A path is whatever the site's user typed, even on a shared service (sites.google.com/view/...).
    # Only the full domain counts: a bare name in a path is normal (github.com/coinbase).
    path = _path(candidate)
    if path and re.search(rf"(?<![a-z0-9]){re.escape(ref_reg)}(?![a-z0-9])", path):
        shown = f"{cand_host}{path}"
        shown = shown if len(shown) <= 60 else shown[:57] + "..."
        return f"{shown} imitates {ref_reg} (the page is on {cand_reg})"
    return None


def lookalike_finding(domains: Iterable[str], *, official_domain: Optional[str],
                      known_contact_domain: Optional[str]) -> Finding:
    """H3: does any domain involved imitate the official or the known contact's domain."""
    check = "H3_lookalike_domain"
    references = [r for r in (_registrable(official_domain), _registrable(known_contact_domain)) if r]
    references = list(dict.fromkeys(references))
    if not references:
        return unknown(check, "no official or known contact domain to compare against")
    lines: list[str] = []
    for candidate in domains:
        if not candidate or _registrable(candidate) in references:
            continue  # the real domain, or one of its subdomains
        reason = next((r for ref in references if (r := lookalike_reason(candidate, ref))), None)
        if reason and reason not in lines:
            lines.append(reason)
    if lines:
        return Finding(check=check, status="hit", evidence=[Evidence(summary=line) for line in lines])
    return clear(check, f"No link or email imitates {' or '.join(references)}")


# ---------------------------------------------------------------- H2

# Brand rule. A link's host (and any user@ part before it) is split into tokens on dots, hyphens
# and underscores, after folding homoglyphs (z00m -> zoom). A token uses a provider's name when:
#   - distinctive names (zoom, webex, skype): the token is the name, or the name glued to a
#     meeting word ("zoomus", "joinzoom", "webexmeeting"). So "zoominfo" doesn't count.
#   - generic words (teams, meet): only with a qualifier, glued ("msteams", "gmeet", "googlemeet",
#     "teamslive") or as the neighbouring token ("teams-live", "ms-teams", "google-meet",
#     "meet.google"). So "teamsnap", "meetup" and "meet.jit.si" don't count.
_MEETING_WORDS = frozenset({
    "us", "gov", "mtg", "meet", "meeting", "meetings", "call", "video", "join", "web", "app",
    "live", "link", "invite",
})
# (name shown, owner, brand word, qualifiers or None for distinctive names, official domains)
_PROVIDERS = (
    ("Zoom", "Zoom", "zoom", None, ("zoom.us", "zoom.com", "zoomgov.com")),
    ("Webex", "Cisco", "webex", None, ("webex.com",)),
    ("Skype", "Microsoft", "skype", None, ("skype.com",)),
    # cloud.microsoft hosts the new Teams web app; microsoft.us is Teams for US government.
    ("Microsoft Teams", "Microsoft", "teams", frozenset({"ms", "msft", "microsoft", "live"}),
     ("microsoft.com", "teams.live.com", "cloud.microsoft", "microsoft.us")),
    ("Google Meet", "Google", "meet", frozenset({"g", "google"}), ("google.com",)),
)


def _tokens(text: str) -> list[str]:
    folded = ".".join(_skeleton(_unicode(part))[0] for part in text.split("."))
    return [t for t in re.split(r"[.\-_]+", folded) if t]


def _uses_brand(tokens: list[str], word: str, qualifiers: Optional[frozenset[str]]) -> bool:
    if qualifiers is None:
        glued = {word} | {word + w for w in _MEETING_WORDS} | {w + word for w in _MEETING_WORDS}
        return any(t in glued for t in tokens)
    glued = {q + word for q in qualifiers} | {word + q for q in qualifiers}
    if any(t in glued for t in tokens):
        return True
    return any((a == word and b in qualifiers) or (b == word and a in qualifiers)
               for a, b in zip(tokens, tokens[1:]))


def _on_domain(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def meeting_link_finding(links: Iterable[str]) -> Finding:
    """H2: a link that uses a Zoom, Teams, Meet, Webex or Skype name on a host the provider doesn't own."""
    check = "H2_fake_meeting_link"
    lines: list[str] = []
    for link in links:
        host = _parse(link)[0]
        if not host:
            continue
        userinfo = _userinfo(link)
        tokens = _tokens(f"{userinfo}.{host}" if userinfo else host)
        for name, owner, word, qualifiers, official in _PROVIDERS:
            if _uses_brand(tokens, word, qualifiers) and not _on_domain(host, official):
                line = f"{_shown(host, userinfo)} uses the {name} name, but {owner} doesn't own it"
                if line not in lines:
                    lines.append(line)
                break
    if lines:
        return Finding(check=check, status="hit", evidence=[Evidence(summary=line) for line in lines])
    return clear(check, "No meeting link uses a Zoom, Teams, Meet or Webex name off their own domains")


# ---------------------------------------------------------------- C4

def off_official_domain_finding(supplied: Iterable[str], *, official_domain: Optional[str]) -> Finding:
    """C4: a domain the recruiter gave for the company that is unrelated to the official one.

    Free webmail and recruiting platforms say nothing about the company's own domain, so they are
    skipped (P1 and P2 cover the email). Lookalikes are skipped too: H3 counts them.
    """
    check = "C4_off_official_domain"
    official = _registrable(official_domain)
    if official is None:
        return unknown(check, "the company's official domain isn't known")
    items_by_reg: dict[str, list[str]] = {}
    for item in supplied:
        reg = _registrable(item)
        if reg and (reg == official or (reg not in FREE_WEBMAIL and reg not in ATS_SENDERS)):
            items_by_reg.setdefault(reg, []).append(item)
    if not items_by_reg:
        return unknown(check, "no company website or email domain was given")
    off = [reg for reg, items in items_by_reg.items()
           if reg != official and not any(lookalike_reason(i, official) for i in items)]
    if off:
        return Finding(check=check, status="hit", evidence=[
            Evidence(summary=f"{reg} isn't the company's official domain, {official}") for reg in off])
    if official in items_by_reg and len(items_by_reg) == 1:
        return clear(check, f"Every domain given is {official}")
    return clear(check, f"No unrelated domain given; lookalikes of {official} are counted separately")
