"""S11-S14: what the code would do to your machine, read without running it.

S11  runs a hidden or encoded shell command (PowerShell -EncodedCommand or a hidden
     window, a download piped into Invoke-Expression, certutil/bitsadmin/mshta downloads)
S12  points at where keys, browser passwords or crypto wallets are stored
S13  connects straight to a hard-coded public IP address, or opens a remote shell
S14  walks through every file in the home folder

Plain patterns over code and config files; documentation is skipped so a README
that describes an attack doesn't count as one. Pure: nothing here runs the code.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional

from app.rules.engine import Evidence, Finding
from app.static_scan.files import RepoFiles
from app.static_scan.textutil import conclude, excerpt, is_bundle, is_source, line_number, unread_sources

MAX_PER_FILE = 3
_DOC_EXTS = (".md", ".markdown", ".rst", ".txt", ".adoc", ".html", ".htm", ".lock")
_CONFIG_EXTS = (".json", ".jsonc", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".plist", ".xml")
_SEP = r"[\s'\",]+"  # between arguments, also when written as a list: "-WindowStyle", "Hidden"
_PS = r"\b(?:powershell|pwsh)(?:\.exe)?\b"


def _r(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


HIDDEN_SHELL = (
    ("PowerShell with an encoded command", _r(_PS + r"[^\n]{0,240}?" + _SEP + r"-(?:e|ec|enc|encodedcommand)\b")),
    ("PowerShell in a hidden window", _r(_PS + r"[^\n]{0,240}?-(?:w|win|windowstyle)" + _SEP + r"hidden\b")),
    ("PowerShell told to ignore the execution policy",
     _r(_PS + r"[^\n]{0,240}?-(?:ep|exec|executionpolicy)" + _SEP + r"bypass\b")),
    ("a download run with Invoke-Expression",
     _r(r"\b(?:iex|invoke-expression)\b[^\n]{0,200}(?:downloadstring|downloadfile|net\.webclient|invoke-webrequest"
        r"|invoke-restmethod|\biwr\b|\birm\b)")),
    ("a download piped into Invoke-Expression",
     _r(r"(?:downloadstring|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b)[^\n]{0,200}\|\s*(?:iex|invoke-expression)\b")),
    ("certutil used to download a file", _r(r"\bcertutil(?:\.exe)?\b[^\n]{0,80}-urlcache\b")),
    ("bitsadmin used to download a file", _r(r"\bbitsadmin(?:\.exe)?\b[^\n]{0,80}/transfer\b")),
    ("mshta running a web page", _r(r"\bmshta(?:\.exe)?\b[^\n]{0,40}(?:https?://|javascript:|vbscript:)")),
    ("regsvr32 loading a remote script", _r(r"\bregsvr32(?:\.exe)?\b[^\n]{0,80}/i:\s*https?://")),
    # Seen live on ike/cursor-task-hijack and upsurge0/assessment2: a folder-open task that decodes base64
    # and pipes it into zsh or node. Only the model caught them before these patterns.
    ("base64 decoded and piped into an interpreter",
     _r(r"\bbase64\s+(?:-d|--decode|-D)\b[^|\n]{0,80}\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|node|python[23]?|perl|ruby|pwsh)\b")),
    ("base64 decoded and handed to an interpreter",
     _r(r"\b(?:node|python[23]?|perl|ruby|(?:ba|z)?sh)\s+-[ec]\s+\\?[\"']?\$\([^)\n]{0,240}base64\s+(?:-d|--decode|-D)\b")),
    # Seen live on upsurge0/assessment2: node -e "console.log(atob('...'))" | node, after 768 spaces.
    ("decoded output piped into an interpreter",
     _r(r"\b(?:node|python[23]?)\s+-[ec]\s+[^\n]{0,600}?(?:atob|b64decode|base64)[^\n]{0,600}?\|\s*"
        r"(?:node|python[23]?|(?:ba|z)?sh)\b")),
    ("a command pushed off-screen with spaces", _r(r"\"(?:command|args|program)\"\s*:\s*\[?[ \t]{40,}\"")),
    ("base64 decoded and run as code",
     _r(r"(?:\beval|\bnew\s+function|\bexec)\s*\(\s*(?:buffer\.from|atob|base64\.b64decode"
        r"|__import__\(\s*['\"]base64['\"]\s*\)\.b64decode)\s*\("
        r"|frombase64string[^\n]{0,200}\b(?:iex|invoke-expression)\b|\b(?:iex|invoke-expression)\b[^\n]{0,200}frombase64string")),
)

SECRET_STORES = (
    ("an SSH private key", _r(r"\.ssh[\\/]+id_(?:rsa|dsa|ecdsa|ed25519)\b")),
    ("cloud credentials", _r(r"\.aws[\\/]+credentials\b|\.config[\\/]+gcloud\b|\.azure[\\/]+(?:accesstokens|msal)"
                             r"|\.kube[\\/]+config\b|\.git-credentials\b|\.docker[\\/]+config\.json\b")),
    ("saved browser passwords or cookies",
     _r(r"\b(?:login data|local state)\b|user data[\\/]+default[\\/]+(?:cookies|network)"
        r"|\bcookies\.sqlite\b|\blogins\.json\b|\bkey4\.db\b")),
    ("a crypto wallet",
     _r(r"\bnkbihfbeogaeaoehlefnkodbefgpgknn\b|\bbfnaelmomeimhlpmgjnjophhpkkoljpa\b|\bhnfanknocfeofbddgcijnmhnfnkdnaad\b"
        r"|exodus[\\/]+exodus\.wallet|\.config[\\/]+solana[\\/]+id\.json|\bwallet\.dat\b|\.electrum[\\/]+wallets")),
    ("the macOS keychain", _r(r"\blogin\.keychain(?:-db)?\b|\bsecurity\s+find-generic-password\b")),
)

REMOTE_SHELL = (
    ("a shell sent over a raw connection", _r(r"/dev/tcp/[\w.-]+/\d+")),
    ("netcat handing out a shell", _r(r"\bn(?:c|cat)\b[^\n]{0,60}\s-(?:e|c)\s+\S*(?:sh|cmd|powershell)\b")),
    ("a terminal attached to a socket", _r(r"\bpty\.spawn\s*\(")),
)
_LOCAL_NETS = tuple(ipaddress.IPv4Network(n) for n in
                    ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "255.255.255.255/32"))
# Only addresses the code uses: inside quotes or a URL, not ones mentioned in prose or comments.
_IP = re.compile(r"(?:['\"`]|://|@)(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
_NET_WORDS = _r(r"\b(?:socket|connect|create_connection|fetch|axios|requests|urllib|http\.client|httpx|net\.socket"
                r"|websocket|invoke-webrequest|invoke-restmethod|webclient|curl|wget|tcpclient)\b")

HOME_WALK = (
    ("os.walk over the home folder",
     _r(r"os\.walk\(\s*(?:str\(\s*)?(?:path(?:lib\.path)?\.home\(\)|os\.path\.expanduser\(\s*['\"]~['\"]\s*\)"
        r"|os\.environ(?:\.get\(|\[)\s*['\"](?:home|userprofile)['\"]|os\.getenv\(\s*['\"](?:home|userprofile)['\"])")),
    ("a recursive search from the home folder",
     _r(r"path(?:lib\.path)?\.home\(\)\s*\.\s*rglob\(|glob\.i?glob\([^)\n]{0,60}~[^)\n]{0,80}recursive\s*=\s*true")),
    ("Node reading the home folder",
     _r(r"(?:readdir(?:sync)?|opendir(?:sync)?|walk\w*|glob\w*)\s*\(\s*(?:require\(\s*['\"](?:node:)?os['\"]\s*\)\.|os\.)homedir\(\)"
        r"|(?:readdir(?:sync)?|walk\w*|glob\w*)\s*\(\s*process\.env\.(?:home|userprofile)\b")),
    ("PowerShell listing the whole user folder",
     _r(r"\b(?:get-childitem|gci)\b[^\n]{0,80}(?:\$env:userprofile|\$home)\b[^\n]{0,80}-recurse"
        r"|\b(?:get-childitem|gci)\b[^\n]{0,80}-recurse[^\n]{0,80}(?:\$env:userprofile|\$home)\b")),
    ("find over the home folder", _r(r"\bfind\s+(?:~|\$home|\$\{home\})(?:/|\s)[^\n]{0,80}-(?:name|type|iname)\b")),
)


def _in_scope(path: str, text: str) -> bool:
    low = path.lower()
    if low.endswith(_DOC_EXTS) or "/node_modules/" in f"/{low}" or is_bundle(path, text):
        return False
    return is_source(path, text) or low.endswith(_CONFIG_EXTS) or "." not in low.rsplit("/", 1)[-1]


def _find(path: str, text: str, signals) -> list[Evidence]:
    found: list[Evidence] = []
    for label, pattern in signals:
        for m in pattern.finditer(text):
            found.append(Evidence(summary=f"{label} in {path}, line {line_number(text, m.start())}: "
                                          f"{excerpt(text, m.start(), m.end())}"))
            break  # one line per kind of signal and file is enough proof
        if len(found) >= MAX_PER_FILE:
            break
    return found


def _public_ip(text: str) -> Optional[tuple[str, int]]:
    for m in _IP.finditer(text):
        try:
            ip = ipaddress.IPv4Address(m.group(1))
        except ValueError:
            continue
        # Python's is_private also covers the documentation ranges, so local networks are listed by hand.
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast or ip.is_reserved \
                or any(ip in net for net in _LOCAL_NETS):
            continue
        if text[max(0, m.start(1) - 3): m.start(1)] == "://":  # inside a URL: the call can be a few lines off
            window = text[max(0, m.start() - 300): m.end() + 300]
        else:  # a quoted address only counts on the same line as a network call
            # Seen live: psf/requests tests have assert is_ipv4_address("8.8.8.8") near "socket".
            start = text.rfind("\n", 0, m.start()) + 1
            end = text.find("\n", m.end())
            window = text[start: end if end >= 0 else len(text)]
        if _NET_WORDS.search(window):
            return str(ip), m.start(1)
    return None


_TEST_PATH = re.compile(r"(?:^|/)(?:tests?|__tests__|spec|fixtures?)/|(?:^|/)test_[^/]*\.py$|_test\.py$"
                        r"|\.(?:test|spec)\.[cm]?[jt]sx?$", re.IGNORECASE)


def _ip_connections(path: str, text: str) -> list[Evidence]:
    found = _find(path, text, REMOTE_SHELL)
    hit = None if _TEST_PATH.search(path) else _public_ip(text)  # tests are full of sample addresses
    if hit:
        ip, pos = hit
        found.append(Evidence(summary=f"a connection to the hard-coded address {ip} in {path}, "
                                      f"line {line_number(text, pos)}: {excerpt(text, pos)}"))
    return found


def _scan(files: RepoFiles, check: str, finder, clear_summary: str) -> Finding:
    hits: list[Evidence] = []
    read = 0
    for path, text in sorted(files.texts.items()):
        if not _in_scope(path, text):
            continue
        read += 1
        hits.extend(finder(path, text))
    return conclude(check, hits, clear_summary.format(read=read), unread_sources(files), files)


def check_hidden_shell(files: RepoFiles) -> Finding:
    return _scan(files, "S11_hidden_shell_command", lambda p, t: _find(p, t, HIDDEN_SHELL),
                 "Read {read} code and config file(s); no hidden or encoded shell command")


def check_secret_stores(files: RepoFiles) -> Finding:
    return _scan(files, "S12_reads_secret_stores", lambda p, t: _find(p, t, SECRET_STORES),
                 "Read {read} code and config file(s); none points at keys, passwords or wallets")


def check_hardcoded_ip(files: RepoFiles) -> Finding:
    return _scan(files, "S13_connects_to_hardcoded_ip", _ip_connections,
                 "Read {read} code and config file(s); no connection to a hard-coded address or remote shell")


def check_home_walk(files: RepoFiles) -> Finding:
    return _scan(files, "S14_walks_home_directory", lambda p, t: _find(p, t, HOME_WALK),
                 "Read {read} code and config file(s); none walks through your home folder")
