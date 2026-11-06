"""Words that mean "downloads something" and "runs something", shared by the install and hook checks.

Each signal has a plain name for the evidence card. They are matched on text only.
"""

from __future__ import annotations

import re
from typing import NamedTuple, Optional


class Signal(NamedTuple):
    name: str
    pattern: re.Pattern


def _s(name: str, pattern: str, flags: int = 0) -> Signal:
    return Signal(name, re.compile(pattern, flags))


FETCH = (
    _s("curl", r"\bcurl\b"),
    _s("wget", r"\bwget\b"),
    _s("Invoke-WebRequest", r"\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b", re.IGNORECASE),
    _s("a .NET web client", r"\b(?:DownloadString|DownloadFile|DownloadData|Net\.WebClient)\b"),
    _s("certutil", r"\bcertutil\b[^\n]{0,80}-urlcache", re.IGNORECASE),
    _s("bitsadmin", r"\bbitsadmin\b", re.IGNORECASE),
    _s("http.get", r"\bhttps?\.(?:get|request)\s*\(|\brequire\(\s*['\"](?:node:)?https?['\"]\s*\)\s*\.\s*(?:get|request)\s*\("),
    _s("fetch", r"(?<![\w$.])fetch\s*\("),
    _s("axios", r"\baxios\b"),
    _s("got", r"(?<![\w$.])got(?:\.\w+)?\s*\("),
    _s("request", r"(?<![\w$.])request(?:\.(?:get|post))?\s*\("),
    _s("XMLHttpRequest", r"\bXMLHttpRequest\b"),
    _s("node-fetch", r"""['"](?:node-fetch|undici|needle|superagent)['"]"""),
    _s("urllib", r"\burllib\b|\burlopen\s*\("),
    _s("requests", r"\brequests\.(?:get|post|request)\s*\("),
    _s("httpx", r"\bhttpx\.(?:get|post|stream)\s*\("),
)

# "| sh", "| bash -s --", "| node -": an interpreter reading its code from the pipe. Only flags may
# follow, so "| node scripts/parse.js" (data piped into a repo script) doesn't count.
PIPE_TO_SHELL = (r"(?<!\|)\|(?!\|)\s*(?:sudo\s+(?:-\w+\s+)*)?"
                 r"(?:sh|bash|zsh|dash|ksh|cmd|powershell|pwsh|python[23]?|node|perl|ruby|iex)(?:\.exe)?"
                 r"(?:\s+-[\w-]*)*\s*(?:$|[;&|)'\"`])")

# Runs whatever it is given: enough on its own once something was downloaded.
EXEC_STRONG = (
    _s("eval", r"\beval\s*\("),
    _s("new Function", r"\bFunction(?:\.constructor)?\)?\s*\("),
    _s("vm.runInThisContext", r"\.runIn(?:This|New)?Context\s*\(|\bnew\s+vm\.Script\b|\bvm\.compileFunction\b"),
    _s("a pipe into a shell", PIPE_TO_SHELL, re.MULTILINE | re.IGNORECASE),
    _s("Invoke-Expression", r"\b(?:iex|Invoke-Expression)\b", re.IGNORECASE),
    _s("a shell running the download", r"\$\(\s*(?:curl|wget)\b|`\s*(?:curl|wget)\b|<\(\s*(?:curl|wget)\b"),
)
PY_EXEC = _s("exec", r"(?<![\w.$])exec\s*\(")

# Runs a program: counts only when the same code also saves the download to disk,
# so "download a file, run tar" stays apart from "download a script, run it" as much as text allows.
EXEC_WEAK = (
    _s("child_process", r"\bchild_process\b[\s\S]{0,4000}?\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\("),
    _s("subprocess", r"\bsubprocess\.\w+\s*\(|\bos\.(?:system|popen|exec\w*)\s*\("),
    _s("a shell running the saved file", r"&&\s*(?:sudo\s+)?(?:sh|bash|zsh|node|python[23]?|pwsh|powershell|cmd|\./)"),
    _s("chmod +x", r"\bchmod\s+(?:[ugoa]*\+x|[0-7]*[1357])\b"),
    _s("Start-Process", r"\bStart-Process\b", re.IGNORECASE),
)
_WRITES_CODE = (r"writeFileSync|writeFile\s*\(|createWriteStream|urlretrieve|open\([^)\n]{0,200}['\"][wa]b?\+?['\"]"
                r"|\s-[oO]\s|--output\b|-OutFile\b|Out-File\b")
WRITES_FILE = {
    "js": re.compile(_WRITES_CODE, re.IGNORECASE),
    "py": re.compile(_WRITES_CODE, re.IGNORECASE),
    # Shell adds the > redirect, which in code would mostly be a comparison.
    "shell": re.compile(_WRITES_CODE + r"|(?<![=\-<>])>{1,2}\s*[\w./$~\"'-]", re.IGNORECASE),
}


def first(signals: tuple[Signal, ...], text: str) -> Optional[tuple[str, re.Match]]:
    for sig in signals:
        if m := sig.pattern.search(text):
            return sig.name, m
    return None


def language(path: str) -> str:
    """How fetch_and_run reads a file: "py", "shell" or "js" (the default, also for TypeScript)."""
    name = path.lower()
    if name.endswith((".py", ".pyw")):
        return "py"
    if name.endswith((".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd")) or "." not in name.rsplit("/", 1)[-1]:
        return "shell"
    return "js"


Hit = tuple[str, re.Match]


def fetch_and_run(text: str, lang: str = "shell") -> Optional[tuple[Hit, Hit]]:
    """(fetch, run) signals when the text both downloads and runs code, else None.

    lang is "js", "py" or "shell"; "shell" is also right for package.json commands,
    which may hold inline code (node -e, python -c).
    """
    fetch = first(FETCH, text)
    if fetch is None:
        return None
    run = first(EXEC_STRONG + ((PY_EXEC,) if lang in ("py", "shell") else ()), text)
    if run is None and WRITES_FILE[lang].search(text):
        run = first(EXEC_WEAK, text)
    return (fetch, run) if run else None
