"""S10: code that downloads something and runs the response as code.

This is the BeaverTail / InvisibleFerret loader of the fake-interview repos:
axios.get(url).then(res => eval(res.data)), or new Function("require", res.data)(require).

The rule is strict on purpose. A sink (eval, new Function, vm.runIn*, exec) must get
the response itself: the network call inside its argument, or a name that holds
the response within DISTANCE characters after the call (the variable the call is
assigned to, the first parameter of a .then callback, the call's own callback
parameters, and names assigned from those). A sink fed a constant, and a network
call far from any sink, stay clear, which keeps webpack's runtime and lodash.template out.
"""

from __future__ import annotations

import bisect
import re

from app.rules.engine import Evidence, Finding
from app.static_scan.files import RepoFiles
from app.static_scan.textutil import conclude, excerpt, is_source, line_number, unread_sources

CHECK = "S10_runs_downloaded_code"
DISTANCE = 1200   # characters from the network call to the sink
ARG_LIMIT = 400   # characters of a sink's argument we read
MAX_PER_FILE = 3

_NET = re.compile(
    r"\baxios(?:\.\w+)?\s*\(|(?<![\w$.])fetch\s*\(|\bhttps?\.(?:get|request)\s*\("
    r"|\brequire\(\s*['\"](?:node:)?https?['\"]\s*\)\s*\.\s*(?:get|request)\s*\("
    r"|(?<![\w$.])(?:request|got|needle|superagent)(?:\.(?:get|post))?\s*\(|\bnew\s+XMLHttpRequest\b"
    r"|(?:\$|\bjQuery)\.(?:get|ajax|post)\s*\("
    r"|\brequests\.\w+\s*\(|\b(?:urllib\.request\.|urllib2\.)?urlopen\s*\(|\bhttpx\.\w+\s*\(")
_SINK = re.compile(
    r"(?P<name>\beval|\bnew\s+Function|\bFunction(?:\.constructor)?\)?|\.runIn(?:This|New)?Context"
    r"|\bvm\.compileFunction|\bnew\s+vm\.Script|(?<![\w$.])exec|\bchild_process\.exec(?:Sync)?"
    r"|\bos\.system|\bsubprocess\.(?:run|call|Popen|check_output|check_call))\s*\(")
_NET_WORDS = ("axios", "fetch", "http", "request", "got", "needle", "superagent", "XMLHttpRequest", "$.",
              "jQuery.", "urlopen", "httpx")
_SINK_WORDS = ("eval", "Function", "runIn", "vm.", "exec", "os.system", "subprocess")
_THEN_SINK = re.compile(r"\.then\s*\(\s*(?:(?:window|globalThis|global|self)\.)?(?:eval|Function)\s*\)")

_ASSIGNED_TO = re.compile(
    r"(\{[^{}=;]{0,120}\}|[A-Za-z_$][\w$]*)\s*=\s*(?:\(\s*)?(?:await\s+)?(?:\(\s*)?(?:await\s+)?$")
_THEN_PARAM = re.compile(
    r"\.then\s*\(\s*(?:async\s+)?(?:function\b\s*[\w$]*\s*)?\(?\s*(\{[^{}]{0,120}\}|[A-Za-z_$][\w$]*)")
_CALLBACK_PARAMS = re.compile(
    r"(?:function\b\s*[\w$]*\s*)?\(\s*([A-Za-z_$][\w$]*(?:\s*,\s*[A-Za-z_$][\w$]*){0,4})\s*\)\s*(?:=>|\{)"
    r"|\b([A-Za-z_$][\w$]*)\s*=>")
_ON_DATA = re.compile(r"\.on\s*\(\s*['\"]data['\"]\s*,\s*(?:async\s+)?(?:function\b\s*[\w$]*\s*)?\(?\s*([A-Za-z_$][\w$]*)")
_WITH_AS = re.compile(r"\bas\s+([A-Za-z_]\w*)\s*:")
_ASSIGN = re.compile(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*(?:\+=|=(?![=>]))\s*([^;\n]{1,200})")
_PUSH = re.compile(r"\b([A-Za-z_$][\w$]*)\.push\s*\(\s*([A-Za-z_$][\w$]*)")
_WORD = re.compile(r"[A-Za-z_$][\w$]*")
_STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'|`(?:[^`\\]|\\.)*`', re.DOTALL)
_TEMPLATE_EXPR = re.compile(r"\$\{([^}]*)\}")
_RESPONSE_MEMBERS = frozenset({"responseText", "responseBody"})
_NOT_NAMES = frozenset({"function", "async", "await", "return", "new", "this", "const", "let", "var",
                        "if", "else", "true", "false", "null", "undefined", "err", "error"})


def _args(text: str, start: int) -> str:
    """The argument text of a call whose "(" ends just before start, cut at ARG_LIMIT."""
    limit = min(len(text), start + ARG_LIMIT)
    close = text.find(")", start, limit)
    if close >= 0 and not any(c in "([{\"'`" for c in text[start:close]):
        return text[start:close]  # the common case, eval(res.data)
    depth, quote, j = 1, "", start
    while j < limit:
        c = text[j]
        if quote:
            if c == "\\":
                j += 2
                continue
            if c == quote:
                quote = ""
        elif c in "\"'`":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return text[start:j]


def _code_only(arg: str) -> str:
    """The argument with string constants emptied; template literals keep their ${...} parts."""
    def repl(m: re.Match) -> str:
        s = m.group(0)
        return " ".join(_TEMPLATE_EXPR.findall(s)) if s.startswith("`") else '""'
    return _STRING.sub(repl, arg)


def _names(binding: str) -> set[str]:
    """Names bound by "res" or a destructuring like "{ data }" / "{ data: code }"."""
    if binding.startswith("{"):
        out = set()
        for item in binding.strip("{} ").split(","):
            item = item.split("=")[0]
            name = item.split(":")[-1].strip()
            if _WORD.fullmatch(name):
                out.add(name)
        return out
    return {binding}


def _response_names(text: str, net: re.Match, end: int) -> set[str]:
    names: set[str] = set()
    if m := _ASSIGNED_TO.search(text, max(0, net.start() - 160), net.start()):
        names |= _names(m.group(1))
    region = text[net.start():end]
    own_args = _args(text, net.end()) if text[net.end() - 1:net.end()] == "(" else ""
    if m := _CALLBACK_PARAMS.search(own_args):  # https.get(url, res => ...), request(url, (err, res, body) => ...)
        names |= {n.strip() for n in (m.group(1) or m.group(2)).split(",")}
    for pattern in (_THEN_PARAM, _ON_DATA):
        for m in pattern.finditer(region):
            names |= _names(m.group(1))
    if m := _WITH_AS.search(region, 0, 300):  # with urlopen(url) as resp:
        names.add(m.group(1))
    names -= _NOT_NAMES
    if not names:
        return names
    for m in sorted(list(_ASSIGN.finditer(region)) + list(_PUSH.finditer(region)), key=lambda m: m.start()):
        if m.group(1) not in names and set(_WORD.findall(m.group(2))) & names:
            names.add(m.group(1))
    return names - _NOT_NAMES


def _label(sink: str) -> str:
    if "Function" in sink:
        return "new Function"
    if "runIn" in sink:
        return "vm" + sink
    return " ".join(sink.split())


def find_downloaded_code_runs(path: str, text: str) -> list[Evidence]:
    """Evidence for the places one file runs a network response as code (at most MAX_PER_FILE)."""
    if not any(w in text for w in _SINK_WORDS) or not any(w in text for w in _NET_WORDS):
        return []  # cheap test first: most files have no sink or no network call at all
    sinks = list(_SINK.finditer(text))
    then_sinks = list(_THEN_SINK.finditer(text))
    if not sinks and not then_sinks:
        return []
    nets = list(_NET.finditer(text))
    if not nets:
        return []
    starts = [m.start() for m in nets]
    names: dict[int, set[str]] = {}  # per network call, the names that hold its response
    out: list[Evidence] = []

    def add(pos: int, end: int, how: str) -> None:
        out.append(Evidence(summary=f"{path} downloads something and runs it as code with {how} "
                                    f"(line {line_number(text, pos)})",
                            source=path, quote=excerpt(text, pos, end)))

    def nearby(pos: int) -> list[re.Match]:
        i = bisect.bisect_left(starts, pos)
        return [nets[k] for k in range(i - 1, max(-1, i - 4), -1) if pos - starts[k] <= DISTANCE]

    def response_names(net: re.Match) -> set[str]:
        if net.start() not in names:
            names[net.start()] = _response_names(text, net, min(len(text), net.start() + DISTANCE))
        return names[net.start()]

    for sink in sinks:
        if len(out) >= MAX_PER_FILE:
            break
        arg = _code_only(_args(text, sink.end()))
        words = set(_WORD.findall(arg))
        if not words:
            continue  # a constant: eval("1 + 1")
        label = _label(sink.group("name"))
        if _NET.search(arg) or any(words & _RESPONSE_MEMBERS or words & response_names(net)
                                   for net in nearby(sink.start())):
            add(sink.start(), sink.end(), label)
    for m in then_sinks[:MAX_PER_FILE]:
        if nearby(m.start()):
            add(m.start(), m.end(), "eval")
    return out[:MAX_PER_FILE]


def check_downloaded_code(files: RepoFiles) -> Finding:
    hits: list[Evidence] = []
    read = 0
    for path, text in sorted(files.texts.items()):
        if not is_source(path, text):
            continue
        read += 1
        hits.extend(find_downloaded_code_runs(path, text))
    return conclude(CHECK, hits, f"Read {read} source file(s); none runs a download as code",
                    unread_sources(files), files)
