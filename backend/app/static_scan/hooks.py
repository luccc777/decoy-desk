"""S6: git hooks the repo sets up, and whether they run more than ordinary tooling.

Hooks run on your own machine at every commit or push once husky or a similar
tool installs them, often from "prepare", so during npm install. Sources read:
.husky/, lefthook, .pre-commit-config.yaml, simple-git-hooks / husky v4 / yorkie
in package.json, .githooks/, any folder a script points core.hooksPath at, and
scripts that write into .git/hooks.

A hook is a hit when a line downloads (curl, wget, Invoke-WebRequest), names a
web address, runs inline or hidden code (node -e, python -c, eval, base64 -d,
a pipe into a shell, PowerShell), or runs a repo file that downloads. Ordinary
tools (lint-staged, eslint, prettier, tests, commitlint, ...) and other plain
commands stay clear; the clear evidence lists what the hooks run.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

import yaml

from app.rules.engine import Evidence, Finding
from app.static_scan.files import RepoFiles
from app.static_scan.manifest import local_files, normalize, package_scripts, script_target, split_commands
from app.static_scan.signals import EXEC_STRONG, FETCH, PIPE_TO_SHELL, first, language
from app.static_scan.textutil import conclude, dir_of, is_source, resolve, shorten

CHECK = "S6_git_hooks"

ORDINARY_TOOLS = frozenset({
    "lint-staged", "nano-staged", "pretty-quick", "eslint", "prettier", "stylelint", "biome", "oxlint",
    "tsc", "vue-tsc", "commitlint", "jest", "vitest", "mocha", "ava", "pytest", "ruff", "black", "flake8",
    "mypy", "isort", "pylint", "go", "gofmt", "golangci-lint", "cargo", "rustfmt", "git", "npm", "yarn",
    "pnpm", "bun", "turbo", "nx", "lerna", "cz", "git-cz", "validate-branch-name", "ls-lint", "sort-package-json",
})

RED_FLAGS: tuple[tuple[str, re.Pattern], ...] = tuple((name, re.compile(p, re.IGNORECASE)) for name, p in (
    ("downloads from the internet (curl)", r"\bcurl\b"),
    ("downloads from the internet (wget)", r"\bwget\b"),
    ("downloads from the internet (PowerShell)",
     r"\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm|DownloadString|DownloadFile|Net\.WebClient)\b"),
    ("opens a raw network connection", r"/dev/(?:tcp|udp)/|\b(?:nc|ncat|netcat|socat|telnet)\b"),
    ("runs inline Node.js code (node -e)", r"\bnode(?:\.exe)?\s+(?:-e|--eval|-p|--print)\b"),
    ("runs inline code", r"\bpython[23]?(?:\.exe)?\s+-c\b|\b(?:perl|ruby)\s+-e\b|\bphp\s+-r\b"),  # not ruby -c (syntax check)
    ("runs PowerShell", r"\b(?:powershell|pwsh)(?:\.exe)?\b"),
    ("runs cmd /c", r"\bcmd(?:\.exe)?\s+/c\b"),
    ("runs a built string as code (eval)", r"(?<![\w-])eval\s+[\"'$`]"),  # the shell builtin, not "no-eval"
    ("decodes hidden data (base64 -d)", r"\bbase64\s+(?:-d|--decode|-D)\b"),
    ("pipes text into a shell", PIPE_TO_SHELL),
    ("runs a system scripting tool", r"\b(?:osascript|mshta|rundll32|regsvr32|certutil|bitsadmin)\b"),
))
_URL = re.compile(r"\b(?:https?|wss?|ftp)://\S+", re.IGNORECASE)
_PRINT_LINE = re.compile(r"^\s*(?:echo|printf)\b")
_HUSKY_SOURCE = re.compile(r"""^\.\s+["']?\$\(dirname\b.*husky\.sh["']?\s*$""")
_SHELL_WORDS = frozenset({"then", "else", "fi", "do", "done", "esac", "{", "}", ";;", "exit", "exit 0", "exit 1",
                          "true", "false", ":", "set -e", "set -eu", "set -euo pipefail"})
_LEADING_WORD = re.compile(r"^(?:(?:if|elif|while|until|then|else|do|!|\{)\s+)+")
_BUILTIN = re.compile(r"^(?:echo|printf|exit|set|export|unset|local|read|cd|test|\[|\[\[|return|shift|exec\s*<|:|"
                      r"[A-Za-z_]\w*=)")
_HOOKS_PATH = re.compile(r"""core\.hooksPath(?:\s*=\s*|\s+)['"]?([^\s'"&;|)]+)""")
_GIT_HOOKS_DIR = re.compile(r"\.git[/\\]hooks\b")
HOOK_DIRS = frozenset({".husky", ".githooks", ".git-hooks"})
LEFTHOOK_FILES = frozenset({"lefthook.yml", "lefthook.yaml", ".lefthook.yml", ".lefthook.yaml",
                            "lefthook-local.yml", "lefthook-local.yaml"})
PRECOMMIT_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"})

WHEN = {
    "pre-commit": "every time you commit", "commit-msg": "every time you commit",
    "prepare-commit-msg": "every time you commit", "post-commit": "every time you commit",
    "pre-push": "every time you push", "post-checkout": "every time you switch branches or clone",
    "post-merge": "every time you pull or merge", "pre-merge-commit": "every time you merge",
    "pre-rebase": "before every rebase", "post-rewrite": "after every rebase or amend",
}


@dataclass
class Hook:
    origin: str     # where it is defined, e.g. ".husky/pre-commit" or "lefthook.yml"
    name: str       # the git hook, e.g. "pre-commit"
    body: str       # shell text
    base_dir: str = ""


@dataclass
class Context:
    files: RepoFiles
    scripts: dict[str, str]
    unread: list[str] = field(default_factory=list)
    ran: list[str] = field(default_factory=list)   # what the hooks run, for the clear evidence


# ---------------------------------------------------------------- reading a hook

def _lines(body: str) -> list[str]:
    return body.replace("\\\r\n", " ").replace("\\\n", " ").splitlines()


def _red_flag(line: str) -> Optional[str]:
    for name, pattern in RED_FLAGS:
        if pattern.search(line):
            return name
    if not _PRINT_LINE.match(line) and (m := _URL.search(line)):
        return f"contacts {shorten(m.group(0), 80)}"
    return None


def _head(part: str) -> str:
    words = part.split()
    if not words:
        return ""
    if words[0] in {"npm", "yarn", "pnpm", "bun"} and len(words) > 1:
        return " ".join(words[:3] if words[1] == "run" and len(words) > 2 else words[:2])
    return words[0]


def unusual(body: str, ctx: Context, base_dir: str = "", depth: int = 0) -> Optional[tuple[str, str]]:
    """(what it does, the line) for the first line of a hook that goes beyond ordinary tooling."""
    for raw in _lines(body):
        line = raw.strip()
        if not line or line.startswith("#") or _HUSKY_SOURCE.match(line):
            continue
        if reason := _red_flag(line):
            return reason, line
        for part in split_commands(line):
            part = normalize(_LEADING_WORD.sub("", part))
            if not part or part in _SHELL_WORDS or _BUILTIN.match(part):
                continue
            target = script_target(part, ctx.scripts)
            if target is not None:
                if target in ctx.scripts and depth < 3:
                    if found := unusual(ctx.scripts[target], ctx, base_dir, depth + 1):
                        return f"runs the {target} script, which {found[0]}", line
                ctx.ran.append(_head(part))
                continue
            for path in local_files(part, base_dir, ctx.files):
                if path.endswith("/_/husky.sh"):
                    continue
                text = ctx.files.text(path)
                if text is None:
                    ctx.unread.append(path)
                elif language(path) == "shell" and depth < 3:
                    if found := unusual(text, ctx, dir_of(path), depth + 1):
                        return f"runs {path}, which {found[0]}", line
                elif hit := first(FETCH, text) or first(EXEC_STRONG, text):
                    return f"runs {path}, which uses {hit[0]}", line
            ctx.ran.append(_head(part))
    return None


# ---------------------------------------------------------------- finding the hooks

def _hooks_in_dir(files: RepoFiles, directory: str, *, nested: bool = False, note: str = "") -> list[Hook]:
    """Hook files directly in directory; with nested, lefthook's <hook>/<script> layout."""
    prefix = directory.rstrip("/") + "/"
    out = []
    for path in sorted(files.sizes):
        rest = path[len(prefix):] if path.startswith(prefix) else ""
        if not rest or ("/" in rest) != nested or rest.count("/") > 1:
            continue
        file_name = path.rsplit("/", 1)[-1]
        if file_name.startswith(".") or file_name.endswith((".md", ".txt")):
            continue
        out.append(Hook(origin=path + note, name=rest.split("/", 1)[0], body=files.text(path) or ""))
    return out


def _walk_runs(node: Any, budget: list[int]) -> list[str]:
    """Every "run" string in a lefthook config, with a node budget against YAML alias bombs."""
    out: list[str] = []
    stack = [node]
    while stack and budget[0] > 0:
        item = stack.pop()
        budget[0] -= 1
        if isinstance(item, dict):
            for k, v in item.items():
                if k == "run" and isinstance(v, str):
                    out.append(v)
                else:
                    stack.append(v)
        elif isinstance(item, list):
            stack.extend(item)
    return out


def _load_yaml(text: str) -> Any:
    try:
        return yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError, ValueError):
        return None


def _config_hooks(files: RepoFiles, ctx: Context, flags: list[Evidence]) -> list[Hook]:
    hooks: list[Hook] = []
    for path in sorted(files.sizes):
        name = path.rsplit("/", 1)[-1].lower()
        if name in LEFTHOOK_FILES:
            text = files.text(path)
            if text is None:
                ctx.unread.append(path)
                continue
            data = _load_yaml(text)
            if isinstance(data, dict):
                budget = [20_000]  # one budget per file, shared by every hook in it
                for hook_name, spec in data.items():
                    for run in _walk_runs(spec, budget):
                        hooks.append(Hook(origin=f"{path} ({hook_name})", name=str(hook_name), body=run,
                                          base_dir=dir_of(path)))
        elif name in {".pre-commit-config.yaml", ".pre-commit-config.yml"}:
            text = files.text(path)
            if text is None:
                ctx.unread.append(path)
                continue
            data = _load_yaml(text)
            repos = data.get("repos") if isinstance(data, dict) else None
            for repo in repos if isinstance(repos, list) else []:
                if not isinstance(repo, dict):
                    continue
                url = str(repo.get("repo", ""))
                if url not in {"local", "meta"}:
                    host = (urlparse(url).hostname or "").lower()
                    if host not in PRECOMMIT_HOSTS:
                        flags.append(Evidence(summary=f"{path} pulls hook code from {shorten(url, 80)}, "
                                                      "outside the usual code hosts", source=path,
                                              quote=shorten(url)))
                    continue
                for h in repo.get("hooks") or []:
                    if not isinstance(h, dict) or h.get("language") in {"pygrep", "fail"}:
                        continue
                    args = h.get("args") if isinstance(h.get("args"), list) else []
                    body = " ".join([str(h.get("entry", ""))] + [str(a) for a in args])
                    stages = h.get("stages") or ["pre-commit"]
                    hooks.append(Hook(origin=f"{path} ({h.get('id', 'local hook')})",
                                      name=str(stages[0]) if isinstance(stages, list) and stages else "pre-commit",
                                      body=body, base_dir=dir_of(path)))
        elif name in {"package.json", ".simple-git-hooks.json", "simple-git-hooks.json"}:
            text = files.text(path)
            if text is None:
                continue  # an unread package.json is already S2's unknown
            try:
                data = json.loads(text.lstrip("\ufeff"))
            except (ValueError, RecursionError):
                continue
            if not isinstance(data, dict):
                continue
            tables = [data] if name != "package.json" else [
                data.get("simple-git-hooks"), (data.get("husky") or {}).get("hooks") if isinstance(
                    data.get("husky"), dict) else None, data.get("gitHooks"), data.get("ghooks")]
            for table in tables:
                if isinstance(table, dict):
                    for hook_name, command in table.items():
                        if isinstance(command, str) and hook_name != "preserveUnused":
                            hooks.append(Hook(origin=f"{path} ({hook_name})", name=hook_name, body=command,
                                              base_dir=dir_of(path)))
            pre_commit = data.get("pre-commit") if name == "package.json" else None
            names = [pre_commit] if isinstance(pre_commit, str) else pre_commit if isinstance(pre_commit, list) else []
            for script in names:
                if isinstance(script, str):
                    hooks.append(Hook(origin=f"{path} (pre-commit)", name="pre-commit", body=f"npm run {script}",
                                      base_dir=dir_of(path)))
    return hooks


def _hooks_path_dirs(files: RepoFiles, flags: list[Evidence]) -> list[tuple[str, str]]:
    """(folder, the file that sets it) for every git config core.hooksPath in the repo."""
    out = []
    for path, text in sorted(files.texts.items()):
        if "hooksPath" not in text or not (is_source(path, text) or path.endswith("package.json")
                                           or path.rsplit("/", 1)[-1] in {"Makefile", "justfile", "Taskfile.yml"}):
            continue
        for m in _HOOKS_PATH.finditer(text):
            target = resolve("", m.group(1))
            if target is None:
                flags.append(Evidence(summary=f"{path} points git's hooks at {shorten(m.group(1), 80)}, "
                                              "a folder outside the repo", source=path, quote=shorten(m.group(0))))
            else:
                out.append((target, path))
    return out


def _hook_writers(files: RepoFiles, flags: list[Evidence]) -> None:
    """Scripts that write into .git/hooks and also download something."""
    for path, text in sorted(files.texts.items()):
        if is_source(path, text) and _GIT_HOOKS_DIR.search(text) and (hit := first(FETCH, text)):
            flags.append(Evidence(summary=f"{path} writes git hooks and downloads from the internet ({hit[0]})",
                                  source=path, quote=shorten(text[max(0, hit[1].start() - 40):hit[1].end() + 120])))


def all_hooks(files: RepoFiles, ctx: Context, flags: list[Evidence]) -> list[Hook]:
    hooks: list[Hook] = []
    dirs = {p.rsplit("/", 1)[0] for p in files.sizes
            if "/" in p and p.rsplit("/", 1)[0].rsplit("/", 1)[-1] in HOOK_DIRS}
    for directory in sorted(dirs):
        hooks += _hooks_in_dir(files, directory)
    for directory in (".lefthook", ".lefthook-local"):
        hooks += _hooks_in_dir(files, directory, nested=True)
    for directory, setter in _hooks_path_dirs(files, flags):
        if directory not in dirs:
            dirs.add(directory)
            hooks += _hooks_in_dir(files, directory, note=f" (set by {setter})")
    hooks += _config_hooks(files, ctx, flags)
    _hook_writers(files, flags)
    return hooks


def check_git_hooks(files: RepoFiles) -> Finding:
    root = files.text("package.json")
    scripts = package_scripts(root)[0] if root else {}
    ctx = Context(files=files, scripts=scripts)
    flags: list[Evidence] = []
    hooks = all_hooks(files, ctx, flags)
    hits = list(flags)
    for hook in hooks:
        path = hook.origin.split(" (", 1)[0]
        if path in files.sizes and files.text(path) is None:
            ctx.unread.append(path)
            continue
        if found := unusual(hook.body, ctx, hook.base_dir):
            reason, line = found
            when = WHEN.get(hook.name, "when git runs this hook")
            hits.append(Evidence(summary=f"{hook.origin} {reason} {when}", source=path, quote=shorten(line)))
    if not hooks:
        return conclude(CHECK, hits, "The repo doesn't set up any git hooks", ctx.unread, files)
    ran = list(dict.fromkeys(r for r in ctx.ran if r))
    known = [r for r in ran if r.split()[0] in ORDINARY_TOOLS]
    other = [r for r in ran if r.split()[0] not in ORDINARY_TOOLS]
    summary = f"{len(hooks)} git hook(s) only run ordinary tools" + (f": {', '.join(known[:6])}" if known else "")
    notes = [f"They also run {', '.join(other[:4])}, which we don't recognise but which doesn't download "
             "or run hidden code"] if other else []
    return conclude(CHECK, hits, summary, ctx.unread, files, notes=notes)
