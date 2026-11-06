"""S2 and S3: what runs when someone installs the project.

npm runs the lifecycle scripts below on `npm install` (prepack and prepublish also
on pack, publish and installs from git). pip runs setup.py, including any
cmdclass override of install, develop or egg_info, and an in-tree build backend.
"""

from __future__ import annotations

import ast
import json
import re
import shlex
import tomllib
from dataclasses import dataclass, field
from typing import Optional

from app.rules.engine import Evidence, Finding
from app.static_scan.files import RepoFiles
from app.static_scan.signals import fetch_and_run, language
from app.static_scan.textutil import conclude, dir_of, excerpt, line_number, resolve, shorten

CHECK_SCRIPT = "S2_install_script"
CHECK_FETCH = "S3_install_fetches_remote_code"

LIFECYCLE = ("preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare", "prepack", "prepublish")
PY_COMMANDS = frozenset({"install", "develop", "egg_info"})

# Plain flags and paths only: no pipes, redirects, $(...), quotes or backslashes, so
# "husky install && curl x | sh" is never benign as a whole.
_ARGS = r"(?: [\w./=:@,*+-]+)*"

# Commands ordinary repos run on install. Each is matched against one whole command
# (split on && || ;) after env assignments and npx/pnpm exec/yarn prefixes are removed.
# A command alone on this list keeps S2 clear; the evidence still says what runs.
BENIGN_COMMANDS: tuple[tuple[str, str], ...] = (
    ("husky", rf"husky(?: install)?{_ARGS}"),                      # git hooks manager, v4 to v9
    ("is-ci", r"is-ci|ci-info"),                                     # as in "is-ci || husky install"
    ("a no-op", r"true|false|:|exit(?: \d+)?"),
    ("echo", r"echo(?: [^|&;<>$`\\]*)?"),
    ("cd", rf"cd{_ARGS}"),
    ("patch-package", rf"patch-package{_ARGS}"),                     # applies saved patches to node_modules
    ("prisma generate", rf"prisma generate{_ARGS}"),
    ("ngcc", rf"ngcc{_ARGS}"),                                       # Angular compatibility compiler
    ("tsc", rf"tsc{_ARGS}"),
    ("lerna bootstrap", rf"lerna bootstrap{_ARGS}"),
    ("node-gyp rebuild", rf"node-gyp rebuild{_ARGS}"),
    ("electron-builder install-app-deps", rf"electron-builder install-app-deps{_ARGS}"),
    ("electron-rebuild", rf"(?:electron-rebuild|@electron/rebuild){_ARGS}"),
    ("prebuilt native modules", rf"(?:prebuild-install|node-pre-gyp install|node-gyp-build){_ARGS}"),
    ("simple-git-hooks", rf"simple-git-hooks{_ARGS}"),
    ("lefthook install", rf"lefthook install{_ARGS}"),
    ("only-allow", r"only-allow (?:npm|yarn|pnpm|bun)"),
    ("svelte-kit sync", rf"svelte-kit sync{_ARGS}"),
    ("nuxt prepare", rf"nux[ti] prepare{_ARGS}"),
    ("installing dependencies", r"(?:npm|pnpm|bun) (?:install|ci|i)(?: --?[\w=./-]+)*|yarn(?: install)?(?: --?[\w=./-]+)*"),
    # What "npm run build" usually reaches; build tools read their own config files,
    # which the obfuscation and download checks read like any other source file.
    ("a build tool", r"(?:vite build|webpack|rollup|tsup|tshy|esbuild|babel|swc|next build|nuxt build|ng build"
                     r"|react-scripts build|vue-cli-service build|parcel build|astro build|svelte-kit build"
                     r"|turbo(?: run)? build|gulp|grunt|rimraf|del-cli|shx rm|tsc-alias|copyfiles|cpx|mkdirp"
                     rf"|mkdir){_ARGS}"),
)
_BENIGN = tuple((name, re.compile(pattern)) for name, pattern in BENIGN_COMMANDS)

_PREFIX = re.compile(
    r"^(?:(?:[A-Za-z_]\w*=\S*|cross-env|npx(?: --?[\w-]+)*(?: --)?|pnpx|bunx|pnpm (?:exec|dlx)"
    r"|yarn (?:exec|dlx)|npm exec(?: --)?)\s+)+")
_SCRIPT_TARGET = re.compile(
    r"^(?:(?P<npm>npm (?:run(?:-script)?|rum|urn)(?: --?[\w-]+)* |npm (?=(?:test|start|stop|restart)\b)"
    r"|yarn run |pnpm run |bun run )|(?P<bare>yarn |pnpm ))(?P<name>[\w:.@/-]+)")
_RUNNER = re.compile(r"^(?:yarn|pnpm|bun) ")
_SEPARATORS = re.compile(r"&&|\|\||[;&\n]")
_CODE_EXTS = (".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".py", ".sh", ".bash", ".ps1", ".bat", ".cmd")
_LOCAL_IMPORT = re.compile(
    r"""require\(\s*['"](\.{1,2}/[^'"\n]+)['"]\s*\)"""
    r"""|\bimport\s+(?:[^'";]{0,200}?\s+from\s+)?['"](\.{1,2}/[^'"\n]+)['"]"""
    r"""|\bimport\s*\(\s*['"](\.{1,2}/[^'"\n]+)['"]""")
_SCRIPTS_FALLBACK = re.compile(r'"(' + "|".join(LIFECYCLE) + r')"\s*:\s*"((?:[^"\\\n]|\\.)*)"')


# ---------------------------------------------------------------- commands

def split_commands(command: str) -> list[str]:
    """Splits a shell line on && || ; & and newlines, outside quotes. Pipes stay inside a part."""
    if "'" not in command and '"' not in command:
        return [p.strip() for p in _SEPARATORS.split(command) if p.strip()]
    parts, buf, quote, i = [], [], "", 0
    while i < len(command):
        c = command[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < len(command):
                buf.append(command[i:i + 2])
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif command.startswith(("&&", "||"), i):
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        elif c in ";&\n":
            parts.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def normalize(part: str) -> str:
    """One command without env assignments, npx-style prefixes or surrounding parentheses."""
    part = " ".join(part.strip().strip("()").split())
    return _PREFIX.sub("", part)


def script_target(part: str, scripts: dict[str, str]) -> Optional[str]:
    """The package.json script a command runs (npm run X, yarn X, pnpm X), if any."""
    m = _SCRIPT_TARGET.match(part)
    if not m:
        return None
    name = m.group("name")
    if m.group("bare") and name not in scripts:
        return None  # "yarn husky": a binary, not a script
    return name


def benign_tool(part: str) -> Optional[str]:
    for name, pattern in _BENIGN:
        if pattern.fullmatch(part):
            return name
    return None


@dataclass
class Classified:
    benign: bool = True
    tools: list[str] = field(default_factory=list)    # benign tools seen, for the clear evidence
    reached: list[str] = field(default_factory=list)  # script bodies reached through npm run
    unusual: list[str] = field(default_factory=list)  # the parts that aren't on the list


def classify(command: str, scripts: dict[str, str], _depth: int = 0, _seen: frozenset = frozenset()) -> Classified:
    """Whether a lifecycle command only runs benign tools, following npm run into other scripts."""
    out = Classified()
    for raw in split_commands(command):
        part = normalize(raw)
        if not part:
            continue
        target = script_target(part, scripts)
        if target is not None:
            if target not in scripts or target in _seen or _depth >= 4:
                continue  # a missing script fails without running anything; a loop stops here
            inner = classify(scripts[target], scripts, _depth + 1, _seen | {target})
            out.reached.append(scripts[target])
            out.reached.extend(inner.reached)
            out.tools.extend(inner.tools)
            out.unusual.extend(inner.unusual)
            out.benign = out.benign and inner.benign
            continue
        tool = benign_tool(part) or (benign_tool(_RUNNER.sub("", part)) if _RUNNER.match(part) else None)
        if tool:
            out.tools.append(tool)
        else:
            out.benign = False
            out.unusual.append(part)
    return out


def local_files(command: str, base_dir: str, files: RepoFiles) -> list[str]:
    """Repo files a command runs or loads, e.g. "node scripts/setup.js" -> scripts/setup.js."""
    found: list[str] = []
    for part in split_commands(command):
        try:
            # shlex is slow on huge input; a real command line is short.
            tokens = shlex.split(part, posix=True) if len(part) <= 2000 else part.split()
        except ValueError:
            tokens = part.split()
        for token in tokens:
            if token.startswith("-"):
                if "=" not in token:
                    continue
                token = token.split("=", 1)[1]
            if "/" not in token and not token.lower().endswith(_CODE_EXTS):
                continue
            if path := find_file(files, base_dir, token):
                found.append(path)
    return list(dict.fromkeys(found))


def find_file(files: RepoFiles, base_dir: str, target: str) -> Optional[str]:
    path = resolve(base_dir, target)
    if path is None:
        return None
    for candidate in (path, path + ".js", path + ".cjs", path + ".mjs", path + ".ts", path + "/index.js"):
        if candidate in files.sizes or candidate in files.texts:
            return candidate
    return None


def local_imports(path: str, text: str, files: RepoFiles) -> list[str]:
    """Repo files a JS file requires or imports by relative path."""
    out = []
    for m in _LOCAL_IMPORT.finditer(text):
        target = m.group(1) or m.group(2) or m.group(3)
        if found := find_file(files, dir_of(path), target):
            out.append(found)
    return list(dict.fromkeys(out))


# ---------------------------------------------------------------- manifests

@dataclass
class Step:
    manifest: str            # package.json, setup.py or pyproject.toml path
    hook: str                # "postinstall", "cmdclass install", ...
    command: str = ""        # the command as written, for npm
    classified: Classified = field(default_factory=Classified)
    summary: str = ""        # for Python steps, the plain-English line
    quote: Optional[str] = None

    @property
    def benign(self) -> bool:
        return bool(self.command) and self.classified.benign


def _unescape(s: str) -> str:
    try:
        return json.loads(f'"{s}"')
    except ValueError:
        return s


def package_scripts(text: str) -> tuple[dict[str, str], bool]:
    """(scripts, parsed): every string script; parsed is False when only a fallback scan was possible."""
    try:
        data = json.loads(text.lstrip("\ufeff"))
    except (ValueError, RecursionError):
        return {m.group(1): _unescape(m.group(2)) for m in _SCRIPTS_FALLBACK.finditer(text)}, False
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return {}, True
    return {k: v for k, v in scripts.items() if isinstance(k, str) and isinstance(v, str)}, True


def npm_steps(files: RepoFiles) -> tuple[list[Step], list[str]]:
    steps: list[Step] = []
    unread: list[str] = []
    for path in files.find("package.json"):
        text = files.text(path)
        if text is None:
            unread.append(path)
            continue
        scripts, _ = package_scripts(text)
        for hook in LIFECYCLE:
            command = scripts.get(hook, "").strip()
            if command:
                steps.append(Step(manifest=path, hook=hook, command=command,
                                  classified=classify(command, scripts)))
    return steps, unread


def _keys(node: ast.AST) -> Optional[list[str]]:
    if isinstance(node, ast.Dict):
        return [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "dict":
        return [kw.arg for kw in node.keywords if kw.arg]
    return None


def _call_name(node: ast.Call) -> str:
    f = node.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def setup_py_overrides(text: str) -> list[str]:
    """The pip steps (install, develop, egg_info) a setup.py replaces through cmdclass. Never runs it."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return _overrides_by_regex(text)
    nodes = list(ast.walk(tree))
    aliases = {c: c for c in PY_COMMANDS}  # "from setuptools.command.install import install as _install"
    for node in nodes:
        if isinstance(node, ast.ImportFrom) and node.module and re.fullmatch(
                r"(?:setuptools|distutils)\.command\.(?:install|develop|egg_info)", node.module):
            aliases.update({a.asname or a.name: a.name for a in node.names if a.name in PY_COMMANDS})

    def base_cmd(base: ast.AST) -> Optional[str]:
        name = base.id if isinstance(base, ast.Name) else base.attr if isinstance(base, ast.Attribute) else ""
        return aliases.get(name)

    subclassed = sorted({cmd for node in nodes if isinstance(node, ast.ClassDef)
                         for b in node.bases if (cmd := base_cmd(b))})
    named_dicts = {t.id: node.value for node in nodes if isinstance(node, ast.Assign)
                   for t in node.targets if isinstance(t, ast.Name) and _keys(node.value) is not None}
    found: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Call) and _call_name(node) == "setup":
            for kw in node.keywords:
                if kw.arg != "cmdclass":
                    continue
                value = named_dicts.get(kw.value.id, kw.value) if isinstance(kw.value, ast.Name) else kw.value
                keys = _keys(value)
                found.update(PY_COMMANDS & set(keys) if keys is not None else subclassed)
        if isinstance(node, ast.Assign):  # cmdclass["install"] = PostInstall
            for t in node.targets:
                if (isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant)
                        and t.slice.value in PY_COMMANDS
                        and isinstance(t.value, ast.Name) and "cmd" in t.value.id.lower()):
                    found.add(t.slice.value)
    return sorted(found)


def _overrides_by_regex(text: str) -> list[str]:
    """For a setup.py Python 3 can't parse (Python 2, say)."""
    found = set()
    for m in re.finditer(r"cmdclass\s*=\s*(?:\{([^{}]{0,800})\}|dict\(([^()]{0,800})\))", text):
        body = m.group(1) or m.group(2) or ""
        found.update(re.findall(r"""['"]?\b(install|develop|egg_info)\b['"]?\s*[:=]""", body))
    return sorted(found)


def _table(data: object, key: str) -> dict:
    value = data.get(key) if isinstance(data, dict) else None
    return value if isinstance(value, dict) else {}


def python_steps(files: RepoFiles) -> tuple[list[Step], list[str]]:
    steps: list[Step] = []
    unread: list[str] = []
    for path in files.find("setup.py"):
        text = files.text(path)
        if text is None:
            unread.append(path)
            continue
        for cmd in setup_py_overrides(text):
            m = re.search(r"cmdclass", text)
            steps.append(Step(manifest=path, hook=f"cmdclass {cmd}",
                              summary=f"{path} replaces pip's {cmd} step with its own code",
                              quote=excerpt(text, m.start()) if m else None))
    for path in files.find("pyproject.toml"):
        text = files.text(path)
        if text is None:
            unread.append(path)
            continue
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError, RecursionError):
            continue
        cmdclass = _table(_table(_table(data, "tool"), "setuptools"), "cmdclass")
        for cmd in sorted(PY_COMMANDS & set(cmdclass)):
            steps.append(Step(manifest=path, hook=f"cmdclass {cmd}",
                              summary=f"{path} replaces pip's {cmd} step with its own code",
                              quote=shorten(f"{cmd} = {cmdclass[cmd]}")))
        build = _table(data, "build-system")
        if backend_path := build.get("backend-path"):
            backend = build.get("build-backend", "")
            steps.append(Step(manifest=path, hook="build backend",
                              summary=f"{path} builds the package with its own code from the repo",
                              quote=shorten(f"build-backend = {backend}, backend-path = {backend_path}")))
    return steps, unread


# ---------------------------------------------------------------- the checks

def _what_runs(step: Step) -> str:
    reached = [r for r in step.classified.reached if r != step.command]
    return shorten(step.command + (f"  (which runs: {'; '.join(reached)})" if reached else ""))


def check_install_script(files: RepoFiles) -> Finding:
    npm, npm_unread = npm_steps(files)
    py, py_unread = python_steps(files)
    hits = [Evidence(summary=f"{s.manifest} runs a command when the project is installed ({s.hook})",
                     source=s.manifest, quote=_what_runs(s)) for s in npm if not s.benign]
    hits += [Evidence(summary=s.summary, source=s.manifest, quote=s.quote) for s in py]
    benign = [s for s in npm if s.benign]
    if benign:
        tools = list(dict.fromkeys(t for s in benign for t in s.classified.tools))
        clear_summary = (f"Installing only runs common tools ({', '.join(tools)}): "
                         + "; ".join(f"{s.hook}: {shorten(s.command, 60)}" for s in benign[:3]))
    else:
        clear_summary = "Installing the project doesn't run any script"
    return conclude(CHECK_SCRIPT, hits, clear_summary, npm_unread + py_unread, files)


def _fetch_run_evidence(text: str, lang: str, summary_head: str, source: str) -> Optional[Evidence]:
    found = fetch_and_run(text, lang)
    if not found:
        return None
    (fetch, _), (run, rm) = found
    where = f" (line {line_number(text, rm.start())})" if "\n" in text else ""
    return Evidence(summary=f"{summary_head} downloads code ({fetch}) and runs it ({run}){where}",
                    source=source, quote=excerpt(text, rm.start(), rm.end()))


def check_install_fetch(files: RepoFiles) -> Finding:
    npm, unread = npm_steps(files)
    hits: list[Evidence] = []
    for step in npm:
        base = dir_of(step.manifest)
        commands = [step.command] + step.classified.reached
        for command in commands:
            if ev := _fetch_run_evidence(command, "shell", f"{step.manifest} {step.hook}", step.manifest):
                hits.append(ev.model_copy(update={"quote": shorten(command)}))
        seen: set[str] = set()
        queue = [p for c in commands for p in local_files(c, base, files)]
        depth = {p: 0 for p in queue}
        while queue:
            path = queue.pop(0)
            if path in seen:
                continue
            seen.add(path)
            text = files.text(path)
            if text is None:
                unread.append(path)
                continue
            head = f"{step.manifest} {step.hook} runs {path}, which"
            if ev := _fetch_run_evidence(text, language(path), head, path):
                hits.append(ev)
            if depth[path] < 2 and language(path) == "js":
                for dep in local_imports(path, text, files):
                    if dep not in depth:
                        depth[dep] = depth[path] + 1
                        queue.append(dep)
    for path in files.find("setup.py"):
        text = files.text(path)
        if text is None:
            unread.append(path)
            continue
        if ev := _fetch_run_evidence(text, "py", f"{path}, which pip runs on install,", path):
            hits.append(ev)
    hits = list({(e.summary, e.quote): e for e in hits}.values())
    return conclude(CHECK_FETCH, hits, "No install step downloads code and runs it", unread, files)
