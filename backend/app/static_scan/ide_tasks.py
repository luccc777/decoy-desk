"""S1: a VS Code task that runs by itself when the folder is opened.

The 2025 Contagious Interview repos hid their loader in .vscode/tasks.json with
"runOptions": {"runOn": "folderOpen"}, often with a different command per OS
(the windows/linux/osx keys) and sometimes pushed far right with spaces.
A .code-workspace file can carry the same tasks, so it is read too.
"""

from __future__ import annotations

import re
from typing import Any, Optional

from app.rules.engine import Evidence, Finding
from app.static_scan.files import RepoFiles
from app.static_scan.jsonc import loads_jsonc, strip_jsonc
from app.static_scan.textutil import conclude, excerpt, shorten

CHECK = "S1_runs_on_folder_open"
OS_KEYS = (("windows", "Windows"), ("linux", "Linux"), ("osx", "macOS"))

_RUN_ON = re.compile(r'"runOn"\s*:\s*"folderOpen"', re.IGNORECASE)
_COMMAND = re.compile(r'"command"\s*:\s*"((?:[^"\\\n]|\\.)*)"')
_AUTO_TASKS_ON = re.compile(r'"task\.allowAutomaticTasks"\s*:\s*"on"', re.IGNORECASE)
_WIDE_GAP = re.compile(r"(?<![ \t])[ \t]{150,}(?=\S)")


def task_files(files: RepoFiles) -> list[str]:
    """Every .vscode/tasks.json and *.code-workspace in the repo, read or not."""
    found = [p for p in files.sizes if p.lower().endswith(".code-workspace")
             or (p.lower().endswith(".vscode/tasks.json") and (p.lower() == ".vscode/tasks.json"
                                                              or p.lower().endswith("/.vscode/tasks.json")))]
    return sorted(set(found) | {p for p in files.skipped if p.lower().endswith((".vscode/tasks.json", ".code-workspace"))})


def _value(v: Any) -> str:
    """A command or argument: a string, a list, or {"value": ..., "quoting": ...}."""
    if isinstance(v, dict):
        v = v.get("value", "")
    if isinstance(v, list):
        return " ".join(_value(x) for x in v)
    return str(v) if v is not None else ""


def _command_line(task: dict) -> str:
    if task.get("type") == "npm" and task.get("script"):
        return f"npm run {_value(task['script'])}"
    command = _value(task.get("command"))
    args = task.get("args")
    if isinstance(args, list) and args:
        command = (command + " " + " ".join(_value(a) for a in args)).strip()
    return command.strip()


def _runs_on_open(task: dict) -> bool:
    blocks = [task] + [task[k] for k, _ in OS_KEYS if isinstance(task.get(k), dict)]
    for block in blocks:
        options = block.get("runOptions")
        if isinstance(options, dict) and str(options.get("runOn", "")).lower() == "folderopen":
            return True
    return False


def _commands(task: dict) -> list[tuple[Optional[str], str]]:
    """(OS name or None, command line) for the task and each OS-specific override."""
    out: list[tuple[Optional[str], str]] = []
    base = _command_line(task)
    if base:
        out.append((None, base))
    for key, os_name in OS_KEYS:
        override = task.get(key)
        if isinstance(override, dict):
            line = _command_line({**task, **override}) if ("command" in override or "args" in override) else ""
            if line and line != base:
                out.append((os_name, line))
    return out


def _tasks_of(data: Any, path: str) -> list[dict]:
    if not isinstance(data, dict):
        return []
    if path.lower().endswith(".code-workspace"):
        data = data.get("tasks")
        if not isinstance(data, dict):
            return []
    tasks = data.get("tasks")
    return [t for t in tasks if isinstance(t, dict)] if isinstance(tasks, list) else []


def _depends_on(task: dict) -> list[str]:
    dep = task.get("dependsOn")
    if isinstance(dep, str):
        return [dep]
    if isinstance(dep, list):
        return [d for d in dep if isinstance(d, str)]
    return []


def _evidence_for(path: str, task: dict, by_label: dict[str, dict]) -> list[Evidence]:
    label = task.get("label") or task.get("taskName")
    named = f' (task "{shorten(str(label), 60)}")' if label else ""
    out = []
    for os_name, line in _commands(task):
        where = f" on {os_name}" if os_name else ""
        out.append(Evidence(summary=f"{path} runs a command when the folder opens{where}{named}",
                            source=path, quote=shorten(line)))
    for dep in _depends_on(task):
        other = by_label.get(dep)
        for os_name, line in _commands(other) if other else []:
            where = f" on {os_name}" if os_name else ""
            out.append(Evidence(summary=f'{path} first runs task "{shorten(dep, 60)}" when the folder opens{where}',
                                source=path, quote=shorten(line)))
    if not out:
        out.append(Evidence(summary=f"{path} runs a task when the folder opens{named}", source=path))
    return out


def scan_tasks_file(path: str, text: str) -> list[Evidence]:
    """Evidence for every task in one tasks.json or .code-workspace that runs on folder open."""
    try:
        data = loads_jsonc(text)
    except (ValueError, RecursionError):
        # VS Code reads broken JSON leniently, so a malformed file may still run its task.
        plain = strip_jsonc(text)
        m = _RUN_ON.search(plain)
        if not m:
            return []
        cmd = _COMMAND.search(plain)
        return [Evidence(summary=f"{path} asks VS Code to run a task when the folder opens "
                                 "(the file is malformed, so the exact command is unclear)",
                         source=path, quote=shorten(cmd.group(1)) if cmd else excerpt(plain, m.start(), m.end()))]
    tasks = _tasks_of(data, path)
    by_label = {str(t.get("label")): t for t in tasks if t.get("label")}
    out: list[Evidence] = []
    for task in tasks:
        if _runs_on_open(task):
            out.extend(_evidence_for(path, task, by_label))
    if out and (gap := _WIDE_GAP.search(text)):
        out.append(Evidence(summary=f"{path} hides part of a line {len(gap.group(0))} spaces to the right, "
                                    "off the edge of the editor", source=path,
                            quote=excerpt(text, gap.end())))
    return out


def check_folder_open(files: RepoFiles) -> Finding:
    paths = task_files(files)
    hits: list[Evidence] = []
    unread: list[str] = []
    for path in paths:
        text = files.text(path)
        if text is None:
            unread.append(path)
            continue
        hits.extend(scan_tasks_file(path, text))
    if hits:
        for settings in files.find("settings.json"):
            if settings.lower().endswith(".vscode/settings.json") and _AUTO_TASKS_ON.search(files.text(settings) or ""):
                hits.append(Evidence(summary=f"{settings} tells VS Code not to ask before running these tasks",
                                     source=settings))
    if not paths:
        return conclude(CHECK, [], "No VS Code tasks file in the repo")
    return conclude(CHECK, hits, f"{', '.join(paths[:3])}: no task runs when the folder opens", unread, files)
