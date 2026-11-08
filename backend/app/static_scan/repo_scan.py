"""Layer 2 for repos: reads the code without running it and answers S1-S6 and S10.

Pure: no network, no clock, no subprocess, and nothing from the repo is ever
imported or run. Every check gives exactly one finding. A check that crashes
on a hostile file becomes unknown, never clear, and never takes the others down.
"""

from __future__ import annotations

from collections.abc import Callable

from app.legitimacy.common import unknown
from app.rules.engine import Finding
from app.static_scan.behaviors import check_hardcoded_ip, check_hidden_shell, check_home_walk, check_secret_stores
from app.static_scan.files import RepoFiles
from app.static_scan.hidden_urls import check_hidden_urls
from app.static_scan.hooks import check_git_hooks
from app.static_scan.ide_tasks import check_folder_open
from app.static_scan.manifest import check_install_fetch, check_install_script
from app.static_scan.obfuscation import check_obfuscation
from app.static_scan.remote_exec import check_downloaded_code

CHECKS: tuple[tuple[str, Callable[[RepoFiles], Finding]], ...] = (
    ("S1_runs_on_folder_open", check_folder_open),
    ("S2_install_script", check_install_script),
    ("S3_install_fetches_remote_code", check_install_fetch),
    ("S4_obfuscated_code", check_obfuscation),
    ("S5_hidden_urls", check_hidden_urls),
    ("S6_git_hooks", check_git_hooks),
    ("S10_runs_downloaded_code", check_downloaded_code),
    ("S11_hidden_shell_command", check_hidden_shell),
    ("S12_reads_secret_stores", check_secret_stores),
    ("S13_connects_to_hardcoded_ip", check_hardcoded_ip),
    ("S14_walks_home_directory", check_home_walk),
)


def scan_repo(files: RepoFiles) -> list[Finding]:
    """One finding for each check in CHECKS (S1-S6, S10-S14), in that order."""
    findings = []
    for check, run in CHECKS:
        try:
            finding = run(files)
        except Exception as e:  # a bug or a hostile file must not take the verdict down
            finding = unknown(check, f"the check failed on this repo ({type(e).__name__})")
        findings.append(finding)
    return findings
