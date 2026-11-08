"""One check, end to end, as the page sees it: who sent it, then what's inside, then the verdict.

Each layer adds findings, and every new red flag is announced on the live feed
as soon as it's known. The decoy machine (layer 3) plugs in after the static read.
"""

from __future__ import annotations

import asyncio
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import httpx
from pydantic import BaseModel, ConfigDict

from app.jobs import Job
from app.legitimacy.claims import Complete
from app.legitimacy.collect import check_sender
from app.legitimacy.common import clear, utcnow, unknown
from app.legitimacy.http import FetchError
from app.legitimacy.repo_config_domains import repo_config_finding
from app.rules.engine import Finding, RulesTable, decide, load_table
from app.rules.explain import explain
from app.schemas import Submission
from app.static_scan.fetch import download_repo
from app.static_scan.file_scan import detect_type, scan_file
from app.code_review import investigate
from app.static_scan.files import RepoFiles, from_dict, load_dir
from app.static_scan.repo_scan import scan_repo

SENDER_INPUTS = {"conversation", "company", "job", "contact_email", "email_headers", "meeting_link",
                 "github_handle", "linkedin_answers"}
REPO_CHECKS = ("S1_runs_on_folder_open", "S2_install_script", "S3_install_fetches_remote_code",
               "S4_obfuscated_code", "S5_hidden_urls", "S6_git_hooks", "S10_runs_downloaded_code",
               "S11_hidden_shell_command", "S12_reads_secret_stores", "S13_connects_to_hardcoded_ip",
               "S14_walks_home_directory", "P8_new_domains_in_repo_config", "A1_model_flags_code",
               "A2_model_confirmed_attack")
TEXT_CHECKS = ("S4_obfuscated_code", "S5_hidden_urls", "S10_runs_downloaded_code", "S11_hidden_shell_command",
               "S12_reads_secret_stores", "S13_connects_to_hardcoded_ip", "S14_walks_home_directory",
               "A1_model_flags_code", "A2_model_confirmed_attack")
MODEL_NOTE = ("Two language models now investigate the code, comments removed. They can follow the trail into "
              "other files, and they can only add suspicion, never remove it")
# Files whose behavior only shows when they run. Until the decoy machine runs them, S4, S5 and
# S10 stay unknown for these, so an honestly named program comes out yellow, never green.
RUN_TO_JUDGE = frozenset({"executable", "shortcut", "disk_image", "unknown"})
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
HEARTBEAT_S = 20


class Upload(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    data: bytes


class _Feed:
    """Announces each red flag once, the moment the findings so far make it fire."""

    def __init__(self, job: Job, inputs: set[str], table: RulesTable):
        self.job, self.inputs, self.table = job, inputs, table
        self.findings: list[Finding] = []
        self.shown: set[str] = set()

    def add(self, stage: str, findings: list[Finding]) -> None:
        self.findings += findings
        for f in decide(self.findings, self.inputs, self.table).fired:
            if f.check in self.shown:
                continue
            self.shown.add(f.check)
            ev = f.evidence[0] if f.evidence else None
            good = f.points < 0  # a sign of a real company, not a red flag
            self.job.emit(stage, f.title, "info" if good else "warning", data={
                "check": f.check, "hard": f.hard, "points": f.points, "good": good,
                "evidence": ev.summary if ev else None, "quote": ev.quote if ev else None})


def _file_text_findings(upload: Upload, family: str) -> list[Finding]:
    """S4, S5 and S10 for an upload: scan scripts and text; programs stay unknown until the decoy machine runs."""
    if family in ("script", "text"):
        text = upload.data.decode("utf-8", errors="replace")
        found = scan_repo(from_dict({upload.name: text}, name=upload.name))
        return [f for f in found if f.check in TEXT_CHECKS]
    if family in RUN_TO_JUDGE:
        return [unknown(c, "it's a program or a file we can't read, and only running it on the decoy machine "
                           "shows what it does") for c in TEXT_CHECKS]
    return [clear(c, "Not a script, a program or source code") for c in TEXT_CHECKS]


async def _repo_files(job: Job, sub: Submission, client: httpx.AsyncClient,
                      repo_dir: Optional[Path]) -> tuple[Optional[RepoFiles], Optional[str]]:
    if repo_dir is not None:
        name = sub.repo_url or repo_dir.name
        job.emit("fetch", f"Opening the recorded copy of {name}. Nothing in it runs here.")
        files = load_dir(repo_dir, name)
    else:
        job.emit("fetch", "Downloading the repo as an archive. Nothing in it runs here.")
        dest = job.dir / "repo"
        shutil.rmtree(dest, ignore_errors=True)
        try:
            fetched = await download_repo(client, sub.repo_url, dest)
        except FetchError as e:
            job.emit("fetch", f"Couldn't download the repo: {e}", "warning")
            return None, str(e)
        files = load_dir(dest, fetched.name)
        if fetched.skipped_links:
            job.emit("fetch", f"Skipped {fetched.skipped_links} symbolic link(s) in the repo", "info")
    job.emit("fetch", f"Got {len(files.sizes)} files from {files.name}", "done")
    return files, None


async def run_check(job: Job, sub: Submission, *, client: httpx.AsyncClient, now: Optional[datetime] = None,
                    complete: Optional[Complete] = None, upload: Optional[Upload] = None,
                    repo_dir: Optional[Path] = None, github_token: Optional[str] = None,
                    table: Optional[RulesTable] = None, review_complete: Optional[Complete] = None,
                    review_verify: Optional[Complete] = None) -> dict[str, Any]:
    """complete reads the conversation (demos pass their recording); review_complete and review_verify are the
    two models investigating the code, live by default, also in demos."""
    now = now or utcnow()
    table = table or load_table()
    inputs = sub.inputs() | ({"file"} if upload else set()) | ({"repo"} if repo_dir else set())
    feed = _Feed(job, inputs, table)
    result: dict[str, Any] = {"stage": "before_run", "sender": None, "repo": None, "file": None}

    # Layer 1: who sent it.
    if inputs & SENDER_INPUTS or sub.repo_url:
        job.emit("sender", "Checking who sent this: public records, the job board, GitHub and the conversation")
        # Seen live: 135 s with nothing on screen. A heartbeat shows the check is alive while sources answer.
        task = asyncio.ensure_future(check_sender(sub, client=client, now=now, complete=complete,
                                                  github_token=github_token))
        waited = 0
        while not task.done():
            await asyncio.wait({task}, timeout=HEARTBEAT_S)
            if not task.done():
                waited += HEARTBEAT_S
                job.emit("sender", f"Still checking public records, job boards and the conversation ({waited}s)")
        report = task.result()
        feed.add("sender", report.findings)
        said = report.claims
        result["sender"] = {
            "company": sub.company_name or (said.company_name if said else None),
            "company_domain": report.company_domain,
            "official_website": report.official.website if report.official else None,
            "official_source": report.official.source if report.official else None,
            "claimed_founded_year": said.founded_year if said else None,
            "model_read_conversation": said.model_ok if said else None,
            "notes": report.notes,
        }
        job.emit("sender", "Finished checking the sender", "done")

    # Layer 2: what's inside, read without running it.
    if sub.repo_url or repo_dir:
        files, why = await _repo_files(job, sub, client, repo_dir)
        if files is None:
            feed.add("static", [unknown(c, f"the repo couldn't be downloaded: {why}") for c in REPO_CHECKS])
        else:
            job.emit("static", "Reading the code for traps: tasks that run on open, install scripts, hidden code")
            found = scan_repo(files)
            found.append(await repo_config_finding(client, files.texts, now))
            feed.add("static", found)
            job.emit("static", MODEL_NOTE)
            # Seen live: in a 75-file sample the model never got the flagged file. The rules' files go first.
            flagged = tuple(p for p in files.texts
                            if any(p in e.summary for f in found if f.status == "hit" for e in f.evidence))
            feed.add("static", await investigate(files, flagged=flagged, complete=review_complete,
                                                 verify=review_verify, emit=job.emit))
            result["repo"] = {"name": files.name, "files": len(files.sizes), "read": len(files.texts)}
            job.emit("static", f"Read {len(files.texts)} files", "done")

    if upload:
        kind = detect_type(upload.data)
        job.emit("static", f"Reading {upload.name} without opening it")
        feed.add("static", scan_file(upload.name, upload.data) + _file_text_findings(upload, kind.family))
        if kind.family in ("script", "text"):  # programs wait for the decoy machine; A1 is already unknown for them
            job.emit("static", MODEL_NOTE)
            text = upload.data.decode("utf-8", errors="replace")
            feed.add("static", await investigate(from_dict({upload.name: text}, name=upload.name),
                                                 complete=review_complete, verify=review_verify, emit=job.emit))
        result["file"] = {"name": upload.name, "size": len(upload.data), "kind": kind.label}
        job.emit("static", f"It's a {kind.label}", "done")

    verdict = decide(feed.findings, inputs, table)
    result["verdict"] = verdict.model_dump()
    job.emit("verdict", verdict.message, "done", data={"color": verdict.color, "score": verdict.score,
                                                       "reason": verdict.reason})
    # The color is final above; the explanation only puts it in plain words and never fails the check.
    # Demos pass their recorded answer, which doesn't fit this schema, so they get the template.
    result["explanation"] = (await explain(verdict, complete=complete, checked=inputs)).model_dump()
    return result
