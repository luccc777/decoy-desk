"""Decides the verdict color from what the three layers found.

This module is pure on purpose: no network, no model calls, no clock. The same
findings and the same table always give the same verdict, which is what lets
us test every threshold and publish the table as it is.

The layers send one Finding per check they answered. decide() turns them into
a Verdict:
  1. any hard trigger hit                  -> red
  2. score >= red threshold                -> red
  3. score >= yellow threshold             -> yellow
  4. fewer applicable checks answered than
     the minimum coverage                  -> yellow
  5. otherwise                             -> green
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Literal, Optional, Union

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

TABLE_PATH = Path(__file__).with_name("rules_table.yaml")

# What a user can submit. A check applies only when its inputs are present.
# "detonation" is added by the pipeline once the decoy machine has run.
INPUT_KINDS = frozenset({
    "conversation", "company", "job", "contact_email", "email_headers", "meeting_link",
    "github_handle", "linkedin_answers", "repo", "file", "detonation",
})

Status = Literal["hit", "clear", "unknown"]
Color = Literal["red", "yellow", "green"]
Layer = Literal["sender", "static", "decoy"]
Reason = Literal["hard_trigger", "score", "low_coverage", "no_flags"]


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# ---------------------------------------------------------------- the table

class Check(_Frozen):
    layer: Layer
    title: str = Field(min_length=1)
    needs: list[Union[str, list[str]]] = Field(min_length=1)
    hard: bool = False
    points: Optional[int] = None
    bands: Optional[list[tuple[float, int]]] = Field(default=None, min_length=1)
    only_if_unknown: Optional[str] = None
    enabled: bool = True

    @field_validator("needs")
    @classmethod
    def _known_inputs(cls, needs):
        for need in needs:
            options = [need] if isinstance(need, str) else need
            if not options:
                raise ValueError("an any-of group in needs is empty")
            unknown = set(options) - INPUT_KINDS
            if unknown:
                raise ValueError(f"unknown input kind(s): {sorted(unknown)}")
        return needs

    @model_validator(mode="after")
    def _one_way_to_score(self):
        ways = [self.hard, self.points is not None, self.bands is not None]
        if sum(ways) != 1:
            raise ValueError("a check needs exactly one of: hard, points, bands")
        if self.points == 0:
            raise ValueError("points must not be 0")
        if self.bands:
            limits = [limit for limit, _ in self.bands]
            if any(a >= b for a, b in zip(limits, limits[1:])):
                raise ValueError("band limits must increase")
        return self

    @property
    def reduces_risk(self) -> bool:
        """Counter-signals (negative points) lower the score but don't count for coverage."""
        return self.points is not None and self.points < 0

    def applies(self, inputs: Iterable[str]) -> bool:
        present = set(inputs)
        return all(
            (need in present) if isinstance(need, str) else bool(present & set(need))
            for need in self.needs
        )

    def points_for(self, value: float) -> int:
        """Points for a numeric value; 0 when the value is past every band."""
        for limit, points in self.bands or ():
            if value < limit:
                return points
        return 0


class Thresholds(_Frozen):
    red: int
    yellow: int
    min_coverage: float = Field(gt=0, le=1)

    @model_validator(mode="after")
    def _ordered(self):
        if not 0 < self.yellow < self.red:
            raise ValueError("thresholds need 0 < yellow < red")
        return self


class RulesTable(_Frozen):
    version: int
    thresholds: Thresholds
    max_negative_points: int = Field(ge=0)
    messages: dict[Color, str]
    checks: dict[str, Check] = Field(min_length=1)

    @model_validator(mode="after")
    def _consistent(self):
        missing = {"red", "yellow", "green"} - set(self.messages)
        if missing:
            raise ValueError(f"missing message(s) for: {sorted(missing)}")
        for cid, c in self.checks.items():
            if c.only_if_unknown and c.only_if_unknown not in self.checks:
                raise ValueError(f"{cid}: only_if_unknown refers to a missing check {c.only_if_unknown}")
        return self


class _UniqueKeyLoader(yaml.SafeLoader):
    """PyYAML keeps the last of two equal keys without a word; a rules table must not."""


def _mapping_without_duplicates(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if key in mapping:
            raise ValueError(f"duplicate key in rules table: {key}")
        mapping[key] = loader.construct_object(value_node, deep=True)
    return mapping


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping_without_duplicates)

_default_table: Optional[RulesTable] = None


def load_table(path: Optional[Path] = None) -> RulesTable:
    global _default_table
    if path is None and _default_table is not None:
        return _default_table
    text = Path(path or TABLE_PATH).read_text(encoding="utf-8")
    table = RulesTable.model_validate(yaml.load(text, Loader=_UniqueKeyLoader))
    if path is None:
        _default_table = table
    return table


# ---------------------------------------------------------------- findings and verdict

class Evidence(_Frozen):
    summary: str                  # e.g. "RDAP registration 2024-07-16"
    source: Optional[str] = None  # URL or "decoy machine"
    quote: Optional[str] = None   # verbatim text from the conversation, already checked


class Finding(_Frozen):
    check: str
    status: Status
    value: Optional[float] = None  # for banded checks, e.g. domain age in days
    evidence: list[Evidence] = []


class Fired(_Frozen):
    check: str
    layer: Layer
    title: str
    hard: bool
    points: int
    evidence: list[Evidence]


class Verdict(_Frozen):
    color: Color
    reason: Reason
    message: str
    score: int
    coverage: float              # share of applicable checks answered, 0..1
    fired: list[Fired]           # hard triggers first, then by points
    unknown: list[str]           # applicable checks nobody could answer
    table_version: int


_RANK = {"unknown": 0, "clear": 1, "hit": 2}


def _resolve(check: Check, finding: Finding) -> tuple[Status, int]:
    """Status and points for one finding. Banded checks are decided here, from the value."""
    if finding.status == "unknown":
        return "unknown", 0
    if check.bands is not None:
        if finding.value is None:
            return "unknown", 0
        points = check.points_for(finding.value)
        return ("hit", points) if points else ("clear", 0)
    if finding.status == "clear":
        return "clear", 0
    return "hit", check.points or 0


def decide(findings: Iterable[Finding], inputs: Iterable[str], table: Optional[RulesTable] = None) -> Verdict:
    table = table or load_table()
    inputs = frozenset(inputs)
    order = {cid: i for i, cid in enumerate(table.checks)}

    # Merge every finding into one answer per check: hit beats clear beats unknown.
    answers: dict[str, tuple[Status, int, list[Evidence]]] = {}
    for f in findings:
        if f.check not in table.checks:
            raise ValueError(f"finding for a check that isn't in the table: {f.check}")
        status, points = _resolve(table.checks[f.check], f)
        best = answers.get(f.check)
        if best is None or (_RANK[status], abs(points)) > (_RANK[best[0]], abs(best[1])):
            evidence = (best[2] if best and best[0] == status else []) + list(f.evidence)
            answers[f.check] = (status, points, evidence)
        elif status == best[0]:
            best[2].extend(f.evidence)

    def status_of(cid: str) -> Status:
        return answers.get(cid, ("unknown", 0, []))[0]

    # Which checks count. A check that was answered counts even if the user didn't
    # submit its inputs: evidence is never dropped. A disabled check never counts.
    active: list[str] = []
    for cid, c in table.checks.items():
        if not c.enabled:
            continue
        if c.only_if_unknown and status_of(c.only_if_unknown) != "unknown":
            continue
        if c.applies(inputs) or status_of(cid) != "unknown":
            active.append(cid)

    fired: list[Fired] = []
    for cid in active:
        status, points, evidence = answers.get(cid, ("unknown", 0, []))
        if status == "hit":
            c = table.checks[cid]
            fired.append(Fired(check=cid, layer=c.layer, title=c.title, hard=c.hard,
                               points=points, evidence=evidence))
    fired.sort(key=lambda f: (not f.hard, -f.points, order[f.check]))

    raised = sum(f.points for f in fired if f.points > 0)
    lowered = sum(f.points for f in fired if f.points < 0)
    score = max(0, raised + max(lowered, -table.max_negative_points))

    counted = [cid for cid in active if not table.checks[cid].reduces_risk]
    unknown = [cid for cid in counted if status_of(cid) == "unknown"]
    coverage = (len(counted) - len(unknown)) / len(counted) if counted else 0.0

    th = table.thresholds
    color: Color
    reason: Reason
    if any(f.hard for f in fired):
        color, reason = "red", "hard_trigger"
    elif score >= th.red:
        color, reason = "red", "score"
    elif score >= th.yellow:
        color, reason = "yellow", "score"
    elif coverage < th.min_coverage:
        color, reason = "yellow", "low_coverage"
    else:
        color, reason = "green", "no_flags"

    return Verdict(color=color, reason=reason, message=table.messages[color], score=score,
                   coverage=coverage, fired=fired, unknown=unknown, table_version=table.version)
