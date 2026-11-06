"""Verdict logic. Every threshold the README publishes has a test here."""

import ast
import random
from pathlib import Path

import pytest

from app.rules import engine
from app.rules.engine import Evidence, Finding, RulesTable, decide, load_table


# ---------------------------------------------------------------- helpers

def table(checks, *, red=50, yellow=20, min_coverage=0.6, max_negative=20) -> RulesTable:
    return RulesTable.model_validate({
        "version": 1,
        "thresholds": {"red": red, "yellow": yellow, "min_coverage": min_coverage},
        "max_negative_points": max_negative,
        "messages": {"red": "stop", "yellow": "check first", "green": "no flags"},
        "checks": checks,
    })


def check(points=None, *, needs=("repo",), hard=False, bands=None, **extra) -> dict:
    spec = {"layer": "static", "title": "a check", "needs": list(needs), **extra}
    if hard:
        spec["hard"] = True
    elif bands is not None:
        spec["bands"] = bands
    else:
        spec["points"] = points
    return spec


def hit(cid, value=None, evidence=()):
    return Finding(check=cid, status="hit", value=value, evidence=list(evidence))


def clear(cid, value=None):
    return Finding(check=cid, status="clear", value=value)


def unknown(cid):
    return Finding(check=cid, status="unknown")


def many(n, points=1):
    return {f"A{i}_check": check(points) for i in range(n)}


# ---------------------------------------------------------------- score

class TestScoreThresholds:
    @pytest.mark.parametrize("points,color", [(19, "green"), (20, "yellow"), (49, "yellow"), (50, "red")])
    def test_boundaries(self, points, color):
        v = decide([hit("A1_x")], {"repo"}, table({"A1_x": check(points)}))
        assert v.color == color
        assert v.score == points

    def test_points_add_up(self):
        t = table({"A1_x": check(30), "A2_y": check(25)})
        v = decide([hit("A1_x"), hit("A2_y")], {"repo"}, t)
        assert (v.color, v.reason, v.score) == ("red", "score", 55)

    def test_clear_adds_nothing(self):
        v = decide([clear("A1_x")], {"repo"}, table({"A1_x": check(50)}))
        assert (v.color, v.score) == ("green", 0)


# ---------------------------------------------------------------- coverage

class TestCoverage:
    def test_three_of_five_is_enough(self):
        t = table(many(5))
        v = decide([clear("A0_check"), clear("A1_check"), clear("A2_check")], {"repo"}, t)
        assert v.coverage == pytest.approx(0.6)
        assert v.color == "green"

    def test_two_of_five_is_not(self):
        t = table(many(5))
        v = decide([clear("A0_check"), clear("A1_check")], {"repo"}, t)
        assert (v.color, v.reason) == ("yellow", "low_coverage")

    @pytest.mark.parametrize("answered,color", [(59, "yellow"), (60, "green")])
    def test_boundary_at_sixty_percent(self, answered, color):
        t = table(many(100))
        v = decide([clear(f"A{i}_check") for i in range(answered)], {"repo"}, t)
        assert v.color == color

    def test_errors_never_count_as_clear(self):
        t = table(many(5))
        v = decide([unknown(f"A{i}_check") for i in range(5)], {"repo"}, t)
        assert (v.color, v.coverage) == ("yellow", 0)

    def test_missing_finding_is_unknown(self):
        t = table(many(2))
        v = decide([clear("A0_check")], {"repo"}, t)
        assert v.unknown == ["A1_check"]
        assert v.coverage == pytest.approx(0.5)

    def test_nothing_applicable_is_yellow(self):
        v = decide([], {"repo"}, table({"A1_x": check(10, needs=["company"])}))
        assert (v.color, v.reason, v.coverage) == ("yellow", "low_coverage", 0)

    def test_counter_signals_do_not_count(self):
        t = table({"A1_risk": check(5), "B1_good": check(-10)})
        only_good = decide([hit("B1_good")], {"repo"}, t)
        assert only_good.coverage == 0
        assert only_good.color == "yellow"
        only_risk = decide([clear("A1_risk")], {"repo"}, t)
        assert only_risk.coverage == 1
        assert only_risk.color == "green"

    def test_low_coverage_never_hides_a_high_score(self):
        t = table(many(5, points=50))
        v = decide([hit("A0_check")], {"repo"}, t)
        assert (v.color, v.reason) == ("red", "score")


# ---------------------------------------------------------------- hard triggers

class TestHardTriggers:
    def test_one_hard_hit_is_red_on_its_own(self):
        t = table({"H1_bad": check(hard=True), **many(5)})
        v = decide([hit("H1_bad")], {"repo"}, t)
        assert (v.color, v.reason, v.score) == ("red", "hard_trigger", 0)

    def test_hard_clear_does_nothing(self):
        v = decide([clear("H1_bad")], {"repo"}, table({"H1_bad": check(hard=True)}))
        assert v.color == "green"

    def test_hard_triggers_listed_first(self):
        t = table({"A1_big": check(40), "H1_bad": check(hard=True)})
        v = decide([hit("A1_big"), hit("H1_bad")], {"repo"}, t)
        assert [f.check for f in v.fired] == ["H1_bad", "A1_big"]
        assert v.fired[0].hard


# ---------------------------------------------------------------- risk-lowering points

class TestNegativePoints:
    def test_capped_at_twenty(self):
        t = table({"A1_x": check(40), "B1_good": check(-15), "B2_good": check(-15)})
        v = decide([hit("A1_x"), hit("B1_good"), hit("B2_good")], {"repo"}, t)
        assert v.score == 20
        assert v.color == "yellow"

    def test_score_never_below_zero(self):
        t = table({"A1_x": check(5), "B1_good": check(-10)})
        v = decide([clear("A1_x"), hit("B1_good")], {"repo"}, t)
        assert v.score == 0


# ---------------------------------------------------------------- numeric bands

class TestBands:
    AGE = {"C2_age": check(bands=[[30, 20], [180, 12], [730, 5]], needs=["company"])}

    @pytest.mark.parametrize("days,points", [(10, 20), (30, 12), (179, 12), (180, 5), (729, 5), (730, 0)])
    def test_band_edges(self, days, points):
        v = decide([hit("C2_age", value=days)], {"company"}, table(self.AGE))
        assert v.score == points
        assert v.coverage == 1

    def test_value_past_every_band_is_clear(self):
        v = decide([hit("C2_age", value=5000)], {"company"}, table(self.AGE))
        assert v.fired == []

    def test_missing_value_is_unknown(self):
        v = decide([hit("C2_age")], {"company"}, table(self.AGE))
        assert (v.score, v.unknown) == (0, ["C2_age"])

    def test_unknown_status_wins_over_value(self):
        v = decide([Finding(check="C2_age", status="unknown", value=3)], {"company"}, table(self.AGE))
        assert (v.score, v.unknown) == (0, ["C2_age"])


# ---------------------------------------------------------------- only_if_unknown

class TestOnlyIfUnknown:
    CHECKS = {
        "C2_age": check(bands=[[30, 20]], needs=["company"]),
        "C3_archive": check(bands=[[180, 8]], needs=["company"], only_if_unknown="C2_age"),
    }

    def test_counts_when_the_other_is_unknown(self):
        v = decide([unknown("C2_age"), hit("C3_archive", value=100)], {"company"}, table(self.CHECKS))
        assert v.score == 8

    def test_ignored_when_the_other_answered(self):
        v = decide([clear("C2_age", value=5000), hit("C3_archive", value=100)], {"company"}, table(self.CHECKS))
        assert v.score == 0
        assert v.coverage == 1


# ---------------------------------------------------------------- findings

class TestFindings:
    def test_unknown_check_id_raises(self):
        with pytest.raises(ValueError, match="Z9_typo"):
            decide([hit("Z9_typo")], {"repo"}, table({"A1_x": check(10)}))

    def test_duplicates_keep_the_hit_and_merge_evidence(self):
        t = table({"A1_x": check(20)})
        findings = [
            clear("A1_x"),
            hit("A1_x", evidence=[Evidence(summary="one")]),
            hit("A1_x", evidence=[Evidence(summary="two")]),
        ]
        v = decide(findings, {"repo"}, t)
        assert v.score == 20
        assert [e.summary for e in v.fired[0].evidence] == ["one", "two"]

    def test_disabled_check_is_ignored(self):
        t = table({"A1_x": check(50, enabled=False), "A2_y": check(1)})
        v = decide([hit("A1_x"), clear("A2_y")], {"repo"}, t)
        assert (v.color, v.score, v.coverage) == ("green", 0, 1)

    def test_a_hit_counts_even_without_its_inputs(self):
        v = decide([hit("A1_x")], {"repo"}, table({"A1_x": check(50, needs=["company"])}))
        assert v.color == "red"

    def test_needs_any_of(self):
        t = table({"S4_obf": check(20, needs=[["repo", "file"]])})
        assert decide([], {"file"}, t).unknown == ["S4_obf"]
        assert decide([], {"conversation"}, t).unknown == []

    def test_needs_all_of(self):
        t = table({"C5_job": check(15, needs=["company", "job"])})
        assert decide([], {"company"}, t).unknown == []
        assert decide([], {"company", "job"}, t).unknown == ["C5_job"]

    def test_order_does_not_matter(self):
        t = table({**many(6, points=7), "H1_bad": check(hard=True)})
        findings = [hit("A0_check"), clear("A1_check"), hit("A2_check"), unknown("A3_check"), clear("H1_bad")]
        first = decide(findings, {"repo"}, t)
        for seed in range(5):
            shuffled = findings[:]
            random.Random(seed).shuffle(shuffled)
            assert decide(shuffled, {"repo"}, t) == first

    def test_fired_carries_what_the_card_needs(self):
        t = table({"A1_x": check(25)})
        ev = Evidence(summary="RDAP registration 2024-07-16", source="https://rdap.org/domain/example.com")
        v = decide([hit("A1_x", evidence=[ev])], {"repo"}, t)
        f = v.fired[0]
        assert (f.check, f.layer, f.title, f.points, f.hard) == ("A1_x", "static", "a check", 25, False)
        assert f.evidence == [ev]
        assert v.message == "check first"


# ---------------------------------------------------------------- purity

ALLOWED_IMPORTS = {"__future__", "collections", "pathlib", "typing", "yaml", "pydantic"}


def test_engine_imports_no_network_or_model_code():
    tree = ast.parse(Path(engine.__file__).read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= ALLOWED_IMPORTS, imported - ALLOWED_IMPORTS


# ---------------------------------------------------------------- real cases, real table

REAL = load_table()


def all_clear(inputs, **values):
    """A clear answer for every check that applies, as a working pipeline would give."""
    out = []
    for cid, c in REAL.checks.items():
        if not c.enabled or c.only_if_unknown or not c.applies(inputs):
            continue
        out.append(clear(cid, value=100_000 if c.bands else None))
    return out


def with_hits(findings, *hits):
    ids = {h.check for h in hits}
    return [f for f in findings if f.check not in ids] + list(hits)


class TestRealCases:
    BLOCKNOVAS = {"company", "conversation", "job", "repo", "github_handle"}

    def test_blocknovas_is_red_before_anything_runs(self):
        # "12+ years" vs a 2024 domain, 9-month-old domain, a test-only GitHub org,
        # a repo on a personal account, "run it before our call".
        findings = with_hits(
            all_clear(self.BLOCKNOVAS),
            hit("C1_claimed_age_contradiction"),
            hit("C2_domain_age", value=270),
            hit("C9_assessment_only_github_org"),
            hit("P6_repo_on_personal_account"),
            hit("T1_run_locally_or_rushed"),
        )
        v = decide(findings, self.BLOCKNOVAS, REAL)
        assert (v.color, v.reason, v.score) == ("red", "score", 63)
        assert not any(f.hard for f in v.fired)
        assert not any(cid.startswith("D") for cid in v.unknown)

    def test_binance_style_repo_is_red_on_the_decoy_machine(self):
        inputs = {"repo", "detonation"}
        findings = with_hits(
            all_clear(inputs),
            hit("D3_toolchain_tampered"),
            hit("D1_decoy_secret_read"),
            hit("D6_blocked_destination"),
        )
        v = decide(findings, inputs, REAL)
        assert (v.color, v.reason) == ("red", "hard_trigger")
        assert [f.check for f in v.fired[:2]] == ["D1_decoy_secret_read", "D3_toolchain_tampered"]

    def test_disguised_file_is_red_on_the_static_read(self):
        inputs = {"file"}
        v = decide(with_hits(all_clear(inputs), hit("S7_file_type_mismatch")), inputs, REAL)
        assert (v.color, v.reason) == ("red", "hard_trigger")

    def test_benign_repo_is_green(self):
        inputs = {"repo", "detonation"}
        v = decide(all_clear(inputs), inputs, REAL)
        assert (v.color, v.score, v.coverage) == ("green", 0, 1)
        assert v.message == REAL.messages["green"]

    def test_real_recruiter_from_a_real_company_is_green(self):
        inputs = {"company", "job", "email_headers", "contact_email", "repo", "detonation"}
        findings = with_hits(
            all_clear(inputs),
            hit("C5_job_on_official_board"),
            hit("P3_dmarc_aligned_pass"),
            hit("P6_repo_on_personal_account"),
        )
        v = decide(findings, inputs, REAL)
        assert (v.color, v.score) == ("green", 0)

    def test_everything_failing_is_yellow_not_green(self):
        inputs = {"company", "conversation", "repo"}
        findings = [unknown(f.check) for f in all_clear(inputs)]
        v = decide(findings, inputs, REAL)
        assert (v.color, v.reason) == ("yellow", "low_coverage")

    def test_new_config_domains_plus_a_blocked_call_is_red(self):
        inputs = {"repo", "detonation"}
        findings = with_hits(
            all_clear(inputs),
            hit("P8_new_domains_in_repo_config"),
            hit("D6_blocked_destination"),
        )
        v = decide(findings, inputs, REAL)
        assert (v.color, v.reason, v.score) == ("red", "score", 50)
